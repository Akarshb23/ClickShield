
import { logger } from "../shared/utils/logger";

export interface DomObserverOptions {
  onMutation: () => void;
  debounceMs?: number;
}

export class DynamicDomObserver {
  private observer: MutationObserver | null = null;

  private timer: ReturnType<typeof setTimeout> | null = null;

  private debounceMs: number;

  private onMutation: () => void;

  private observedTarget: Node | null = null;

  private static readonly IGNORE_SELECTOR =
    '[data-clickshield-ignore], [id^="clickshield"]';

  constructor(options: DomObserverOptions) {
    this.onMutation = options.onMutation;

    this.debounceMs =
      typeof options.debounceMs === "number" &&
      Number.isFinite(options.debounceMs)
        ? Math.max(0, options.debounceMs)
        : 500;

    if (typeof MutationObserver === "undefined") {
      logger.warn(
        "ClickShield: MutationObserver is unavailable."
      );
      return;
    }

    this.observer = new MutationObserver((mutations) => {
      this.handleMutations(mutations);
    });
  }

  // ==========================================================
  // INTERNAL UI DETECTION
  // ==========================================================

  /**
   * Determines whether a node belongs to ClickShield's UI.
   *
   * Handles:
   * - ClickShield root elements.
   * - Descendants of ClickShield UI.
   * - Text nodes inside ClickShield UI.
   */
  private isIgnoredNode(node: Node): boolean {
    try {
      let element: Element | null =
        node instanceof Element
          ? node
          : node.parentElement;

      while (element) {
        if (
          element.hasAttribute("data-clickshield-ignore") ||
          element.id.toLowerCase().startsWith("clickshield")
        ) {
          return true;
        }

        element = element.parentElement;
      }

      return false;
    } catch {
      return false;
    }
  }

  // ==========================================================
  // MUTATION FILTERING
  // ==========================================================

  /**
   * Process individual mutation records.
   *
   * Important:
   * A batch containing internal and external changes must
   * still trigger scanning for the external changes.
   */
  private hasRelevantMutations(
    mutations: MutationRecord[]
  ): boolean {
    return mutations.some((mutation) => {
      // Ignore changes occurring inside ClickShield UI.
      if (this.isIgnoredNode(mutation.target)) {
        return false;
      }

      if (mutation.type === "characterData") {
        return true;
      }

      if (mutation.type === "childList") {
        const changedNodes = [
          ...Array.from(mutation.addedNodes),
          ...Array.from(mutation.removedNodes),
        ];

        // Ignore a mutation if all changed nodes belong
        // to ClickShield's own interface.
        return changedNodes.some(
          (node) => !this.isIgnoredNode(node)
        );
      }

      return false;
    });
  }

  // ==========================================================
  // MUTATION HANDLING
  // ==========================================================

  private handleMutations(
    mutations: MutationRecord[]
  ): void {
    try {
      if (!this.hasRelevantMutations(mutations)) {
        return;
      }

      this.scheduleScan();
    } catch (error) {
      logger.debug(
        "Error processing ClickShield DOM mutations:",
        error
      );
    }
  }

  // ==========================================================
  // DEBOUNCED SCANNING
  // ==========================================================

  private scheduleScan(): void {
    if (this.timer !== null) {
      clearTimeout(this.timer);
    }

    this.timer = setTimeout(() => {
      this.timer = null;

      try {
        this.onMutation();
      } catch (error) {
        logger.warn(
          "ClickShield DOM mutation callback failed:",
          error
        );
      }
    }, this.debounceMs);
  }

  private clearPendingScan(): void {
    if (this.timer !== null) {
      clearTimeout(this.timer);
      this.timer = null;
    }
  }

  // ==========================================================
  // OBSERVER LIFECYCLE
  // ==========================================================

  start(
    target: Node = document.body ?? document.documentElement
  ): void {
    if (!this.observer) {
      logger.warn(
        "ClickShield DOM observer is unavailable."
      );
      return;
    }

    if (!target) {
      logger.debug(
        "ClickShield DOM observer: no target available."
      );
      return;
    }

    // Avoid observing the same node more than once.
    if (this.observedTarget === target) {
      return;
    }

    try {
      // When switching targets, disconnect the previous
      // observation to avoid duplicate mutation records.
      if (this.observedTarget) {
        this.observer.disconnect();
        this.clearPendingScan();
      }

      this.observer.observe(target, {
        childList: true,
        subtree: true,
        characterData: true,
      });

      this.observedTarget = target;

      logger.debug(
        "ClickShield dynamic DOM observer started."
      );
    } catch (error) {
      this.observedTarget = null;

      logger.warn(
        "Failed to attach ClickShield DOM observer:",
        error
      );
    }
  }

  stop(): void {
    try {
      this.clearPendingScan();

      if (this.observer) {
        this.observer.disconnect();
      }

      this.observedTarget = null;

      logger.debug(
        "ClickShield dynamic DOM observer stopped."
      );
    } catch (error) {
      logger.warn(
        "Failed to stop ClickShield DOM observer:",
        error
      );
    }
  }
}
