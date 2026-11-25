import { logger } from "../shared/utils/logger";

export interface DomObserverOptions {
  onMutation: () => void;
  debounceMs?: number;
}

export class DynamicDomObserver {
  private observer: MutationObserver | null = null;
  private timer: ReturnType<typeof setTimeout> | null = null;
  private debounceMs: number;

  constructor(options: DomObserverOptions) {
    this.debounceMs = options.debounceMs || 500;

    this.observer = new MutationObserver((mutations) => {
      // Ignore mutations originating from ClickShield UI elements
      const isInternal = mutations.some((m) =>
        Array.from(m.addedNodes).some(
          (n) => n instanceof HTMLElement && (n.hasAttribute("data-clickshield-ignore") || n.id?.startsWith("clickshield"))
        )
      );

      if (isInternal) return;

      if (this.timer) {
        clearTimeout(this.timer);
      }

      this.timer = setTimeout(() => {
        options.onMutation();
      }, this.debounceMs);
    });
  }

  start(target: Node = document.body) {
    if (!this.observer) return;
    try {
      this.observer.observe(target, {
        childList: true,
        subtree: true,
        characterData: true,
      });
      logger.debug("Dynamic DOM observer started");
    } catch (err) {
      logger.warn("Failed to attach DOM observer:", err);
    }
  }

  stop() {
    if (this.timer) clearTimeout(this.timer);
    if (this.observer) this.observer.disconnect();
  }
}

