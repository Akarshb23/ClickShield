
import type { ThreatSignal } from "../shared/types/signal";
import { logger } from "../shared/utils/logger";

export interface EventMonitorCallbacks {
  onInteractionThreat: (signal: ThreatSignal) => void;
}

const INTERACTIVE_SELECTOR =
  "button, a, div[role='button'], input[type='checkbox'], label";

const VERIFICATION_REGEX =
  /\b(?:verify|verification|human|robot|captcha|turnstile|recaptcha)\b/i;

const GENERIC_ACTION_REGEX =
  /\b(?:confirm|check|continue|fix|update)\b/i;

const CAPTCHA_METADATA_REGEX =
  /\b(?:captcha|turnstile|verify|recaptcha)\b/i;

const RUN_DIALOG_REGEX =
  /\b(?:win(?:dows)?\s*\+\s*r|press\s+(?:the\s+)?windows?\s+key\s*(?:\+|and)\s*r|open\s+(?:the\s+)?run\s+(?:dialog|box)|run\s+(?:the\s+)?dialog)\b/i;

const SHELL_COMMAND_REGEX =
  /\b(?:powershell(?:\.exe)?|pwsh|cmd(?:\.exe)?|command\s+prompt|terminal|mshta(?:\.exe)?|bitsadmin(?:\.exe)?|certutil(?:\.exe)?|regsvr32(?:\.exe)?|rundll32(?:\.exe)?|wscript(?:\.exe)?|cscript(?:\.exe)?|curl|wget|osascript|bash|sh)\b/i;

const EXECUTION_INSTRUCTION_REGEX =
  /\b(?:paste|copy|enter|execute|run|type)\b.{0,120}\b(?:command|script|code|powershell|terminal|cmd)\b/i;

export class InteractionMonitor {
  private static isListening = false;

  private static callbacks: EventMonitorCallbacks | null = null;

  // ==========================================================
  // INITIALIZATION
  // ==========================================================

  static initialize(callbacks: EventMonitorCallbacks): void {
    // Always update callbacks, even if the listener already exists.
    this.callbacks = callbacks;

    if (this.isListening) return;

    this.isListening = true;

    document.addEventListener(
      "click",
      (event: MouseEvent) => {
        this.handleClick(event);
      },
      true
    );

    logger.info("ClickShield InteractionMonitor initialized.");
  }

  // ==========================================================
  // EVENT TARGET RESOLUTION
  // ==========================================================

  private static getTargetElement(
    event: MouseEvent
  ): Element | null {
    try {
      // Handle clicks originating inside SVGs or shadow DOM.
      const path = event.composedPath();

      for (const item of path) {
        if (item instanceof Element) {
          return item;
        }
      }

      const target = event.target;

      if (target instanceof Element) {
        return target;
      }

      if (target instanceof Node) {
        return target.parentElement;
      }

      return null;
    } catch {
      return null;
    }
  }

  // ==========================================================
  // INTERACTIVE ELEMENT DETECTION
  // ==========================================================

  private static findInteractiveElement(
    target: Element
  ): Element | null {
    try {
      return target.closest(INTERACTIVE_SELECTOR);
    } catch {
      return null;
    }
  }

  // ==========================================================
  // ELEMENT CONTEXT EXTRACTION
  // ==========================================================

  private static getElementContext(
    element: Element
  ): string {
    try {
      const text = element.textContent || "";

      const ariaLabel =
        element.getAttribute("aria-label") || "";

      const title =
        element.getAttribute("title") || "";

      const id =
        element.getAttribute("id") || "";

      const className =
        element.getAttribute("class") || "";

      const value =
        element instanceof HTMLInputElement
          ? element.value
          : "";

      const parentLabel =
        element.closest("label")?.textContent || "";

      return [
        text,
        ariaLabel,
        title,
        id,
        className,
        value,
        parentLabel,
      ]
        .join(" ")
        .toLowerCase()
        .slice(0, 1000);
    } catch {
      return "";
    }
  }

  // ==========================================================
  // VERIFICATION ELEMENT DETECTION
  // ==========================================================

  private static isVerificationElement(
    element: Element
  ): boolean {
    const context = this.getElementContext(element);

    if (!context) return false;

    // Strong verification indicators.
    if (VERIFICATION_REGEX.test(context)) {
      return true;
    }

    // Generic actions need additional CAPTCHA-related
    // metadata to avoid flagging ordinary buttons.
    if (
      GENERIC_ACTION_REGEX.test(context) &&
      CAPTCHA_METADATA_REGEX.test(context)
    ) {
      return true;
    }

    return false;
  }

  // ==========================================================
  // PAGE INSTRUCTION ANALYSIS
  // ==========================================================

  private static getVisiblePageText(): string {
    try {
      return (
        document.body?.innerText || ""
      ).slice(0, 50000).toLowerCase();
    } catch {
      return "";
    }
  }

  private static containsClickFixInstructions(): boolean {
    const bodyText = this.getVisiblePageText();

    if (!bodyText) return false;

    const hasRunDialogPrompt =
      RUN_DIALOG_REGEX.test(bodyText);

    const hasExecutionInstruction =
      EXECUTION_INSTRUCTION_REGEX.test(bodyText);

    const hasShellCommand =
      SHELL_COMMAND_REGEX.test(bodyText);

    // A strong ClickFix pattern requires:
    // 1. A Run dialog instruction OR an explicit execution instruction.
    // 2. A recognizable shell or command-line tool.
    const hasExecutionPrompt =
      hasRunDialogPrompt || hasExecutionInstruction;

    return (
      hasExecutionPrompt &&
      hasShellCommand
    );
  }

  // ==========================================================
  // INTERACTION HANDLING
  // ==========================================================

  private static handleClick(event: MouseEvent): void {
    try {
      const target = this.getTargetElement(event);

      if (!target) return;

      const interactiveElement =
        this.findInteractiveElement(target);

      if (!interactiveElement) return;

      // Ignore unrelated interactive elements.
      if (
        !this.isVerificationElement(interactiveElement)
      ) {
        return;
      }

      // Check whether the page contains actual
      // terminal-execution instructions.
      if (!this.containsClickFixInstructions()) {
        return;
      }

      const elementContext =
        this.getElementContext(interactiveElement);

      logger.warn(
        "ClickShield detected suspicious verification interaction."
      );

      this.reportThreat(
        elementContext
      );
    } catch (error) {
      logger.debug(
        "Error in ClickShield interaction monitor:",
        error
      );
    }
  }

  // ==========================================================
  // THREAT REPORTING
  // ==========================================================

  private static reportThreat(
    elementContext: string
  ): void {
    const signal: ThreatSignal = {
      type: "FAKE_CAPTCHA",

      reason:
        "User interacted with a verification-like element on a page containing terminal execution instructions.",

      snippet: elementContext.slice(0, 80),
    };

    try {
      this.callbacks?.onInteractionThreat(signal);
    } catch (error) {
      logger.debug(
        "Unable to report interaction threat:",
        error
      );
    }
  }
}
