import type { ThreatSignal } from "../shared/types/signal";
import { logger } from "../shared/utils/logger";

export interface EventMonitorCallbacks {
  onInteractionThreat: (signal: ThreatSignal) => void;
}

export class InteractionMonitor {
  private static isListening = false;

  static initialize(callbacks: EventMonitorCallbacks) {
    if (this.isListening) return;
    this.isListening = true;

    // Track clicks on suspicious elements mimicking verification buttons
    document.addEventListener(
      "click",
      (event: MouseEvent) => {
        const target = event.target as HTMLElement | null;
        if (!target) return;

        const interactiveEl = target.closest("button, a, div[role='button'], input[type='checkbox']");
        if (!interactiveEl) return;

        const text = (interactiveEl.textContent || "").toLowerCase();
        const className = (interactiveEl.className || "").toString().toLowerCase();

        const isVerificationClick =
          /verify|human|robot|turnstile|recaptcha|confirm/i.test(text) ||
          /captcha|turnstile|verify/i.test(className);

        if (isVerificationClick) {
          logger.debug("User interacted with verification element:", text.slice(0, 50));

          // Check if page instructs Win+R or PowerShell
          const bodyText = (document.body?.innerText || "").toLowerCase();
          const hasWinRPrompt = /win\s*\+\s*r|powershell|run dialog/i.test(bodyText);

          if (hasWinRPrompt) {
            callbacks.onInteractionThreat({
              type: "FAKE_CAPTCHA",
              reason: "User interacted with verification element on a page directing terminal execution.",
              snippet: text.slice(0, 80),
            });
          }
        }
      },
      { passive: true }
    );
  }
}

