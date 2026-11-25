import type { ThreatSignal } from "../shared/types/signal";
import { logger } from "../shared/utils/logger";

export interface ClipboardGuardCallbacks {
  onThreatDetected: (signal: ThreatSignal) => void;
  onIntervention?: (reason: string) => void;
}

export class ClipboardGuard {
  private static isInitialized = false;

  static initialize(callbacks: ClipboardGuardCallbacks) {
    if (this.isInitialized) return;
    this.isInitialized = true;

    // 1. Listen for custom events from MAIN-world clipboard monitor
    window.addEventListener("clickshield:suspicious-copy", (event: any) => {
      const detail = event?.detail;
      logger.warn("Suspicious programmatic clipboard write detected:", detail?.snippet);

      callbacks.onThreatDetected({
        type: "CLIPBOARD_MANIPULATION",
        reason: "Webpage script attempted programmatic clipboard write with system command syntax.",
        snippet: detail?.snippet,
      });

      callbacks.onIntervention?.("Programmatic command clipboard write intercepted");
    });

    // 2. Listen for native DOM copy events
    document.addEventListener("copy", (event: ClipboardEvent) => {
      try {
        const selection = document.getSelection()?.toString() || "";
        const target = event.target as HTMLElement | null;

        // Check if copy originates from a deceptive button (e.g., "Verify", "Copy Code")
        const buttonText = target?.closest("button, [role='button']")?.textContent || "";
        const isVerificationButton = /verify|human|solve|copy\s*command/i.test(buttonText);

        const hasCommandSyntax =
          /\b(powershell|cmd|irm|iex|mshta|bitsadmin|curl.*\||wget.*\|)\b/i.test(selection);

        if (isVerificationButton && hasCommandSyntax) {
          logger.warn("Copy event triggered on verification element containing command syntax");

          callbacks.onThreatDetected({
            type: "CLIPBOARD_MANIPULATION",
            reason: "User clicked verification button that copies executable commands to clipboard.",
            snippet: selection.slice(0, 100),
          });

          callbacks.onIntervention?.("Verification-linked clipboard command flagged");
        }
      } catch (err) {
        logger.debug("Error in copy event monitor:", err);
      }
    });
  }
}

