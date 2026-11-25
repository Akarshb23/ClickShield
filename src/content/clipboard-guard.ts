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

        // Check if copy originates from a deceptive button or link
        const buttonText = target?.closest("button, a, [role='button']")?.textContent || "";
        const isDeceptiveContext =
          /verify|human|solve|captcha|fix|update|download|code|command|continue/i.test(buttonText);

        const hasCommandSyntax =
          /\b(powershell|pwsh|cmd|irm|iex|mshta|bitsadmin|certutil|curl.*\||wget.*\||invoke-expression|invoke-webrequest|downloadstring|start-process|osascript)\b/i.test(
            selection
          );

        const isBlatantPayload =
          /\b(powershell.*(-w(indowstyle)?|-e(nc)?|-nop)|(irm|iex|invoke-expression).*http|certutil.*-urlcache|mshta|curl.*\|\s*(ba)?sh)\b/i.test(
            selection
          );

        if ((isDeceptiveContext && hasCommandSyntax) || isBlatantPayload) {
          logger.warn("Copy event triggered on element containing command syntax");

          callbacks.onThreatDetected({
            type: "CLIPBOARD_MANIPULATION",
            reason: "User interaction triggered clipboard copy with executable command syntax.",
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

