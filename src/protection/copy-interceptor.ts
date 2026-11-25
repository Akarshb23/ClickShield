import { logger } from "../shared/utils/logger";

export interface CopyInterventionResult {
  wasBlocked: boolean;
  reason?: string;
}

export class CopyInterceptor {
  private static isArmed = false;

  static arm(callbacks: { onIntervention: (reason: string) => void }) {
    if (this.isArmed) return;
    this.isArmed = true;

    // Capture phase listener to intercept before hostile scripts can complete the clipboard write
    document.addEventListener(
      "copy",
      (event: ClipboardEvent) => {
        try {
          const selection = document.getSelection()?.toString() || "";
          const target = event.target as HTMLElement | null;

          const buttonContext = target?.closest("button, a, [role='button']")?.textContent || "";
          const isDeceptiveContext =
            /verify|human|solve|turnstile|recaptcha|fix|update|download|code|command/i.test(buttonContext);

          const hasDangerousPayload =
            /\b(powershell|pwsh|cmd(\.exe)?|mshta|bitsadmin|certutil|regsvr32|rundll32|irm\s+|iex\s+|invoke-expression|curl.*\||wget.*\||osascript|bash\s+-c)\b/i.test(
              selection
            );

          const isBlatantAttack =
            /\b(powershell.*(-w(indowstyle)?\s+h|-e(nc)?|-nop)|(irm|iex).*http|certutil.*-urlcache|mshta|curl.*\|\s*(ba)?sh)\b/i.test(
              selection
            );

          if ((isDeceptiveContext && hasDangerousPayload) || isBlatantAttack) {
            // Block copying the malicious command payload
            event.preventDefault();
            event.stopImmediatePropagation();

            // Overwrite with benign warning text if clipboardData is available
            if (event.clipboardData) {
              event.clipboardData.setData(
                "text/plain",
                "[ClickShield Blocked: Dangerous terminal command payload intercepted]"
              );
            }

            logger.warn("ClickShield active intervention: malicious clipboard payload blocked!");
            callbacks.onIntervention("Malicious clipboard payload neutralized");
          }
        } catch (err) {
          logger.debug("Error during copy interception:", err);
        }
      },
      true // Use capture phase
    );
  }
}

