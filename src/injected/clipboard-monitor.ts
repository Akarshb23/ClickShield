/**
 * ClickShield MAIN World Clipboard Monitor
 * Operates in the webpage execution context to observe programmatic
 * navigator.clipboard.writeText calls commonly abused in ClickFix attacks.
 *
 * Privacy guarantee: Does NOT store or transmit personal data or passwords.
 * Only flags command patterns matching known attack vectors.
 */

(function () {
  // Prevent duplicate execution
  if ((window as any).__CLICKSHIELD_MAIN_MONITOR_ACTIVE__) return;
  (window as any).__CLICKSHIELD_MAIN_MONITOR_ACTIVE__ = true;

  if (!navigator.clipboard || typeof navigator.clipboard.writeText !== "function") {
    return;
  }

  const originalWriteText = navigator.clipboard.writeText.bind(navigator.clipboard);

  navigator.clipboard.writeText = async function (text: string): Promise<void> {
    try {
      const lower = (text || "").toLowerCase();

      // Check for suspicious command indicators in programmatic clipboard writes
      const isSuspicious =
        /\b(powershell|cmd\.exe|mshta|bitsadmin|irm |iex |curl.*\||wget.*\|)\b/i.test(lower);

      if (isSuspicious) {
        // Dispatch custom event to notify ClickShield isolated content script
        window.dispatchEvent(
          new CustomEvent("clickshield:suspicious-copy", {
            detail: {
              timestamp: Date.now(),
              hasCommandSyntax: true,
              snippet: text.slice(0, 100), // bounded snippet for explainable warning
            },
          })
        );
      }
    } catch {
      // Do not break page flow on internal monitor exception
    }

    return originalWriteText(text);
  };
})();

