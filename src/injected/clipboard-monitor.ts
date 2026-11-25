/**
 * ClickShield MAIN World Clipboard Monitor
 * Operates in the webpage execution context to observe programmatic
 * navigator.clipboard and document.execCommand calls abused in ClickFix attacks.
 *
 * Privacy guarantee: Does NOT store or transmit personal data or passwords.
 * Only flags command patterns matching known attack vectors.
 */

(function () {
  // Prevent duplicate execution
  if ((window as any).__CLICKSHIELD_MAIN_MONITOR_ACTIVE__) return;
  (window as any).__CLICKSHIELD_MAIN_MONITOR_ACTIVE__ = true;

  const SUSPICIOUS_COMMAND_REGEX =
    /\b(powershell(\.exe)?|pwsh|cmd(\.exe)?|mshta(\.exe)?|bitsadmin(\.exe)?|certutil(\.exe)?|regsvr32(\.exe)?|rundll32(\.exe)?|wscript|cscript|irm\s+|iex\s+|curl.*\||wget.*\||invoke-expression|invoke-webrequest|downloadstring|start-process|osascript|bash\s+-c|sh\s+-c|\[convert\]::frombase64string)\b/i;

  function notifySuspiciousPayload(text: string) {
    try {
      window.dispatchEvent(
        new CustomEvent("clickshield:suspicious-copy", {
          detail: {
            timestamp: Date.now(),
            hasCommandSyntax: true,
            snippet: text.slice(0, 100),
          },
        })
      );
    } catch {}
  }

  // 1. Hook navigator.clipboard.writeText
  if (navigator.clipboard && typeof navigator.clipboard.writeText === "function") {
    const originalWriteText = navigator.clipboard.writeText.bind(navigator.clipboard);

    navigator.clipboard.writeText = async function (text: string): Promise<void> {
      try {
        if (text && SUSPICIOUS_COMMAND_REGEX.test(text)) {
          notifySuspiciousPayload(text);
        }
      } catch {}

      return originalWriteText(text);
    };
  }

  // 2. Hook document.execCommand("copy") commonly used by older ClickFix and phishing scripts
  if (typeof document.execCommand === "function") {
    const originalExecCommand = document.execCommand.bind(document);

    document.execCommand = function (commandId: string, showUI?: boolean, value?: string): boolean {
      try {
        if ((commandId || "").toLowerCase() === "copy") {
          const selectedText = document.getSelection()?.toString() || "";
          if (selectedText && SUSPICIOUS_COMMAND_REGEX.test(selectedText)) {
            notifySuspiciousPayload(selectedText);
          }
        }
      } catch {}

      return originalExecCommand(commandId, showUI, value);
    };
  }
})();

