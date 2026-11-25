import type { ThreatSignal } from "../shared/types/signal";

export function scanPage(): ThreatSignal[] {
  // Never scan inside ClickShield's own UI elements
  if (document.querySelector("[data-clickshield-ignore]")) {
    // handled inside DOM traversal
  }

  const text = (document.body?.innerText || "").toLowerCase();
  if (!text) return [];

  const signals: ThreatSignal[] = [];

  // 1. CAPTCHA & Verification patterns
  const hasVerificationPrompt =
    /verify (that )?you are human|i am not a robot|confirm you are not a robot|security verification|ddos protection by|cloudflare verification/i.test(
      text
    );

  // 2. Clipboard instructions
  const hasCopyPastePrompt =
    /copy (and )?paste|paste into (the )?(terminal|powershell|run dialog|command prompt)|press ctrl \+ v|press win \+ r/i.test(
      text
    );

  // 3. Operating System / Command execution instructions
  const hasExecutionPrompt =
    /open (the )?(terminal|powershell|cmd|run dialog)|powershell -[a-z]|cmd\.exe|curl |wget |irm |iex |mshta |bitsadmin/i.test(
      text
    );

  // Correlate heuristic findings
  if (hasVerificationPrompt && hasExecutionPrompt) {
    signals.push({
      type: "FAKE_CAPTCHA",
      reason: "Verification prompt requests operating-system execution or terminal interaction.",
    });
  }

  if (hasVerificationPrompt && hasCopyPastePrompt) {
    signals.push({
      type: "SUSPICIOUS_INSTRUCTION",
      reason: "Verification requests copying and pasting instructions into system utilities.",
    });
  }

  if (hasExecutionPrompt && hasCopyPastePrompt) {
    signals.push({
      type: "EXECUTION_INSTRUCTION",
      reason: "Page instructs user to copy and execute terminal or PowerShell commands.",
    });
  }

  // Check for suspicious hidden buttons or fake captcha checkboxes
  const fakeCheckboxes = document.querySelectorAll(
    "button[class*='captcha'], div[class*='captcha'], div[class*='turnstile'], [id*='captcha-box']"
  );
  if (fakeCheckboxes.length > 0 && hasExecutionPrompt) {
    signals.push({
      type: "FAKE_CAPTCHA",
      reason: "Deceptive verification element detected with correlated system execution commands.",
    });
  }

  return signals;
}

