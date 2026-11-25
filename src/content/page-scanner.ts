import type { ThreatSignal } from "../shared/types/signal";
import { detectCaptchaAnomalies } from "../engine/detectors/captcha-detector";
import { detectSuspiciousInstructions } from "../engine/detectors/instruction-detector";
import { detectExecutionCommands } from "../engine/detectors/command-detector";
import { detectDomainAnomalies } from "../engine/detectors/domain-detector";
import { detectBrandImpersonation } from "../engine/detectors/impersonation-detector";

export function scanPage(): ThreatSignal[] {
  // Avoid scanning inside ClickShield's own UI elements
  if (typeof document === "undefined" || !document.body) {
    return [];
  }

  const rawText = document.body.innerText || "";
  const hostname = window.location.hostname || "local-file";

  // 1. Gather iframe sources to check for legitimate CAPTCHA providers
  const iframes = Array.from(document.querySelectorAll("iframe"));
  const iframeSources = iframes
    .map((iframe) => iframe.src || iframe.getAttribute("data-src") || "")
    .filter(Boolean);

  // 2. Identify potential fake captcha checkboxes or deceptive verification elements
  const potentialButtons = document.querySelectorAll(
    "button, [role='button'], div[class*='captcha'], div[class*='turnstile'], [id*='captcha'], [id*='cf-turnstile'], [id*='verify'], [class*='verify']"
  );
  const hasFakeCheckbox = Array.from(potentialButtons).some((el) => {
    const text = (el.textContent || "").toLowerCase();
    const id = (el.id || "").toLowerCase();
    const cls = (el.className || "").toString().toLowerCase();
    return (
      /captcha|turnstile|verify|human|robot|check/i.test(text) ||
      /captcha|turnstile|verify|robot/i.test(id) ||
      /captcha|turnstile|verify|robot/i.test(cls)
    );
  });

  // 3. Extract text from code blocks, input values, and pre tags where payloads hide
  const codeSnippets = Array.from(document.querySelectorAll("code, pre, blockquote, input[type='text']"))
    .map((el) => (el instanceof HTMLInputElement ? el.value : el.textContent || ""))
    .join(" ");

  const combinedContent = `${rawText} ${codeSnippets}`;

  const allSignals: ThreatSignal[] = [];

  // Run Modular Detectors
  allSignals.push(
    ...detectCaptchaAnomalies({
      text: rawText,
      hasIframes: iframes.length > 0,
      iframeSources,
      hasFakeCheckbox,
    })
  );

  allSignals.push(...detectSuspiciousInstructions(combinedContent));
  allSignals.push(...detectExecutionCommands(combinedContent));
  allSignals.push(...detectDomainAnomalies(hostname));
  allSignals.push(...detectBrandImpersonation(rawText, hostname));

  return allSignals;
}
