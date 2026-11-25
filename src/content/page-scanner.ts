import type { ThreatSignal } from "../shared/types/signal";
import { detectCaptchaAnomalies } from "../engine/detectors/captcha-detector";
import { detectSuspiciousInstructions } from "../engine/detectors/instruction-detector";
import { detectExecutionCommands } from "../engine/detectors/command-detector";
import { detectDomainAnomalies } from "../engine/detectors/domain-detector";
import { detectBrandImpersonation } from "../engine/detectors/impersonation-detector";

function extractShadowDomData(root: Node): { text: string; snippets: string[] } {
  let text = "";
  const snippets: string[] = [];

  try {
    const walker = document.createTreeWalker(root, NodeFilter.SHOW_ELEMENT, null);
    let currentNode: Node | null = walker.currentNode;

    while (currentNode) {
      if (currentNode instanceof HTMLElement) {
        // Collect data attributes where payloads or commands hide
        for (const attr of currentNode.attributes) {
          if (attr.name.startsWith("data-") || attr.name === "title" || attr.name === "aria-label") {
            if (attr.value && attr.value.length > 5) {
              snippets.push(attr.value);
            }
          }
        }

        // Check if element has an open shadow root
        if (currentNode.shadowRoot && currentNode.id !== "clickshield-security-warning") {
          const shadowData = extractShadowDomData(currentNode.shadowRoot);
          text += " " + shadowData.text;
          snippets.push(...shadowData.snippets);
        }
      }
      currentNode = walker.nextNode();
    }
  } catch {}

  return { text, snippets };
}

export function scanPage(): ThreatSignal[] {
  // Avoid scanning inside ClickShield's own UI elements or test harness
  if (
    typeof document === "undefined" ||
    !document.body ||
    document.body.hasAttribute("data-clickshield-ignore") ||
    document.documentElement.hasAttribute("data-clickshield-ignore")
  ) {
    return [];
  }

  const titleText = document.title || "";
  const bodyInnerText = document.body.innerText || "";
  const rawText = `${titleText} ${bodyInnerText}`;
  const hostname = window.location.hostname || "local-file";

  // 1. Gather iframe sources to check for legitimate CAPTCHA providers
  const iframes = Array.from(document.querySelectorAll("iframe"));
  const iframeSources = iframes
    .map((iframe) => iframe.src || iframe.getAttribute("data-src") || "")
    .filter(Boolean);

  // 2. Identify potential fake captcha checkboxes or deceptive verification elements
  const potentialButtons = document.querySelectorAll(
    "button, [role='button'], div[class*='captcha'], div[class*='turnstile'], [id*='captcha'], [id*='cf-turnstile'], [id*='verify'], [class*='verify'], div[class*='checkbox'], span[class*='checkbox']"
  );
  const hasFakeCheckbox = Array.from(potentialButtons).some((el) => {
    const text = (el.textContent || "").toLowerCase();
    const id = (el.id || "").toLowerCase();
    const cls = (el.className || "").toString().toLowerCase();
    const aria = (el.getAttribute("aria-label") || "").toLowerCase();
    return (
      /(\bverify\s+(you\s+are\s+)?(human|not\s+a\s+robot)\b|i'm\s+not\s+a\s+robot|i\s+am\s+not\s+a\s+robot|\b(captcha|turnstile|recaptcha|hcaptcha)\b|\bverify\s+human\b|\bverify\s+checkbox\b)/i.test(
        text
      ) ||
      /[_-]?(captcha|turnstile|recaptcha|hcaptcha|fake-checkbox)[_-]?/i.test(id) ||
      /[_-]?(captcha|turnstile|recaptcha|hcaptcha|fake-checkbox)[_-]?/i.test(cls) ||
      /captcha|turnstile|verify\s+human/i.test(aria)
    );
  });

  // 3. Extract text from code blocks, inputs, textareas, and data-clipboard attributes
  const codeElements = Array.from(
    document.querySelectorAll("code, pre, blockquote, input, textarea, [data-clipboard-text], [data-copy], [data-payload], [data-command]")
  );
  const codeSnippets = codeElements
    .map((el) => {
      let content = "";
      if (el instanceof HTMLInputElement || el instanceof HTMLTextAreaElement) {
        content = `${el.value} ${el.placeholder || ""}`;
      } else {
        content = el.textContent || "";
      }

      const dataClipboard = el.getAttribute("data-clipboard-text") || el.getAttribute("data-copy") || el.getAttribute("data-payload") || el.getAttribute("data-command") || "";
      return `${content} ${dataClipboard}`;
    })
    .join(" ");

  // 4. Shadow DOM recursive traversal for modular web applications
  const shadowDomData = extractShadowDomData(document.body);
  const shadowText = `${shadowDomData.text} ${shadowDomData.snippets.join(" ")}`;

  const combinedContent = `${rawText} ${codeSnippets} ${shadowText}`;

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
  allSignals.push(...detectBrandImpersonation(titleText, hostname));

  return allSignals;
}
