import type { ThreatSignal } from "../../shared/types/signal";
import { CAPTCHA_KEYWORDS, LEGITIMATE_CAPTCHA_IFRAMES } from "../rules/captcha-rules";

export interface CaptchaScanContext {
  text: string;
  hasIframes: boolean;
  iframeSources: string[];
  hasFakeCheckbox: boolean;
}

export function detectCaptchaAnomalies(context: CaptchaScanContext): ThreatSignal[] {
  const signals: ThreatSignal[] = [];
  const lowerText = context.text.toLowerCase();

  // Check if page claims to be a captcha or human verification
  const claimsCaptcha = CAPTCHA_KEYWORDS.some((kw) => lowerText.includes(kw));

  // Check if recognized legitimate captcha providers are present
  const hasLegitIframe = context.iframeSources.some((src) =>
    LEGITIMATE_CAPTCHA_IFRAMES.some((legit) => src.toLowerCase().includes(legit))
  );

  if (claimsCaptcha && !hasLegitIframe && context.hasFakeCheckbox) {
    signals.push({
      type: "FAKE_CAPTCHA",
      reason: "Simulated verification interface detected without standard provider infrastructure.",
      snippet: "Custom checkbox/button mimicking captcha controls.",
    });
  }

  // Look for text explicitly directing manual steps to 'solve' verification or fix simulated errors
  const manualSolvingDirectives = [
    "follow these steps to verify",
    "manual verification steps",
    "verification code will be generated",
    "to prove you are not a robot follow",
    "press the buttons below to verify",
    "copy and paste to fix",
    "perform the following steps",
    "run the command below to verify",
    "click verify and follow instructions",
  ];

  if (claimsCaptcha && !hasLegitIframe && manualSolvingDirectives.some((d) => lowerText.includes(d))) {
    signals.push({
      type: "FAKE_CAPTCHA",
      reason: "Deceptive verification prompt claims manual user actions or commands are required.",
    });
  }

  return signals;
}

