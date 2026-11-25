import { describe, it, expect } from "vitest";
import { detectCaptchaAnomalies } from "../../src/engine/detectors/captcha-detector";

describe("Captcha Detector", () => {
  it("flags fake captcha prompts lacking legitimate iframe providers", () => {
    const signals = detectCaptchaAnomalies({
      text: "Please verify that you are human to continue. Complete manual verification.",
      hasIframes: false,
      iframeSources: [],
      hasFakeCheckbox: true,
    });

    expect(signals.length).toBeGreaterThan(0);
    expect(signals[0].type).toBe("FAKE_CAPTCHA");
  });

  it("does not flag legitimate captcha providers with official iframes", () => {
    const signals = detectCaptchaAnomalies({
      text: "verify that you are human",
      hasIframes: true,
      iframeSources: ["https://challenges.cloudflare.com/turnstile/v0/api.js"],
      hasFakeCheckbox: false,
    });

    expect(signals).toHaveLength(0);
  });
});
