import { describe, it, expect } from "vitest";
import { scanPage } from "../../src/content/page-scanner";
import { correlateSignals } from "../../src/engine/signal-correlator";
import { detectCaptchaAnomalies } from "../../src/engine/detectors/captcha-detector";
import { detectSuspiciousInstructions } from "../../src/engine/detectors/instruction-detector";
import { calculateRisk } from "../../src/engine/risk-engine";

describe("False Positive Prevention & Calibration", () => {
  it("classifies normal websites as zero risk and non-ClickFix", () => {
    const text = "Artisanal Coffee Delivered to Your Door. Shop Roast Selection.";
    const signals = detectSuspiciousInstructions(text);
    const result = calculateRisk(signals);
    const verdict = correlateSignals(signals);

    expect(result.score).toBe(0);
    expect(result.level).toBe("LOW");
    expect(verdict.isClickFixAttack).toBe(false);
  });

  it("does not classify developer documentation discussing PowerShell as a ClickFix attack", () => {
    const docText = `
      PowerShell is a cross-platform task automation framework.
      To inspect active processes use: Get-Process | Where-Object WorkingSet -gt 100MB.
      To test network connectivity use: Invoke-WebRequest -Uri "https://api.github.com/repos".
    `;

    // Educational content should NOT trigger fake captcha or Win+R sequence instructions
    const captchaSignals = detectCaptchaAnomalies({
      text: docText,
      hasIframes: false,
      iframeSources: [],
      hasFakeCheckbox: false,
    });

    const instructionSignals = detectSuspiciousInstructions(docText);

    expect(captchaSignals).toHaveLength(0);
    expect(instructionSignals).toHaveLength(0);

    const combinedSignals = [...captchaSignals, ...instructionSignals];
    const verdict = correlateSignals(combinedSignals);

    expect(verdict.isClickFixAttack).toBe(false);
    expect(verdict.score).toBeLessThan(30);
  });

  it("does not trigger fake captcha alerts on pages containing legitimate Cloudflare Turnstile iframes", () => {
    const pageText = "Checking your browser before accessing the website. Verify that you are human.";
    const signals = detectCaptchaAnomalies({
      text: pageText,
      hasIframes: true,
      iframeSources: ["https://challenges.cloudflare.com/turnstile/v0/api.js"],
      hasFakeCheckbox: false,
    });

    expect(signals).toHaveLength(0);
  });
});

