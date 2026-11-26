import { describe, it, expect } from "vitest";
import { calculateRisk } from "../../src/engine/risk-engine";

describe("ClickShield Risk Engine", () => {
  it("returns zero score and LOW risk for empty signals", () => {
    const result = calculateRisk([]);
    expect(result.score).toBe(0);
    expect(result.level).toBe("LOW");
    expect(result.signals).toHaveLength(0);
  });

  it("deduplicates identical signal categories to prevent artificial score inflation", () => {
    const result = calculateRisk([
      { type: "FAKE_CAPTCHA", reason: "Found fake captcha 1" },
      { type: "FAKE_CAPTCHA", reason: "Found fake captcha 2" },
    ]);
    expect(result.score).toBe(calculateRisk([result.signals[0]]).score);
    expect(result.signals).toHaveLength(1);
    expect(result.level).toBe("LOW");
  });

  it("accurately calculates correlated multi-vector threats and classifies as CRITICAL", () => {
    const result = calculateRisk([
      { type: "FAKE_CAPTCHA", reason: "Deceptive captcha" },
      { type: "SUSPICIOUS_INSTRUCTION", reason: "Copy-paste to run" },
      { type: "EXECUTION_INSTRUCTION", reason: "Terminal launch requested" },
      { type: "CLIPBOARD_MANIPULATION", reason: "Clipboard write hooked" },
    ]);
    expect(result.score).toBeGreaterThanOrEqual(80);
    expect(result.level).toBe("CRITICAL");
  });

  it("keeps the learned score within the display range for all six features", () => {
    const result = calculateRisk([
      { type: "FAKE_CAPTCHA", reason: "1" },
      { type: "SUSPICIOUS_INSTRUCTION", reason: "2" },
      { type: "CLIPBOARD_MANIPULATION", reason: "3" },
      { type: "EXECUTION_INSTRUCTION", reason: "4" },
      { type: "SUSPICIOUS_DOMAIN", reason: "5" },
      { type: "DOMAIN_IMPERSONATION", reason: "6" },
    ]);
    expect(result.score).toBeLessThanOrEqual(100);
    expect(result.level).toBe("CRITICAL");
  });
});
