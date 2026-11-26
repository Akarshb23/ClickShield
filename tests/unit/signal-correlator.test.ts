import { describe, it, expect } from "vitest";
import { correlateSignals } from "../../src/engine/signal-correlator";

describe("Signal Correlator", () => {
  it("identifies classic ClickFix attack vector when fake captcha and terminal execution co-occur", () => {
    const verdict = correlateSignals([
      { type: "FAKE_CAPTCHA", reason: "Deceptive captcha" },
      { type: "EXECUTION_INSTRUCTION", reason: "PowerShell command" },
    ]);

    expect(verdict.isClickFixAttack).toBe(true);
    expect(verdict.primaryAttackVector).toContain("ClickFix Attack");
    expect(verdict.score).toBeGreaterThanOrEqual(45);
  });

  it("handles isolated single signals gracefully without false alarm of full ClickFix", () => {
    const verdict = correlateSignals([
      { type: "SUSPICIOUS_DOMAIN", reason: "High-abuse TLD" },
    ]);

    expect(verdict.isClickFixAttack).toBe(false);
    expect(verdict.score).toBeLessThan(30);
    expect(verdict.level).toBe("LOW");
  });
});
