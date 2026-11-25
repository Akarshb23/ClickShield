import { describe, it, expect, beforeEach, afterEach } from "vitest";
import { WarningOverlay } from "../../src/protection/warning-overlay";
import type { ScanResult } from "../../src/shared/types/signal";

describe("Warning Overlay", () => {
  beforeEach(() => {
    WarningOverlay.hide();
  });

  afterEach(() => {
    WarningOverlay.hide();
  });

  it("injects a Shadow DOM isolated overlay into the document body", () => {
    const mockScan: ScanResult = {
      score: 85,
      level: "CRITICAL",
      signals: [
        { type: "FAKE_CAPTCHA", reason: "Deceptive captcha" },
        { type: "EXECUTION_INSTRUCTION", reason: "PowerShell commands" },
      ],
      hostname: "malicious-fixture.test",
      timestamp: Date.now(),
    };

    WarningOverlay.show(mockScan);

    expect(WarningOverlay.isVisible()).toBe(true);
    const hostEl = document.getElementById("clickshield-security-warning");
    expect(hostEl).not.toBeNull();
    expect(hostEl?.getAttribute("data-clickshield-ignore")).toBe("true");
  });

  it("removes the overlay when hidden", () => {
    const mockScan: ScanResult = {
      score: 90,
      level: "CRITICAL",
      signals: [{ type: "FAKE_CAPTCHA", reason: "Test" }],
      timestamp: Date.now(),
    };

    WarningOverlay.show(mockScan);
    expect(WarningOverlay.isVisible()).toBe(true);

    WarningOverlay.hide();
    expect(WarningOverlay.isVisible()).toBe(false);
    expect(document.getElementById("clickshield-security-warning")).toBeNull();
  });
});

