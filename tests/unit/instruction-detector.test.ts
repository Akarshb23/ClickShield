import { describe, it, expect } from "vitest";
import { detectSuspiciousInstructions } from "../../src/engine/detectors/instruction-detector";

describe("Instruction Detector", () => {
  it("detects Win+R sequence instructions directed at the user", () => {
    const text = "To verify, press Win + R on your keyboard, then paste the command and press enter.";
    const signals = detectSuspiciousInstructions(text);

    expect(signals.length).toBeGreaterThan(0);
    expect(signals[0].type).toBe("SUSPICIOUS_INSTRUCTION");
    expect(signals[0].reason).toContain("Run dialog");
  });

  it("detects paste into terminal instructions", () => {
    const text = "Open powershell as administrator and paste and press enter.";
    const signals = detectSuspiciousInstructions(text);

    expect(signals.length).toBeGreaterThan(0);
    expect(signals[0].type).toBe("SUSPICIOUS_INSTRUCTION");
  });

  it("ignores regular benign web content", () => {
    const text = "Welcome to the photography blog. Click here to see gallery images.";
    const signals = detectSuspiciousInstructions(text);

    expect(signals).toHaveLength(0);
  });
});
