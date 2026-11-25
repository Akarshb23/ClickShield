import type { ThreatSignal } from "../../shared/types/signal";

export function detectExecutionCommands(text: string): ThreatSignal[] {
  const signals: ThreatSignal[] = [];

  // 1. Obfuscated / Encoded PowerShell execution patterns
  const encodedPsPattern = /powershell.*-(e|enc|encodedcommand)\s+[a-zA-Z0-9+/=]{12,}/i;
  // 2. Hidden window execution
  const hiddenWindowPattern = /powershell.*-w(indowstyle)?\s+h(idden)?/i;
  // 3. Download & Execute cradle patterns
  const downloadCradlePattern = /(irm|iex|invoke-expression|invoke-webrequest|downloadstring|start-process)\b/i;
  // 4. Windows native utility abuses
  const lolbinsPattern = /\b(mshta(\.exe)?|certutil(\.exe)?\s+(-urlcache|-decode)|bitsadmin(\.exe)?\s+\/transfer)\b/i;
  // 5. Unix pipeline curl/wget execution
  const unixPipelinePattern = /(curl|wget)\s+[^|\n\r]+(\||;)\s*(bash|sh|zsh)/i;

  if (encodedPsPattern.test(text)) {
    signals.push({
      type: "EXECUTION_INSTRUCTION",
      reason: "Detected base64-encoded PowerShell command execution string.",
      snippet: "PowerShell -EncodedCommand pattern.",
    });
  }

  if (hiddenWindowPattern.test(text)) {
    signals.push({
      type: "EXECUTION_INSTRUCTION",
      reason: "Detected stealth execution flag (hidden window mode) in command string.",
      snippet: "PowerShell -WindowStyle Hidden pattern.",
    });
  }

  if (downloadCradlePattern.test(text)) {
    signals.push({
      type: "EXECUTION_INSTRUCTION",
      reason: "Detected memory download & execute cradle syntax (irm/iex/Invoke-Expression).",
      snippet: "In-memory script download cradle detected.",
    });
  }

  if (lolbinsPattern.test(text)) {
    signals.push({
      type: "EXECUTION_INSTRUCTION",
      reason: "Detected living-off-the-land utility invocation (mshta / certutil / bitsadmin).",
      snippet: "LOLBin utility abuse pattern.",
    });
  }

  if (unixPipelinePattern.test(text)) {
    signals.push({
      type: "EXECUTION_INSTRUCTION",
      reason: "Detected dangerous remote script pipe into shell (curl/wget | sh).",
      snippet: "Remote execution pipeline detected.",
    });
  }

  return signals;
}

