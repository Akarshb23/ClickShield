import type { ThreatSignal } from "../../shared/types/signal";

export function detectExecutionCommands(text: string): ThreatSignal[] {
  const signals: ThreatSignal[] = [];

  // 1. Obfuscated / Encoded PowerShell execution patterns
  const encodedPsPattern = /powershell.*-(e|enc|encodedcommand)\s+[a-zA-Z0-9+/=]{8,}/i;
  // 2. Hidden window or execution policy bypass flags
  const stealthFlagsPattern = /powershell.*(-w(indowstyle)?\s+h(idden)?|-nop(rofile)?|-noni(nteractive)?|-ep\s+bypass|-executionpolicy\s+bypass)/i;
  // 3. Download & Execute cradle patterns - strictly requiring word boundary before command names
  const downloadCradlePattern =
    /\b(irm|iex|invoke-expression|invoke-webrequest|iwr|invoke-restmethod|downloadstring|downloadfile|start-process|system\.net\.webclient)\b/i;
  // 4. Windows native utility abuses (LOLBins)
  const lolbinsPattern = /\b(mshta(\.exe)?|certutil(\.exe)?\s+(-urlcache|-decode|-f)|bitsadmin(\.exe)?\s+\/transfer|regsvr32(\.exe)?.*(\/s|\/u|\/i:)|rundll32(\.exe)?|wscript(\.exe)?|cscript(\.exe)?)\b/i;
  // 5. Shell invocation with command execution switches
  const shellExecPattern = /\b(cmd(\.exe)?\s+(\/c|\/k)|powershell(\.exe)?\s+(-c|-command|\/c))\s+/i;
  // 6. Base64 or string encoding decoders in commands
  const decoderPattern = /(\[Convert\]::FromBase64String|\[System\.Text\.Encoding\]|\[char\[\]\])/i;
  // 7. Security software tampering / defense evasion
  const defenseEvasionPattern = /(Set-MpPreference.*-DisableRealtime|Add-MpPreference|schtasks\s+\/create|reg\s+add\s+hklm)/i;
  // 8. Unix / Mac execution pipelines
  const unixPipelinePattern = /(curl|wget)\s+[^|\n\r]+(\||;)\s*(bash|sh|zsh)/i;
  // 9. Mac ClickFix / AppleScript / direct shell runners
  const macExecPattern = /(osascript\s+-e|bash\s+-c\s+["'].*curl|sh\s+-c\s+["'].*curl|base64\s+-d\s*\|\s*(ba)?sh)/i;

  if (encodedPsPattern.test(text)) {
    signals.push({
      type: "EXECUTION_INSTRUCTION",
      reason: "Detected base64-encoded PowerShell command execution string.",
      snippet: "PowerShell -EncodedCommand pattern.",
    });
  }

  if (stealthFlagsPattern.test(text)) {
    signals.push({
      type: "EXECUTION_INSTRUCTION",
      reason: "Detected stealth execution or execution policy bypass flags in command string.",
      snippet: "Stealth / Bypass command pattern.",
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
      reason: "Detected living-off-the-land utility invocation (mshta / certutil / bitsadmin / regsvr32).",
      snippet: "LOLBin utility abuse pattern.",
    });
  }

  if (shellExecPattern.test(text)) {
    signals.push({
      type: "EXECUTION_INSTRUCTION",
      reason: "Detected direct shell command execution switch (cmd /c or powershell -c).",
      snippet: "Direct shell execution string.",
    });
  }

  if (decoderPattern.test(text)) {
    signals.push({
      type: "EXECUTION_INSTRUCTION",
      reason: "Detected programmatic string decoding/conversion function typical of obfuscated payloads.",
      snippet: "In-line payload decoder.",
    });
  }

  if (defenseEvasionPattern.test(text)) {
    signals.push({
      type: "EXECUTION_INSTRUCTION",
      reason: "Detected command attempting to disable antivirus or register persistence tasks.",
      snippet: "Defense evasion / persistence attempt.",
    });
  }

  if (unixPipelinePattern.test(text) || macExecPattern.test(text)) {
    signals.push({
      type: "EXECUTION_INSTRUCTION",
      reason: "Detected dangerous remote script pipe into shell (curl/wget | sh or osascript).",
      snippet: "Remote execution pipeline detected.",
    });
  }

  return signals;
}

