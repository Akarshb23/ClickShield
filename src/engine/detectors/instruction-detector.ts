import type { ThreatSignal } from "../../shared/types/signal";

export function detectSuspiciousInstructions(text: string): ThreatSignal[] {
  const signals: ThreatSignal[] = [];
  const lower = text.toLowerCase();

  // Shortcut combinations commonly weaponized in ClickFix
  const winRPattern = /\b(press|hit|hold)\s+(win(dows)?\s*\+\s*r|windows\s*key\s*\+\s*r)\b/i;
  const runDialogPattern = /\b(open|launch)\s+(the\s+)?run\s+dialog\b/i;
  const ctrlVPattern = /\b(press|hit)\s+(ctrl\s*\+\s*v|control\s*\+\s*v)\b/i;
  const pasteEnterPattern = /\bpaste(\s+.*)?\s+and\s+(press|hit)\s+enter\b/i;
  const terminalInstruction = /\b(open|paste\s+into|launch)\s+(powershell|cmd|terminal|command\s+prompt)\b/i;

  const hasWinR = winRPattern.test(lower) || runDialogPattern.test(lower);
  const hasPasteEnter = ctrlVPattern.test(lower) || pasteEnterPattern.test(lower);
  const hasTerminal = terminalInstruction.test(lower);

  if (hasWinR && (hasPasteEnter || hasTerminal)) {
    signals.push({
      type: "SUSPICIOUS_INSTRUCTION",
      reason: "Page directs user to open Run dialog (Win+R) and paste instructions.",
      snippet: "Win+R / paste sequence detected.",
    });
  } else if (hasWinR) {
    signals.push({
      type: "SUSPICIOUS_INSTRUCTION",
      reason: "Page instructs the user to invoke the operating system Run dialog.",
      snippet: "Win+R shortcut instruction.",
    });
  } else if (hasTerminal || hasPasteEnter) {
    signals.push({
      type: "SUSPICIOUS_INSTRUCTION",
      reason: "Page directs user to paste or execute commands into system terminal.",
      snippet: "Terminal copy-paste sequence detected.",
    });
  }

  return signals;
}
