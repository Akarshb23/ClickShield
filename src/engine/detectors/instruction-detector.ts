import type { ThreatSignal } from "../../shared/types/signal";

export function detectSuspiciousInstructions(text: string): ThreatSignal[] {
  const signals: ThreatSignal[] = [];
  const lower = text.toLowerCase();

  // Shortcut combinations commonly weaponized in ClickFix
  const winRPattern = /\b(press|hit|hold|type|open)?\s*(the\s+)?(win(dows)?(\s*key)?\s*[\+\-]\s*r|win\s*r|run\s*(dialog|box|window))\b/i;
  const runDialogPattern = /\b(open|launch|in\s+the)\s+(the\s+)?run\s*(dialog|box|window)\b/i;
  const ctrlVPattern = /\b(press|hit)?\s*(ctrl|control)\s*[\+\-]\s*v\b/i;
  const pasteEnterPattern = /\bpaste(\s+.*)?\s+(and\s+)?(press|hit)?\s*enter\b/i;
  const pasteGeneral = /\b(right[\s\-]*click\s+and\s+)?paste\s+(it|the\s+(code|command|key|text|script|payload))\b/i;
  const terminalInstruction =
    /\b(paste.*into|copy.*into|type.*into|paste.*in|run.*in)\s+(the\s+)?(powershell(\.exe)?|cmd(\.exe)?|terminal|command\s+prompt|bash|zsh)\b/i;
  const stepPattern = /(1[\.\)]\s*.*?(win\s*[\+\-]?\s*r|run).*?2[\.\)]\s*.*?(ctrl\s*[\+\-]?\s*v|paste).*?3[\.\)]\s*.*?(enter|ok))/is;
  const macTerminalPattern = /\b(press\s+(cmd|command)\s*[\+\-]\s*space.*?terminal|paste\s+into\s+terminal)\b/i;

  const hasWinR = winRPattern.test(lower) || runDialogPattern.test(lower);
  const hasPasteEnter = ctrlVPattern.test(lower) || pasteEnterPattern.test(lower) || pasteGeneral.test(lower);
  const hasTerminal = terminalInstruction.test(lower) || macTerminalPattern.test(lower);
  const hasStepSequence = stepPattern.test(lower);

  if (hasStepSequence || (hasWinR && (hasPasteEnter || hasTerminal))) {
    signals.push({
      type: "SUSPICIOUS_INSTRUCTION",
      reason: "Page directs user to open Run dialog (Win+R) and execute commands in ClickFix sequence.",
      snippet: "Win+R / terminal execution sequence detected.",
    });
  } else if (hasWinR) {
    signals.push({
      type: "SUSPICIOUS_INSTRUCTION",
      reason: "Page instructs the user to invoke the operating system Run dialog (Win+R).",
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
