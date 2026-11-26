
import type { ThreatSignal } from "../../shared/types/signal";

// ==========================================================
// CONSTANTS
// ==========================================================

const MAX_INPUT_LENGTH = 100000;

const WINDOWS_RUN_PATTERN =
  /\b(?:press|hit|hold|use|type)\s+(?:the\s+)?(?:windows?(?:\s+key)?\s*[\s+-]\s*r|win\s*[\s+-]\s*r)\b|\b(?:open|launch)\s+(?:the\s+)?run\s+(?:dialog|box|window)\b/i;

const WINDOWS_RUN_REFERENCE_PATTERN =
  /\b(?:win(?:dows)?\s*(?:\+\s*|\s+)\s*r|run\s+(?:dialog|box|window))\b/i;

const CTRL_V_PATTERN =
  /\b(?:press|hit|use)\s+(?:the\s+)?(?:ctrl|control)\s*[\s+-]\s*v\b/i;

const PASTE_ENTER_PATTERN =
  /\b(?:paste|insert)\b.{0,180}?\b(?:and\s+then\s+|then\s+)?(?:press|hit|tap)?\s*enter\b/i;

const PASTE_COMMAND_PATTERN =
  /\b(?:copy\s+and\s+)?paste\b.{0,180}?\b(?:the\s+)?(?:command|code|script|payload|text)\b|\b(?:paste|copy)\b.{0,120}?\b(?:into|in)\s+(?:the\s+)?(?:run|powershell|cmd|command\s+prompt|terminal|bash|zsh)\b/i;

const TERMINAL_PATTERN =
  /\b(?:powershell(?:\.exe)?|pwsh|cmd(?:\.exe)?|command\s+prompt|terminal|bash|zsh)\b/i;

const TERMINAL_OPEN_PATTERN =
  /\b(?:open|launch|start)\s+(?:the\s+)?(?:powershell(?:\.exe)?|pwsh|cmd(?:\.exe)?|command\s+prompt|terminal|bash|zsh)\b/i;

const TERMINAL_DIRECT_ACTION_PATTERN =
  /\b(?:paste|copy|type|enter|execute|run)\b.{0,180}?\b(?:into|in)\s+(?:the\s+)?(?:powershell(?:\.exe)?|pwsh|cmd(?:\.exe)?|command\s+prompt|terminal|bash|zsh)\b/i;

const EXECUTION_VERB_PATTERN =
  /\b(?:paste|copy|execute|run|enter|type)\b/i;

const CLICKFIX_STEP_SEQUENCE_PATTERN =
  /(?:step\s*)?1\s*[:.)-][\s\S]{0,250}?\b(?:win\s*[\s+-]\s*r|run\s+(?:dialog|box|window))\b[\s\S]{0,250}?(?:step\s*)?2\s*[:.)-][\s\S]{0,250}?\b(?:ctrl\s*[\s+-]\s*v|paste)\b[\s\S]{0,250}?(?:step\s*)?3\s*[:.)-][\s\S]{0,250}?\b(?:press\s+|hit\s+)?(?:enter|ok)\b/i;

const MAC_TERMINAL_PATTERN =
  /\b(?:press|use)\s+(?:the\s+)?(?:cmd|command)\s*[\s+-]\s*space\b[\s\S]{0,150}?\b(?:open|launch|type)\b[\s\S]{0,100}?\bterminal\b|\b(?:paste|copy)\b.{0,120}?\binto\s+(?:the\s+)?terminal\b/i;

const COMMAND_EXECUTION_CONTEXT_PATTERN =
  /\b(?:verification|verify|human|captcha|turnstile|recaptcha|security\s+check|confirm\s+identity|fix\s+error|complete\s+verification)\b/i;

// ==========================================================
// HELPERS
// ==========================================================

function normalizeInstructionText(text: string): string {
  return text
    .replace(/\u00a0/g, " ")
    .replace(/[ \t]+/g, " ")
    .replace(/\r/g, "\n")
    .slice(0, MAX_INPUT_LENGTH);
}

function createInstructionSignal(
  reason: string,
  snippet: string
): ThreatSignal {
  return {
    type: "SUSPICIOUS_INSTRUCTION",
    reason,
    snippet,
  };
}

// ==========================================================
// MAIN DETECTOR
// ==========================================================

export function detectSuspiciousInstructions(
  text: string
): ThreatSignal[] {
  const signals: ThreatSignal[] = [];

  if (
    typeof text !== "string" ||
    !text.trim()
  ) {
    return signals;
  }

  const normalized = normalizeInstructionText(text);

  // --------------------------------------------------------
  // 1. Detect direct Windows Run dialog instructions
  // --------------------------------------------------------

  const hasWindowsRunInstruction =
    WINDOWS_RUN_PATTERN.test(normalized);

  const hasWindowsRunReference =
    WINDOWS_RUN_REFERENCE_PATTERN.test(normalized);

  // A keyboard shortcut reference alone is not an instruction.
  const hasWinR = hasWindowsRunInstruction;

  // --------------------------------------------------------
  // 2. Detect paste and keyboard instructions
  // --------------------------------------------------------

  const hasCtrlV = CTRL_V_PATTERN.test(normalized);

  const hasPasteEnter =
    PASTE_ENTER_PATTERN.test(normalized);

  const hasPasteCommand =
    PASTE_COMMAND_PATTERN.test(normalized);

  const hasPasteAction =
    hasCtrlV || hasPasteEnter || hasPasteCommand;

  // --------------------------------------------------------
  // 3. Detect terminal interaction
  // --------------------------------------------------------

  const hasTerminal =
    TERMINAL_PATTERN.test(normalized);

  const hasTerminalOpen =
    TERMINAL_OPEN_PATTERN.test(normalized);

  const hasTerminalDirectAction =
    TERMINAL_DIRECT_ACTION_PATTERN.test(normalized);

  const hasMacTerminal =
    MAC_TERMINAL_PATTERN.test(normalized);

  const hasTerminalExecution =
    hasTerminalDirectAction ||
    hasMacTerminal ||
    (
      hasTerminalOpen &&
      hasPasteAction
    ) ||
    (
      hasTerminal &&
      hasPasteEnter &&
      EXECUTION_VERB_PATTERN.test(normalized)
    );

  // --------------------------------------------------------
  // 4. Detect numbered ClickFix sequences
  // --------------------------------------------------------

  const hasStepSequence =
    CLICKFIX_STEP_SEQUENCE_PATTERN.test(normalized);

  // --------------------------------------------------------
  // 5. Detect combined ClickFix behavior
  // --------------------------------------------------------

  const hasWindowsClickFixSequence =
    hasWinR &&
    (
      hasPasteAction ||
      hasTerminalExecution
    );

  const hasTerminalClickFixSequence =
    hasTerminalExecution &&
    hasPasteAction;

  const hasVerificationContext =
    COMMAND_EXECUTION_CONTEXT_PATTERN.test(normalized);

  const isCombinedClickFix =
    hasStepSequence ||
    hasWindowsClickFixSequence ||
    hasTerminalClickFixSequence;

  // --------------------------------------------------------
  // 6. Produce the appropriate detection signal
  // --------------------------------------------------------

  if (isCombinedClickFix) {
    signals.push(
      createInstructionSignal(
        "Page directs the user to open a system Run dialog or terminal and paste or execute commands in a ClickFix-style sequence.",
        "Run dialog / terminal command execution sequence detected."
      )
    );

    return signals;
  }

  // --------------------------------------------------------
  // 7. Detect isolated Run dialog instructions
  // --------------------------------------------------------

  if (hasWinR) {
    signals.push(
      createInstructionSignal(
        "Page directly instructs the user to invoke the operating system Run dialog using the Win+R shortcut.",
        "Win+R shortcut instruction."
      )
    );

    return signals;
  }

  // --------------------------------------------------------
  // 8. Detect isolated terminal execution instructions
  // --------------------------------------------------------

  if (
    hasTerminalDirectAction ||
    hasMacTerminal
  ) {
    signals.push(
      createInstructionSignal(
        "Page directs the user to paste or enter content into a system terminal.",
        "Terminal copy-paste instruction detected."
      )
    );

    return signals;
  }

  // --------------------------------------------------------
  // 9. Detect verification-linked terminal instructions
  // --------------------------------------------------------

  if (
    hasTerminalOpen &&
    hasPasteAction &&
    hasVerificationContext
  ) {
    signals.push(
      createInstructionSignal(
        "Page combines verification-related language with instructions to open a system terminal and paste commands.",
        "Verification-linked terminal execution detected."
      )
    );
  }

  return signals;
}
