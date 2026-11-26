
import type {
  ThreatSignal,
  SignalType,
  RiskLevel,
} from "../shared/types/signal";

import { calculateRisk } from "./risk-engine";

// ==========================================================
// TYPES
// ==========================================================

export interface CorrelatedVerdict {
  isClickFixAttack: boolean;
  score: number;
  level: RiskLevel;
  signals: ThreatSignal[];
  primaryAttackVector: string;
  recommendedAction: string;
}

interface SignalContext {
  hasFakeCaptcha: boolean;
  hasExecution: boolean;
  hasInstruction: boolean;
  hasImpersonation: boolean;
  hasClipboard: boolean;
  hasSuspiciousDomain: boolean;
}

// ==========================================================
// SIGNAL ANALYSIS
// ==========================================================

/**
 * Analyze normalized signals and identify the presence
 * of each supported threat category.
 */
function analyzeSignals(
  signals: readonly ThreatSignal[]
): SignalContext {
  const types = new Set<SignalType>(
    signals.map((signal) => signal.type)
  );

  return {
    hasFakeCaptcha: types.has("FAKE_CAPTCHA"),
    hasExecution: types.has("EXECUTION_INSTRUCTION"),
    hasInstruction: types.has("SUSPICIOUS_INSTRUCTION"),
    hasImpersonation: types.has("DOMAIN_IMPERSONATION"),
    hasClipboard: types.has("CLIPBOARD_MANIPULATION"),
    hasSuspiciousDomain: types.has("SUSPICIOUS_DOMAIN"),
  };
}

// ==========================================================
// CLICKFIX CORRELATION
// ==========================================================

/**
 * A ClickFix attack requires two categories of evidence:
 *
 * 1. A deceptive verification or impersonation lure.
 * 2. An actionable execution, clipboard or manual
 *    command-paste instruction.
 *
 * Individual suspicious signals do not automatically
 * establish a complete ClickFix attack.
 */
function detectClickFixAttack(
  context: SignalContext
): boolean {
  const hasDeceptiveLure =
    context.hasFakeCaptcha ||
    context.hasImpersonation;

  const hasAttackAction =
    context.hasExecution ||
    context.hasClipboard ||
    context.hasInstruction;

  return hasDeceptiveLure && hasAttackAction;
}

// ==========================================================
// ATTACK CLASSIFICATION
// ==========================================================

function classifyAttackVector(
  context: SignalContext,
  isClickFixAttack: boolean
): {
  primaryAttackVector: string;
  recommendedAction: string;
} {

  // --------------------------------------------------------
  // 1. Complete ClickFix attack
  // --------------------------------------------------------

  if (isClickFixAttack) {
    return {
      primaryAttackVector:
        "ClickFix Attack (Fake Verification Coercing Terminal Execution)",

      recommendedAction:
        "Do not copy, paste, or execute instructions from this webpage. Leave immediately.",
    };
  }

  // --------------------------------------------------------
  // 2. Brand impersonation and fake verification
  // --------------------------------------------------------

  if (
    context.hasFakeCaptcha &&
    context.hasImpersonation
  ) {
    return {
      primaryAttackVector:
        "Brand Impersonation & Fake Verification",

      recommendedAction:
        "Do not interact with the simulated verification widgets on this page.",
    };
  }

  // --------------------------------------------------------
  // 3. Brand impersonation
  // --------------------------------------------------------

  if (context.hasImpersonation) {
    return {
      primaryAttackVector:
        "Potential Brand Impersonation",

      recommendedAction:
        "Verify the website's hostname before entering credentials or interacting with its security prompts.",
    };
  }

  // --------------------------------------------------------
  // 4. Fake CAPTCHA
  // --------------------------------------------------------

  if (context.hasFakeCaptcha) {
    return {
      primaryAttackVector:
        "Suspicious Verification Interface",

      recommendedAction:
        "Do not follow unexpected verification instructions or execute commands to complete a CAPTCHA.",
    };
  }

  // --------------------------------------------------------
  // 5. Execution instructions
  // --------------------------------------------------------

  if (context.hasExecution) {
    return {
      primaryAttackVector:
        "Suspicious Command Line Instruction",

      recommendedAction:
        "Avoid executing unknown PowerShell, terminal or command-line snippets.",
    };
  }

  // --------------------------------------------------------
  // 6. Clipboard manipulation
  // --------------------------------------------------------

  if (context.hasClipboard) {
    return {
      primaryAttackVector:
        "Suspicious Clipboard Manipulation",

      recommendedAction:
        "Do not paste or execute unexpected clipboard contents. Inspect suspicious commands before proceeding.",
    };
  }

  // --------------------------------------------------------
  // 7. Manual execution instructions
  // --------------------------------------------------------

  if (context.hasInstruction) {
    return {
      primaryAttackVector:
        "Suspicious Manual Execution Instructions",

      recommendedAction:
        "Do not follow unexpected instructions asking you to open system dialogs or paste commands.",
    };
  }

  // --------------------------------------------------------
  // 8. Suspicious domain
  // --------------------------------------------------------

  if (context.hasSuspiciousDomain) {
    return {
      primaryAttackVector:
        "Suspicious Domain Activity",

      recommendedAction:
        "Verify the website's domain and reputation before interacting with it.",
    };
  }

  // --------------------------------------------------------
  // 9. No recognized attack vector
  // --------------------------------------------------------

  return {
    primaryAttackVector:
      "Standard Page Analysis",

    recommendedAction:
      "Passive monitoring active.",
  };
}

// ==========================================================
// MAIN CORRELATOR
// ==========================================================

export function correlateSignals(
  signals: readonly ThreatSignal[] | null | undefined,
  context?: {
    hostname?: string;
    url?: string;
  }
): CorrelatedVerdict {

  // --------------------------------------------------------
  // 1. Calculate authoritative risk
  // --------------------------------------------------------

  const scanResult = calculateRisk(
    signals,
    context
  );

  // --------------------------------------------------------
  // 2. Use normalized, deduplicated signals
  // --------------------------------------------------------

  const normalizedSignals = scanResult.signals;

  // --------------------------------------------------------
  // 3. Analyze signal combinations
  // --------------------------------------------------------

  const signalContext = analyzeSignals(
    normalizedSignals
  );

  // --------------------------------------------------------
  // 4. Detect correlated ClickFix behavior
  // --------------------------------------------------------

  const isClickFixAttack =
    detectClickFixAttack(signalContext);

  // --------------------------------------------------------
  // 5. Determine primary attack vector
  // --------------------------------------------------------

  const classification = classifyAttackVector(
    signalContext,
    isClickFixAttack
  );

  // --------------------------------------------------------
  // 6. Return final verdict
  // --------------------------------------------------------

  return {
    isClickFixAttack,
    score: scanResult.score,
    level: scanResult.level,
    signals: normalizedSignals,

    primaryAttackVector:
      classification.primaryAttackVector,

    recommendedAction:
      classification.recommendedAction,
  };
}
