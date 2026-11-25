import type { ThreatSignal, SignalType } from "../shared/types/signal";
import { calculateRisk } from "./risk-engine";

export interface CorrelatedVerdict {
  isClickFixAttack: boolean;
  score: number;
  level: string;
  signals: ThreatSignal[];
  primaryAttackVector: string;
  recommendedAction: string;
}

export function correlateSignals(
  signals: ThreatSignal[],
  context?: { hostname?: string; url?: string }
): CorrelatedVerdict {
  const scanResult = calculateRisk(signals, context);
  const types = new Set<SignalType>(scanResult.signals.map((s) => s.type));

  const hasFakeCaptcha = types.has("FAKE_CAPTCHA");
  const hasExecution = types.has("EXECUTION_INSTRUCTION");
  const hasInstruction = types.has("SUSPICIOUS_INSTRUCTION");
  const hasImpersonation = types.has("DOMAIN_IMPERSONATION");
  const hasClipboard = types.has("CLIPBOARD_MANIPULATION");

  // Classic ClickFix signature: Deceptive verification lure + coercive terminal execution instruction or payload
  const hasDeceptiveLure = hasFakeCaptcha || hasImpersonation;
  const hasAttackAction = hasExecution || hasClipboard || (hasInstruction && (hasExecution || hasClipboard));
  const isClickFixAttack = (hasFakeCaptcha && hasExecution) || (hasDeceptiveLure && hasAttackAction);

  let primaryAttackVector = "Standard page analysis";
  let recommendedAction = "Passive monitoring active";

  if (isClickFixAttack) {
    primaryAttackVector = "ClickFix Attack (Fake Verification Coercing Terminal Execution)";
    recommendedAction = "Do not copy, paste, or execute instructions from this webpage. Leave immediately.";
  } else if (hasFakeCaptcha && hasImpersonation) {
    primaryAttackVector = "Brand Impersonation & Fake Verification";
    recommendedAction = "Do not interact with the simulated verification widgets on this page.";
  } else if (hasExecution) {
    primaryAttackVector = "Suspicious Command Line Instruction";
    recommendedAction = "Avoid pasting unknown terminal or PowerShell snippets into your system.";
  }

  return {
    isClickFixAttack,
    score: scanResult.score,
    level: scanResult.level,
    signals: scanResult.signals,
    primaryAttackVector,
    recommendedAction,
  };
}

