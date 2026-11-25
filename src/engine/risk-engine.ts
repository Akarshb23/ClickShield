import type { ThreatSignal, SignalType, RiskLevel, ScanResult } from "../shared/types/signal";
import { SIGNAL_WEIGHTS, RISK_THRESHOLDS } from "../shared/constants/risk-levels";

export function calculateRisk(
  signals: ThreatSignal[],
  context?: { hostname?: string; url?: string }
): ScanResult {
  if (!signals || signals.length === 0) {
    return {
      score: 0,
      level: "LOW",
      signals: [],
      hostname: context?.hostname,
      url: context?.url,
      timestamp: Date.now(),
    };
  }

  // Deduplicate signals by category to prevent artificial inflation
  const seenTypes = new Set<SignalType>();
  const uniqueSignals: ThreatSignal[] = [];

  for (const sig of signals) {
    if (!seenTypes.has(sig.type)) {
      seenTypes.add(sig.type);
      uniqueSignals.push({
        ...sig,
        weight: SIGNAL_WEIGHTS[sig.type] || 0,
      });
    }
  }

  let rawScore = 0;
  for (const type of seenTypes) {
    rawScore += SIGNAL_WEIGHTS[type] || 0;
  }

  const score = Math.min(rawScore, 100);

  let level: RiskLevel = "LOW";
  if (score >= RISK_THRESHOLDS.CRITICAL) {
    level = "CRITICAL";
  } else if (score >= RISK_THRESHOLDS.HIGH) {
    level = "HIGH";
  } else if (score >= RISK_THRESHOLDS.SUSPICIOUS) {
    level = "SUSPICIOUS";
  }

  return {
    score,
    level,
    signals: uniqueSignals,
    hostname: context?.hostname,
    url: context?.url,
    timestamp: Date.now(),
  };
}

