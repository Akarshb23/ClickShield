import type { ThreatSignal, SignalType, ScanResult } from "../shared/types/signal";
import { RISK_THRESHOLDS } from "../shared/constants/risk-levels";
import model from "./model.json";

export function calculateRisk(
  signals: ThreatSignal[],
  context?: { hostname?: string; url?: string }
): ScanResult {
  const unique = new Map<SignalType, ThreatSignal>();
  for (const signal of signals ?? []) {
    if (!unique.has(signal.type)) {
      const { type, reason, snippet } = signal;
      unique.set(type, { type, reason, snippet });
    }
  }

  let logOdds = model.intercept;
  for (const term of model.terms) {
    if (term.signals.every(type => unique.has(type as SignalType))) {
      logOdds += term.coefficient;
    }
  }
  const score = unique.size ? Math.round(100 / (1 + Math.exp(-logOdds))) : 0;
  const level = score >= RISK_THRESHOLDS.CRITICAL ? "CRITICAL"
    : score >= RISK_THRESHOLDS.HIGH ? "HIGH"
    : score >= RISK_THRESHOLDS.SUSPICIOUS ? "SUSPICIOUS" : "LOW";

  return { ...context, score, level, signals: [...unique.values()], timestamp: Date.now() };
}
