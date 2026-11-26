
import type {
  ThreatSignal,
  SignalType,
  RiskLevel,
  ScanResult,
} from "../shared/types/signal";

import {
  SIGNAL_WEIGHTS,
  RISK_THRESHOLDS,
} from "../shared/constants/risk-levels";

// ==========================================================
// CONSTANTS
// ==========================================================

const MAX_REASON_LENGTH = 500;
const MAX_SNIPPET_LENGTH = 100;

// ==========================================================
// VALIDATION
// ==========================================================

function isRecord(
  value: unknown
): value is Record<string, unknown> {
  return (
    typeof value === "object" &&
    value !== null &&
    !Array.isArray(value)
  );
}

function isValidSignalType(
  value: unknown
): value is SignalType {
  return (
    typeof value === "string" &&
    Object.prototype.hasOwnProperty.call(
      SIGNAL_WEIGHTS,
      value
    )
  );
}

/**
 * Normalize incoming signals.
 *
 * The engine never trusts weights supplied by detectors,
 * content scripts or external message payloads.
 *
 * Every accepted signal receives its authoritative weight
 * from the central SIGNAL_WEIGHTS configuration.
 */
function normalizeSignal(
  value: unknown
): ThreatSignal | null {
  if (!isRecord(value)) {
    return null;
  }

  const type = value.type;

  if (!isValidSignalType(type)) {
    return null;
  }

  if (typeof value.reason !== "string") {
    return null;
  }

  const reason = value.reason
    .slice(0, MAX_REASON_LENGTH)
    .trim();

  if (!reason) {
    return null;
  }

  const weight = SIGNAL_WEIGHTS[type];

  if (
    typeof weight !== "number" ||
    !Number.isFinite(weight) ||
    weight < 0 ||
    weight > 100
  ) {
    return null;
  }

  const normalized: ThreatSignal = {
    type,
    reason,
    weight,
  };

  if (typeof value.snippet === "string") {
    const snippet = value.snippet
      .slice(0, MAX_SNIPPET_LENGTH);

    if (snippet) {
      normalized.snippet = snippet;
    }
  }

  return normalized;
}

// ==========================================================
// RISK CLASSIFICATION
// ==========================================================

function classifyRisk(score: number): RiskLevel {
  if (score >= RISK_THRESHOLDS.CRITICAL) {
    return "CRITICAL";
  }

  if (score >= RISK_THRESHOLDS.HIGH) {
    return "HIGH";
  }

  if (score >= RISK_THRESHOLDS.SUSPICIOUS) {
    return "SUSPICIOUS";
  }

  return "LOW";
}

// ==========================================================
// SIGNAL DEDUPLICATION
// ==========================================================

/**
 * Deduplicate by signal category.
 *
 * Multiple detections of the same category contribute
 * only once to the overall risk score.
 *
 * The first valid occurrence is retained to preserve
 * deterministic detection ordering.
 */
function deduplicateSignals(
  signals: readonly unknown[]
): ThreatSignal[] {
  const uniqueSignals = new Map<
    SignalType,
    ThreatSignal
  >();

  for (const incoming of signals) {
    const normalized = normalizeSignal(incoming);

    if (!normalized) {
      continue;
    }

    if (uniqueSignals.has(normalized.type)) {
      continue;
    }

    uniqueSignals.set(
      normalized.type,
      normalized
    );
  }

  return Array.from(uniqueSignals.values());
}

// ==========================================================
// SCORE CALCULATION
// ==========================================================

function calculateScore(
  signals: readonly ThreatSignal[]
): number {
  const rawScore = signals.reduce(
    (total, signal) =>
      total + (signal.weight ?? 0),
    0
  );

  return Math.min(
    100,
    Math.max(0, rawScore)
  );
}

// ==========================================================
// CONTEXT NORMALIZATION
// ==========================================================

function normalizeContext(
  context?: {
    hostname?: string;
    url?: string;
  }
): {
  hostname?: string;
  url?: string;
} {
  return {
    ...(typeof context?.hostname === "string"
      ? { hostname: context.hostname.slice(0, 253) }
      : {}),

    ...(typeof context?.url === "string"
      ? { url: context.url.slice(0, 2048) }
      : {}),
  };
}

// ==========================================================
// EMPTY RESULT
// ==========================================================

function createEmptyResult(
  context?: {
    hostname?: string;
    url?: string;
  }
): ScanResult {
  const normalizedContext = normalizeContext(context);

  return {
    score: 0,
    level: "LOW",
    signals: [],
    ...normalizedContext,
    timestamp: Date.now(),
  };
}

// ==========================================================
// MAIN RISK ENGINE
// ==========================================================

export function calculateRisk(
  signals: readonly ThreatSignal[] | null | undefined,
  context?: {
    hostname?: string;
    url?: string;
  }
): ScanResult {

  // --------------------------------------------------------
  // 1. Handle empty or invalid input
  // --------------------------------------------------------

  if (
    !Array.isArray(signals) ||
    signals.length === 0
  ) {
    return createEmptyResult(context);
  }

  // --------------------------------------------------------
  // 2. Validate and deduplicate signals
  // --------------------------------------------------------

  const uniqueSignals = deduplicateSignals(signals);

  if (uniqueSignals.length === 0) {
    return createEmptyResult(context);
  }

  // --------------------------------------------------------
  // 3. Calculate authoritative risk score
  // --------------------------------------------------------

  const score = calculateScore(uniqueSignals);

  // --------------------------------------------------------
  // 4. Classify risk
  // --------------------------------------------------------

  const level = classifyRisk(score);

  // --------------------------------------------------------
  // 5. Return normalized result
  // --------------------------------------------------------

  const normalizedContext = normalizeContext(context);

  return {
    score,
    level,
    signals: uniqueSignals,
    ...normalizedContext,
    timestamp: Date.now(),
  };
}
