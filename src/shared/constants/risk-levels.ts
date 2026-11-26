
import type { SignalType } from "../types/signal";

// ==========================================================
// SIGNAL WEIGHTS
// ==========================================================

/**
 * Base contribution of each threat category to the risk score.
 *
 * The risk engine should:
 * - Count each signal category only once.
 * - Use these values as authoritative weights.
 * - Cap the final score at 100.
 */
export const SIGNAL_WEIGHTS: Record<SignalType, number> = {
  FAKE_CAPTCHA: 20,
  SUSPICIOUS_INSTRUCTION: 15,
  CLIPBOARD_MANIPULATION: 25,
  EXECUTION_INSTRUCTION: 25,
  SUSPICIOUS_DOMAIN: 10,
  DOMAIN_IMPERSONATION: 15,
};

// ==========================================================
// RISK THRESHOLDS
// ==========================================================

/**
 * Risk classification boundaries.
 *
 * LOW:        0–29
 * SUSPICIOUS: 30–59
 * HIGH:       60–79
 * CRITICAL:   80–100
 */
export const RISK_THRESHOLDS = {
  LOW: 0,
  SUSPICIOUS: 30,
  HIGH: 60,
  CRITICAL: 80,
} as const;

// ==========================================================
// BADGE COLORS
// ==========================================================

/**
 * Browser action badge colors for each risk level.
 */
export const BADGE_COLORS = {
  LOW: "#16A34A",
  SUSPICIOUS: "#D4A32C",
  HIGH: "#EA580C",
  CRITICAL: "#DC2626",
} as const;
