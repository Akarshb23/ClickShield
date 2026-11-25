import type { SignalType } from "../types/signal";

export const SIGNAL_WEIGHTS: Record<SignalType, number> = {
  FAKE_CAPTCHA: 20,
  SUSPICIOUS_INSTRUCTION: 15,
  CLIPBOARD_MANIPULATION: 25,
  EXECUTION_INSTRUCTION: 25,
  SUSPICIOUS_DOMAIN: 10,
  DOMAIN_IMPERSONATION: 15,
};

export const RISK_THRESHOLDS = {
  LOW: 0,
  SUSPICIOUS: 30,
  HIGH: 60,
  CRITICAL: 80,
} as const;

export const BADGE_COLORS = {
  LOW: "#16A34A",       // Green
  SUSPICIOUS: "#D4A32C",// Amber/Yellow
  HIGH: "#EA580C",      // Orange
  CRITICAL: "#DC2626",  // Red
} as const;

