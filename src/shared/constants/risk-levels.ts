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
