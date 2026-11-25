export type SignalType =
  | "FAKE_CAPTCHA"
  | "SUSPICIOUS_INSTRUCTION"
  | "CLIPBOARD_MANIPULATION"
  | "EXECUTION_INSTRUCTION"
  | "SUSPICIOUS_DOMAIN"
  | "DOMAIN_IMPERSONATION";

export interface ThreatSignal {
  type: SignalType;
  reason: string;
  weight?: number;
  snippet?: string;
}

export type RiskLevel = "LOW" | "SUSPICIOUS" | "HIGH" | "CRITICAL";

export interface ScanResult {
  score: number;
  level: RiskLevel;
  signals: ThreatSignal[];
  hostname?: string;
  url?: string;
  timestamp: number;
}

