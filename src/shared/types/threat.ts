import type { RiskLevel, SignalType } from "./signal";

export interface ThreatRecord {
  id: string;
  hostname: string;
  url: string;
  timestamp: number;
  riskScore: number;
  riskLevel: RiskLevel;
  signals: SignalType[];
  details?: string[];
  action: "NONE" | "CAUTION_SHOWN" | "WARNING_DISPLAYED" | "COPY_INTERCEPTED";
}

export interface SecurityStatistics {
  pagesScanned: number;
  threatsDetected: number;
  interventions: number;
}

