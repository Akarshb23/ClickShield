export interface ClickShieldSettings {
  protectionEnabled: boolean;
  clipboardProtection: boolean;
  notificationsEnabled: boolean;
  detectionSensitivity: "low" | "balanced" | "aggressive";
  historyRetentionDays: number;
  soundAlerts: boolean;
}

export interface StorageSchema {
  schemaVersion: number;
  settings: ClickShieldSettings;
  statistics: {
    pagesScanned: number;
    threatsDetected: number;
    interventions: number;
  };
  threatHistory: import("./threat").ThreatRecord[];
  allowlist: string[];
}

