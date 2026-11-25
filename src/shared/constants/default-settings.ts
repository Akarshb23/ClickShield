import type { ClickShieldSettings } from "../types/settings";

export const DEFAULT_SETTINGS: ClickShieldSettings = {
  protectionEnabled: true,
  clipboardProtection: true,
  notificationsEnabled: true,
  detectionSensitivity: "balanced",
  historyRetentionDays: 30,
  soundAlerts: false,
};

