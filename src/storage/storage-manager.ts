import type { ClickShieldSettings } from "../shared/types/settings";
import type { ThreatRecord, SecurityStatistics } from "../shared/types/threat";
import type { TabState } from "../shared/types/messages";
import { SettingsRepository } from "./settings-repository";
import { StatisticsRepository } from "./statistics-repository";
import { AllowlistRepository } from "./allowlist-repository";
import { ThreatRepository } from "./threat-repository";
import { DEFAULT_SETTINGS } from "../shared/constants/default-settings";
import { logger } from "../shared/utils/logger";

export class StorageManager {
  static async initializeDefaults(): Promise<void> {
    try {
      const settings = await SettingsRepository.getSettings();
      if (!settings) {
        await SettingsRepository.resetSettings();
      }
      // Trigger retention pruning on extension startup
      await ThreatRepository.pruneExpiredRecords();
      logger.info("Storage defaults initialized and retention verified.");
    } catch (err) {
      logger.error("Failed to initialize storage defaults:", err);
    }
  }

  static getSettings = SettingsRepository.getSettings.bind(SettingsRepository);
  static updateSettings = SettingsRepository.updateSettings.bind(SettingsRepository);
  static resetSettings = SettingsRepository.resetSettings.bind(SettingsRepository);

  static getStatistics = StatisticsRepository.getStatistics.bind(StatisticsRepository);
  static incrementStats = StatisticsRepository.increment.bind(StatisticsRepository);
  static resetStatistics = StatisticsRepository.reset.bind(StatisticsRepository);

  static getAllowlist = AllowlistRepository.getAll.bind(AllowlistRepository);
  static isAllowlisted = AllowlistRepository.isAllowed.bind(AllowlistRepository);
  static addToAllowlist = AllowlistRepository.add.bind(AllowlistRepository);
  static removeFromAllowlist = AllowlistRepository.remove.bind(AllowlistRepository);

  static getThreatHistory = ThreatRepository.getAll.bind(ThreatRepository);
  static addThreatRecord = ThreatRepository.addRecord.bind(ThreatRepository);
  static clearThreatHistory = ThreatRepository.clearAll.bind(ThreatRepository);
  static pruneExpiredThreats = ThreatRepository.pruneExpiredRecords.bind(ThreatRepository);

  // Per-tab session storage handling (ephemeral, resilient to service worker suspensions)
  static async setTabState(tabId: number, state: TabState): Promise<void> {
    try {
      await chrome.storage.session.set({ [`tab_${tabId}`]: state });
    } catch {}
  }

  static async getTabState(tabId: number): Promise<TabState | null> {
    try {
      const key = `tab_${tabId}`;
      const result: Record<string, any> = await chrome.storage.session.get(key);
      return (result[key] as TabState) || null;
    } catch {
      return null;
    }
  }

  static async clearTabState(tabId: number): Promise<void> {
    try {
      await chrome.storage.session.remove(`tab_${tabId}`);
    } catch {}
  }
}
