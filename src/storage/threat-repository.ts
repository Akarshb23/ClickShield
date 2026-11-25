import type { ThreatRecord } from "../shared/types/threat";
import { SettingsRepository } from "./settings-repository";
import { StatisticsRepository } from "./statistics-repository";
import { logger } from "../shared/utils/logger";

const HISTORY_KEY = "clickshield_history";
const MAX_STORED_RECORDS = 200;

export class ThreatRepository {
  static async getAll(): Promise<ThreatRecord[]> {
    try {
      const result = await chrome.storage.local.get(HISTORY_KEY);
      return (result[HISTORY_KEY] as ThreatRecord[]) || [];
    } catch {
      return [];
    }
  }

  /**
   * Appends a new threat record, applies 30-day retention pruning, and deduplicates.
   */
  static async addRecord(record: ThreatRecord): Promise<void> {
    try {
      const history = await this.getAll();

      // Deduplicate recent threat from same hostname within 30 seconds
      const isDuplicate = history.some(
        (h) => h.hostname === record.hostname && Math.abs(h.timestamp - record.timestamp) < 30000
      );

      if (!isDuplicate) {
        history.unshift(record);

        // Perform retention pruning based on user settings
        const settings = await SettingsRepository.getSettings();
        const retentionDays = settings.historyRetentionDays || 30;
        const cutoffTime = Date.now() - retentionDays * 24 * 60 * 60 * 1000;

        const pruned = history
          .filter((item) => item.timestamp >= cutoffTime)
          .slice(0, MAX_STORED_RECORDS);

        await chrome.storage.local.set({ [HISTORY_KEY]: pruned });
        await StatisticsRepository.increment("threatsDetected");
      }
    } catch (err) {
      logger.error("Failed to add threat record:", err);
    }
  }

  /**
   * Prunes records older than specified retention limit
   */
  static async pruneExpiredRecords(): Promise<number> {
    const history = await this.getAll();
    const settings = await SettingsRepository.getSettings();
    const cutoffTime = Date.now() - (settings.historyRetentionDays || 30) * 24 * 60 * 60 * 1000;

    const kept = history.filter((item) => item.timestamp >= cutoffTime);
    const removedCount = history.length - kept.length;

    if (removedCount > 0) {
      await chrome.storage.local.set({ [HISTORY_KEY]: kept });
      logger.info(`Pruned ${removedCount} expired threat records.`);
    }

    return removedCount;
  }

  static async clearAll(): Promise<void> {
    await chrome.storage.local.set({ [HISTORY_KEY]: [] });
    logger.info("Threat log completely cleared by user.");
  }
}

