import type { SecurityStatistics } from "../shared/types/threat";

const STATS_KEY = "clickshield_stats";

const DEFAULT_STATS: SecurityStatistics = {
  pagesScanned: 0,
  threatsDetected: 0,
  interventions: 0,
};

export class StatisticsRepository {
  static async getStatistics(): Promise<SecurityStatistics> {
    try {
      const result = await chrome.storage.local.get(STATS_KEY);
      return (result[STATS_KEY] as SecurityStatistics) || DEFAULT_STATS;
    } catch {
      return DEFAULT_STATS;
    }
  }

  static async increment(field: keyof SecurityStatistics): Promise<SecurityStatistics> {
    const stats = await this.getStatistics();
    stats[field] = (stats[field] || 0) + 1;
    await chrome.storage.local.set({ [STATS_KEY]: stats });
    return stats;
  }

  static async reset(): Promise<void> {
    await chrome.storage.local.set({ [STATS_KEY]: DEFAULT_STATS });
  }
}

