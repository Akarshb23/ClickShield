import type { ClickShieldSettings } from "../shared/types/settings";
import type { ThreatRecord, SecurityStatistics } from "../shared/types/threat";
import type { TabState } from "../shared/types/messages";
import { DEFAULT_SETTINGS } from "../shared/constants/default-settings";
import { logger } from "../shared/utils/logger";

const STORAGE_KEYS = {
  SCHEMA_VERSION: 1,
  SETTINGS: "clickshield_settings",
  STATS: "clickshield_stats",
  HISTORY: "clickshield_history",
  ALLOWLIST: "clickshield_allowlist",
};

const MAX_HISTORY_ITEMS = 200;

export class StorageManager {
  /**
   * Initializes default storage keys on first install or update
   */
  static async initializeDefaults(): Promise<void> {
    try {
      const data: Record<string, any> = await chrome.storage.local.get([
        STORAGE_KEYS.SETTINGS,
        STORAGE_KEYS.STATS,
        STORAGE_KEYS.HISTORY,
        STORAGE_KEYS.ALLOWLIST,
      ]);

      const updates: Record<string, unknown> = {};

      if (!data[STORAGE_KEYS.SETTINGS]) {
        updates[STORAGE_KEYS.SETTINGS] = DEFAULT_SETTINGS;
      }
      if (!data[STORAGE_KEYS.STATS]) {
        updates[STORAGE_KEYS.STATS] = {
          pagesScanned: 0,
          threatsDetected: 0,
          interventions: 0,
        };
      }
      if (!data[STORAGE_KEYS.HISTORY]) {
        updates[STORAGE_KEYS.HISTORY] = [];
      }
      if (!data[STORAGE_KEYS.ALLOWLIST]) {
        updates[STORAGE_KEYS.ALLOWLIST] = [];
      }

      if (Object.keys(updates).length > 0) {
        await chrome.storage.local.set(updates);
        logger.info("Storage defaults initialized.");
      }
    } catch (err) {
      logger.error("Failed to initialize storage defaults:", err);
    }
  }

  static async getSettings(): Promise<ClickShieldSettings> {
    try {
      const result: Record<string, any> = await chrome.storage.local.get(STORAGE_KEYS.SETTINGS);
      return (result[STORAGE_KEYS.SETTINGS] as ClickShieldSettings) || DEFAULT_SETTINGS;
    } catch {
      return DEFAULT_SETTINGS;
    }
  }

  static async updateSettings(settings: Partial<ClickShieldSettings>): Promise<ClickShieldSettings> {
    const current = await this.getSettings();
    const updated = { ...current, ...settings };
    await chrome.storage.local.set({ [STORAGE_KEYS.SETTINGS]: updated });
    return updated;
  }

  static async getStatistics(): Promise<SecurityStatistics> {
    try {
      const result: Record<string, any> = await chrome.storage.local.get(STORAGE_KEYS.STATS);
      return (
        (result[STORAGE_KEYS.STATS] as SecurityStatistics) || {
          pagesScanned: 0,
          threatsDetected: 0,
          interventions: 0,
        }
      );
    } catch {
      return { pagesScanned: 0, threatsDetected: 0, interventions: 0 };
    }
  }

  static async incrementStats(field: keyof SecurityStatistics): Promise<void> {
    const stats = await this.getStatistics();
    stats[field] = (stats[field] || 0) + 1;
    await chrome.storage.local.set({ [STORAGE_KEYS.STATS]: stats });
  }

  static async addThreatRecord(record: ThreatRecord): Promise<void> {
    try {
      const result: Record<string, any> = await chrome.storage.local.get(STORAGE_KEYS.HISTORY);
      const history: ThreatRecord[] = (result[STORAGE_KEYS.HISTORY] as ThreatRecord[]) || [];

      // Deduplicate recent threat from same hostname within 30 seconds
      const isDuplicate = history.some(
        (h) => h.hostname === record.hostname && Math.abs(h.timestamp - record.timestamp) < 30000
      );

      if (!isDuplicate) {
        history.unshift(record);
        if (history.length > MAX_HISTORY_ITEMS) {
          history.pop();
        }
        await chrome.storage.local.set({ [STORAGE_KEYS.HISTORY]: history });
        await this.incrementStats("threatsDetected");
      }
    } catch (err) {
      logger.error("Failed to add threat record:", err);
    }
  }

  static async getThreatHistory(): Promise<ThreatRecord[]> {
    try {
      const result: Record<string, any> = await chrome.storage.local.get(STORAGE_KEYS.HISTORY);
      return (result[STORAGE_KEYS.HISTORY] as ThreatRecord[]) || [];
    } catch {
      return [];
    }
  }

  static async clearThreatHistory(): Promise<void> {
    await chrome.storage.local.set({ [STORAGE_KEYS.HISTORY]: [] });
  }

  static async getAllowlist(): Promise<string[]> {
    try {
      const result: Record<string, any> = await chrome.storage.local.get(STORAGE_KEYS.ALLOWLIST);
      return (result[STORAGE_KEYS.ALLOWLIST] as string[]) || [];
    } catch {
      return [];
    }
  }

  static async isAllowlisted(hostname: string): Promise<boolean> {
    const list = await this.getAllowlist();
    const cleanHost = hostname.toLowerCase().trim();
    return list.some((item) => cleanHost === item.toLowerCase() || cleanHost.endsWith("." + item.toLowerCase()));
  }

  static async addToAllowlist(hostname: string): Promise<string[]> {
    const list = await this.getAllowlist();
    const cleanHost = hostname.toLowerCase().trim();
    if (cleanHost && !list.includes(cleanHost)) {
      list.push(cleanHost);
      await chrome.storage.local.set({ [STORAGE_KEYS.ALLOWLIST]: list });
    }
    return list;
  }

  static async removeFromAllowlist(hostname: string): Promise<string[]> {
    const list = await this.getAllowlist();
    const cleanHost = hostname.toLowerCase().trim();
    const filtered = list.filter((item) => item.toLowerCase() !== cleanHost);
    await chrome.storage.local.set({ [STORAGE_KEYS.ALLOWLIST]: filtered });
    return filtered;
  }

  // Session storage for per-tab active states
  static async setTabState(tabId: number, state: TabState): Promise<void> {
    try {
      await chrome.storage.session.set({ [`tab_${tabId}`]: state });
    } catch (e) {
      // session storage might not be available in some contexts
    }
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
