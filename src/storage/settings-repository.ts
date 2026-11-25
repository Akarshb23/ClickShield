import type { ClickShieldSettings } from "../shared/types/settings";
import { DEFAULT_SETTINGS } from "../shared/constants/default-settings";
import { logger } from "../shared/utils/logger";

const SETTINGS_KEY = "clickshield_settings";

export class SettingsRepository {
  static async getSettings(): Promise<ClickShieldSettings> {
    try {
      const result = await chrome.storage.local.get(SETTINGS_KEY);
      return (result[SETTINGS_KEY] as ClickShieldSettings) || DEFAULT_SETTINGS;
    } catch {
      return DEFAULT_SETTINGS;
    }
  }

  static async updateSettings(patch: Partial<ClickShieldSettings>): Promise<ClickShieldSettings> {
    const current = await this.getSettings();
    const updated: ClickShieldSettings = { ...current, ...patch };
    await chrome.storage.local.set({ [SETTINGS_KEY]: updated });
    logger.info("Settings updated:", patch);
    return updated;
  }

  static async resetSettings(): Promise<ClickShieldSettings> {
    await chrome.storage.local.set({ [SETTINGS_KEY]: DEFAULT_SETTINGS });
    return DEFAULT_SETTINGS;
  }
}

