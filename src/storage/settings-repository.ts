
import type { ClickShieldSettings } from "../shared/types/settings";

import { DEFAULT_SETTINGS } from "../shared/constants/default-settings";
import { logger } from "../shared/utils/logger";

// ==========================================================
// CONSTANTS
// ==========================================================

const SETTINGS_KEY = "clickshield_settings";

const VALID_SENSITIVITY_LEVELS = [
  "low",
  "balanced",
  "aggressive",
] as const;

const MIN_HISTORY_RETENTION_DAYS = 1;
const MAX_HISTORY_RETENTION_DAYS = 3650;

// ==========================================================
// TYPES
// ==========================================================

type SettingsPatch = Partial<ClickShieldSettings>;

type SettingsRecord = Record<string, unknown>;

type SensitivityLevel =
  (typeof VALID_SENSITIVITY_LEVELS)[number];

// ==========================================================
// HELPERS
// ==========================================================

function isRecord(
  value: unknown
): value is SettingsRecord {
  return (
    typeof value === "object" &&
    value !== null &&
    !Array.isArray(value)
  );
}

function isSensitivityLevel(
  value: unknown
): value is SensitivityLevel {
  return (
    typeof value === "string" &&
    VALID_SENSITIVITY_LEVELS.includes(
      value as SensitivityLevel
    )
  );
}

/**
 * Return a fresh copy of default settings.
 *
 * Prevents callers from accidentally mutating shared defaults.
 */
function getDefaultSettings(): ClickShieldSettings {
  return { ...DEFAULT_SETTINGS };
}

/**
 * Return safe fallback settings if storage cannot be accessed.
 *
 * Protection is disabled rather than assuming that the
 * user's protection configuration was successfully retrieved.
 */
function getFailClosedSettings(): ClickShieldSettings {
  return {
    ...DEFAULT_SETTINGS,
    protectionEnabled: false,
    clipboardProtection: false,
    notificationsEnabled: false,
    soundAlerts: false,
  };
}

// ==========================================================
// SETTINGS NORMALIZATION
// ==========================================================

/**
 * Validate and normalize settings retrieved from Chrome Storage.
 *
 * Invalid or missing individual properties fall back to
 * their corresponding default values.
 */
function normalizeSettings(
  value: unknown
): ClickShieldSettings {
  if (!isRecord(value)) {
    return getDefaultSettings();
  }

  const settings: ClickShieldSettings = {
    protectionEnabled:
      typeof value.protectionEnabled === "boolean"
        ? value.protectionEnabled
        : DEFAULT_SETTINGS.protectionEnabled,

    clipboardProtection:
      typeof value.clipboardProtection === "boolean"
        ? value.clipboardProtection
        : DEFAULT_SETTINGS.clipboardProtection,

    notificationsEnabled:
      typeof value.notificationsEnabled === "boolean"
        ? value.notificationsEnabled
        : DEFAULT_SETTINGS.notificationsEnabled,

    detectionSensitivity:
      isSensitivityLevel(value.detectionSensitivity)
        ? value.detectionSensitivity
        : DEFAULT_SETTINGS.detectionSensitivity,

    historyRetentionDays:
      typeof value.historyRetentionDays === "number" &&
      Number.isSafeInteger(value.historyRetentionDays) &&
      value.historyRetentionDays >= MIN_HISTORY_RETENTION_DAYS &&
      value.historyRetentionDays <= MAX_HISTORY_RETENTION_DAYS
        ? value.historyRetentionDays
        : DEFAULT_SETTINGS.historyRetentionDays,

    soundAlerts:
      typeof value.soundAlerts === "boolean"
        ? value.soundAlerts
        : DEFAULT_SETTINGS.soundAlerts,
  };

  return settings;
}

// ==========================================================
// PATCH VALIDATION
// ==========================================================

/**
 * Validate incoming partial settings updates.
 *
 * Unknown keys, symbol properties and invalid values are
 * rejected instead of silently being written into storage.
 */
function validateSettingsPatch(
  patch: unknown
): SettingsPatch {
  if (!isRecord(patch)) {
    throw new TypeError(
      "Settings update must be a valid object."
    );
  }

  const allowedKeys = new Set<string>([
    "protectionEnabled",
    "clipboardProtection",
    "notificationsEnabled",
    "detectionSensitivity",
    "historyRetentionDays",
    "soundAlerts",
  ]);

  const validated: SettingsPatch = {};

  // Inspect all own keys, including non-enumerable and symbol keys.
  for (const key of Reflect.ownKeys(patch)) {
    if (typeof key !== "string" || !allowedKeys.has(key)) {
      throw new TypeError(
        `Unknown settings property: ${String(key)}`
      );
    }

    const value = patch[key];

    switch (key) {
      // ----------------------------------------------------
      // Boolean settings
      // ----------------------------------------------------

      case "protectionEnabled": {
        if (typeof value !== "boolean") {
          throw new TypeError(
            "protectionEnabled must be a boolean."
          );
        }

        validated.protectionEnabled = value;
        break;
      }

      case "clipboardProtection": {
        if (typeof value !== "boolean") {
          throw new TypeError(
            "clipboardProtection must be a boolean."
          );
        }

        validated.clipboardProtection = value;
        break;
      }

      case "notificationsEnabled": {
        if (typeof value !== "boolean") {
          throw new TypeError(
            "notificationsEnabled must be a boolean."
          );
        }

        validated.notificationsEnabled = value;
        break;
      }

      case "soundAlerts": {
        if (typeof value !== "boolean") {
          throw new TypeError(
            "soundAlerts must be a boolean."
          );
        }

        validated.soundAlerts = value;
        break;
      }

      // ----------------------------------------------------
      // Detection sensitivity
      // ----------------------------------------------------

      case "detectionSensitivity": {
        if (!isSensitivityLevel(value)) {
          throw new TypeError(
            "Detection sensitivity must be low, balanced or aggressive."
          );
        }

        validated.detectionSensitivity = value;
        break;
      }

      // ----------------------------------------------------
      // History retention
      // ----------------------------------------------------

      case "historyRetentionDays": {
        if (
          typeof value !== "number" ||
          !Number.isSafeInteger(value) ||
          value < MIN_HISTORY_RETENTION_DAYS ||
          value > MAX_HISTORY_RETENTION_DAYS
        ) {
          throw new RangeError(
            `History retention must be an integer between ${MIN_HISTORY_RETENTION_DAYS} and ${MAX_HISTORY_RETENTION_DAYS} days.`
          );
        }

        validated.historyRetentionDays = value;
        break;
      }
    }
  }

  return validated;
}

// ==========================================================
// STRICT STORAGE RETRIEVAL
// ==========================================================

/**
 * Retrieve settings without swallowing storage errors.
 *
 * Used by mutations so a failed read cannot silently
 * replace existing preferences with defaults.
 */
async function readStoredSettings(): Promise<ClickShieldSettings> {
  const result = await chrome.storage.local.get(
    SETTINGS_KEY
  );

  return normalizeSettings(result[SETTINGS_KEY]);
}

// ==========================================================
// REPOSITORY
// ==========================================================

export class SettingsRepository {
  /**
   * Serializes writes within the service-worker context.
   *
   * This prevents simultaneous updateSettings() and
   * resetSettings() operations from overwriting each other.
   */
  private static writeQueue: Promise<void> =
    Promise.resolve();

  /**
   * Add a storage mutation to the write queue.
   *
   * A failed operation does not prevent subsequent writes.
   */
  private static enqueueWrite<T>(
    operation: () => Promise<T>
  ): Promise<T> {
    const task = this.writeQueue.then(operation);

    this.writeQueue = task.then(
      () => undefined,
      () => undefined
    );

    return task;
  }

  // ========================================================
  // GET SETTINGS
  // ========================================================

  static async getSettings(): Promise<ClickShieldSettings> {
    try {
      return await readStoredSettings();
    } catch (error) {
      logger.error(
        "Unable to retrieve ClickShield settings. Using fail-closed defaults:",
        error
      );

      return getFailClosedSettings();
    }
  }

  // ========================================================
  // UPDATE SETTINGS
  // ========================================================

  static async updateSettings(
    patch: SettingsPatch
  ): Promise<ClickShieldSettings> {
    // Validate before entering the write queue.
    const validatedPatch =
      validateSettingsPatch(patch);

    return this.enqueueWrite(async () => {
      try {
        // Always retrieve the latest settings inside
        // the serialized operation.
        //
        // Unlike getSettings(), this does not swallow
        // storage retrieval errors.
        const current = await readStoredSettings();

        // Empty updates should not cause unnecessary writes.
        if (Object.keys(validatedPatch).length === 0) {
          return { ...current };
        }

        const updated: ClickShieldSettings = {
          ...current,
          ...validatedPatch,
        };

        // Persist the complete normalized settings object.
        await chrome.storage.local.set({
          [SETTINGS_KEY]: updated,
        });

        logger.info(
          "ClickShield settings updated:",
          Object.keys(validatedPatch)
        );

        return { ...updated };
      } catch (error) {
        logger.error(
          "Failed to update ClickShield settings:",
          error
        );

        throw error;
      }
    });
  }

  // ========================================================
  // RESET SETTINGS
  // ========================================================

  static async resetSettings(): Promise<ClickShieldSettings> {
    return this.enqueueWrite(async () => {
      try {
        const defaults = getDefaultSettings();

        await chrome.storage.local.set({
          [SETTINGS_KEY]: defaults,
        });

        logger.info(
          "ClickShield settings restored to defaults."
        );

        return { ...defaults };
      } catch (error) {
        logger.error(
          "Failed to reset ClickShield settings:",
          error
        );

        throw error;
      }
    });
  }
}
