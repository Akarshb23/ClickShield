
import type {
  SecurityStatistics,
} from "../shared/types/threat";

import type { TabState } from "../shared/types/messages";

import type {
  RiskLevel,
  SignalType,
  ThreatSignal,
} from "../shared/types/signal";

import { SettingsRepository } from "./settings-repository";
import { StatisticsRepository } from "./statistics-repository";
import { AllowlistRepository } from "./allowlist-repository";
import { ThreatRepository } from "./threat-repository";

import { DEFAULT_SETTINGS } from "../shared/constants/default-settings";
import { RISK_THRESHOLDS } from "../shared/constants/risk-levels";
import { logger } from "../shared/utils/logger";

// ==========================================================
// STORAGE CONSTANTS
// ==========================================================

const SETTINGS_KEY = "clickshield_settings";
const STATISTICS_KEY = "clickshield_stats";
const ALLOWLIST_KEY = "clickshield_allowlist";
const HISTORY_KEY = "clickshield_history";

const MAX_TAB_SIGNALS = 6;
const MAX_SIGNAL_REASON_LENGTH = 500;
const MAX_SIGNAL_SNIPPET_LENGTH = 100;
const MAX_HOSTNAME_LENGTH = 253;
const MAX_URL_LENGTH = 2048;

const VALID_RISK_LEVELS = new Set<RiskLevel>([
  "LOW",
  "SUSPICIOUS",
  "HIGH",
  "CRITICAL",
]);

const VALID_SIGNAL_TYPES = new Set<SignalType>([
  "FAKE_CAPTCHA",
  "SUSPICIOUS_INSTRUCTION",
  "CLIPBOARD_MANIPULATION",
  "EXECUTION_INSTRUCTION",
  "SUSPICIOUS_DOMAIN",
  "DOMAIN_IMPERSONATION",
]);

// ==========================================================
// DEFAULT STATISTICS
// ==========================================================

const DEFAULT_STATISTICS: SecurityStatistics = {
  pagesScanned: 0,
  threatsDetected: 0,
  interventions: 0,
};

// ==========================================================
// VALIDATION HELPERS
// ==========================================================

function isRecord(
  value: unknown
): value is Record<string, unknown> {
  return (
    typeof value === "object" &&
    value !== null &&
    !Array.isArray(value)
  );
}

function isValidTabId(tabId: number): boolean {
  return (
    Number.isSafeInteger(tabId) &&
    tabId >= 0
  );
}

// ==========================================================
// RISK CLASSIFICATION
// ==========================================================

function getRiskLevel(score: number): RiskLevel {
  if (score >= RISK_THRESHOLDS.CRITICAL) {
    return "CRITICAL";
  }

  if (score >= RISK_THRESHOLDS.HIGH) {
    return "HIGH";
  }

  if (score >= RISK_THRESHOLDS.SUSPICIOUS) {
    return "SUSPICIOUS";
  }

  return "LOW";
}

// ==========================================================
// SIGNAL NORMALIZATION
// ==========================================================

/**
 * Validate and normalize a signal retrieved from
 * session storage.
 */
function normalizeSignal(
  value: unknown
): ThreatSignal | null {
  if (!isRecord(value)) {
    return null;
  }

  if (
    typeof value.type !== "string" ||
    !VALID_SIGNAL_TYPES.has(value.type as SignalType)
  ) {
    return null;
  }

  if (
    typeof value.reason !== "string" ||
    !value.reason.trim()
  ) {
    return null;
  }

  const reason = value.reason
    .trim()
    .slice(0, MAX_SIGNAL_REASON_LENGTH);

  const normalized: ThreatSignal = {
    type: value.type as SignalType,
    reason,
  };

  if (typeof value.snippet === "string") {
    const snippet = value.snippet
      .slice(0, MAX_SIGNAL_SNIPPET_LENGTH);

    if (snippet) {
      normalized.snippet = snippet;
    }
  }

  if (
    typeof value.weight === "number" &&
    Number.isFinite(value.weight) &&
    value.weight >= 0 &&
    value.weight <= 100
  ) {
    normalized.weight = value.weight;
  }

  return normalized;
}

// ==========================================================
// SIGNAL COLLECTION NORMALIZATION
// ==========================================================

/**
 * Deduplicate stored signals by category.
 *
 * The risk engine counts each category only once, so
 * persisted tab state follows the same rule.
 */
function normalizeSignals(
  value: unknown
): ThreatSignal[] {
  if (!Array.isArray(value)) {
    return [];
  }

  const uniqueSignals = new Map<
    SignalType,
    ThreatSignal
  >();

  for (const item of value) {
    if (uniqueSignals.size >= MAX_TAB_SIGNALS) {
      break;
    }

    const signal = normalizeSignal(item);

    if (!signal) {
      continue;
    }

    if (uniqueSignals.has(signal.type)) {
      continue;
    }

    uniqueSignals.set(signal.type, signal);
  }

  return Array.from(uniqueSignals.values());
}

// ==========================================================
// TAB STATE NORMALIZATION
// ==========================================================

/**
 * Validate the complete tab state before returning it
 * to the background service worker or popup.
 */
function normalizeTabState(
  value: unknown
): TabState | null {
  if (!isRecord(value)) {
    return null;
  }

  if (
    typeof value.score !== "number" ||
    !Number.isFinite(value.score) ||
    value.score < 0 ||
    value.score > 100
  ) {
    return null;
  }

  if (
    typeof value.level !== "string" ||
    !VALID_RISK_LEVELS.has(value.level as RiskLevel)
  ) {
    return null;
  }

  if (
    typeof value.hostname !== "string" ||
    !value.hostname.trim() ||
    value.hostname.length > MAX_HOSTNAME_LENGTH
  ) {
    return null;
  }

  if (
    typeof value.url !== "string" ||
    value.url.length > MAX_URL_LENGTH
  ) {
    return null;
  }

  if (
    typeof value.timestamp !== "number" ||
    !Number.isFinite(value.timestamp) ||
    value.timestamp < 0
  ) {
    return null;
  }

  if (
    typeof value.protectionEnabled !== "boolean" ||
    typeof value.isAllowlisted !== "boolean"
  ) {
    return null;
  }

  if (!Array.isArray(value.signals)) {
    return null;
  }

  const signals = normalizeSignals(value.signals);

  // Derive the level from the authoritative score instead
  // of trusting a potentially inconsistent stored level.
  const level = getRiskLevel(value.score);

  return {
    score: value.score,
    level,
    signals,
    hostname: value.hostname.trim(),
    url: value.url.trim(),
    timestamp: value.timestamp,
    protectionEnabled: value.protectionEnabled,
    isAllowlisted: value.isAllowlisted,
  };
}

// ==========================================================
// STORAGE MANAGER
// ==========================================================

export class StorageManager {

  // ========================================================
  // INITIALIZE DEFAULTS
  // ========================================================

  /**
   * Initialize missing storage keys without overwriting
   * existing user configuration.
   *
   * Also performs threat-history retention pruning.
   */
  static async initializeDefaults(): Promise<void> {
    try {
      const keys = [
        SETTINGS_KEY,
        STATISTICS_KEY,
        ALLOWLIST_KEY,
        HISTORY_KEY,
      ];

      const stored = await chrome.storage.local.get(keys);

      const defaults: Record<string, unknown> = {};

      // Initialize settings only when missing.
      if (
        !Object.prototype.hasOwnProperty.call(
          stored,
          SETTINGS_KEY
        )
      ) {
        defaults[SETTINGS_KEY] = {
          ...DEFAULT_SETTINGS,
        };
      }

      // Initialize statistics only when missing.
      if (
        !Object.prototype.hasOwnProperty.call(
          stored,
          STATISTICS_KEY
        )
      ) {
        defaults[STATISTICS_KEY] = {
          ...DEFAULT_STATISTICS,
        };
      }

      // Initialize allowlist only when missing.
      if (
        !Object.prototype.hasOwnProperty.call(
          stored,
          ALLOWLIST_KEY
        )
      ) {
        defaults[ALLOWLIST_KEY] = [];
      }

      // Initialize threat history only when missing.
      if (
        !Object.prototype.hasOwnProperty.call(
          stored,
          HISTORY_KEY
        )
      ) {
        defaults[HISTORY_KEY] = [];
      }

      // Perform a single initialization write.
      if (Object.keys(defaults).length > 0) {
        await chrome.storage.local.set(defaults);
      }

      // Prune expired history.
      await ThreatRepository.pruneExpiredRecords();

      logger.info(
        "ClickShield storage initialized successfully."
      );
    } catch (error) {
      logger.error(
        "Failed to initialize ClickShield storage:",
        error
      );

      throw error;
    }
  }

  // ========================================================
  // SETTINGS
  // ========================================================

  static getSettings =
    SettingsRepository.getSettings.bind(
      SettingsRepository
    );

  static updateSettings =
    SettingsRepository.updateSettings.bind(
      SettingsRepository
    );

  static resetSettings =
    SettingsRepository.resetSettings.bind(
      SettingsRepository
    );

  // ========================================================
  // STATISTICS
  // ========================================================

  static getStatistics =
    StatisticsRepository.getStatistics.bind(
      StatisticsRepository
    );

  static incrementStats =
    StatisticsRepository.increment.bind(
      StatisticsRepository
    );

  static resetStatistics =
    StatisticsRepository.reset.bind(
      StatisticsRepository
    );

  // ========================================================
  // ALLOWLIST
  // ========================================================

  static getAllowlist =
    AllowlistRepository.getAll.bind(
      AllowlistRepository
    );

  static isAllowlisted =
    AllowlistRepository.isAllowed.bind(
      AllowlistRepository
    );

  static addToAllowlist =
    AllowlistRepository.add.bind(
      AllowlistRepository
    );

  static removeFromAllowlist =
    AllowlistRepository.remove.bind(
      AllowlistRepository
    );

  // ========================================================
  // THREAT HISTORY
  // ========================================================

  static getThreatHistory =
    ThreatRepository.getAll.bind(
      ThreatRepository
    );

  static addThreatRecord =
    ThreatRepository.addRecord.bind(
      ThreatRepository
    );

  static clearThreatHistory =
    ThreatRepository.clearAll.bind(
      ThreatRepository
    );

  static pruneExpiredThreats =
    ThreatRepository.pruneExpiredRecords.bind(
      ThreatRepository
    );

  // ========================================================
  // TAB SESSION STORAGE
  // ========================================================

  /**
   * Store temporary state for an individual browser tab.
   *
   * Uses chrome.storage.session so that tab state survives
   * service-worker suspension without becoming permanent.
   */
  static async setTabState(
    tabId: number,
    state: TabState
  ): Promise<void> {
    if (!isValidTabId(tabId)) {
      throw new TypeError(
        "Invalid browser tab ID."
      );
    }

    const normalizedState = normalizeTabState(state);

    if (!normalizedState) {
      throw new TypeError(
        "Invalid ClickShield tab state."
      );
    }

    try {
      await chrome.storage.session.set({
        [`tab_${tabId}`]: normalizedState,
      });
    } catch (error) {
      logger.error(
        `Failed to save ClickShield state for tab ${tabId}:`,
        error
      );

      throw error;
    }
  }

  // ========================================================
  // GET TAB STATE
  // ========================================================

  static async getTabState(
    tabId: number
  ): Promise<TabState | null> {
    if (!isValidTabId(tabId)) {
      return null;
    }

    try {
      const key = `tab_${tabId}`;

      const result = await chrome.storage.session.get(key);

      const state = normalizeTabState(result[key]);

      if (
        !state &&
        result[key] !== undefined
      ) {
        logger.warn(
          `Invalid ClickShield tab state found for tab ${tabId}.`
        );

        // Remove corrupted session data.
        await chrome.storage.session.remove(key);
      }

      return state;
    } catch (error) {
      logger.error(
        `Failed to retrieve ClickShield state for tab ${tabId}:`,
        error
      );

      return null;
    }
  }

  // ========================================================
  // CLEAR TAB STATE
  // ========================================================

  static async clearTabState(
    tabId: number
  ): Promise<void> {
    if (!isValidTabId(tabId)) {
      return;
    }

    try {
      await chrome.storage.session.remove(
        `tab_${tabId}`
      );
    } catch (error) {
      logger.warn(
        `Failed to clear ClickShield state for tab ${tabId}:`,
        error
      );
    }
  }
}
