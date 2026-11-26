
import type { ThreatRecord } from "../shared/types/threat";

import type {
  SignalType,
  RiskLevel,
} from "../shared/types/signal";

import { SettingsRepository } from "./settings-repository";
import { StatisticsRepository } from "./statistics-repository";

import { RISK_THRESHOLDS } from "../shared/constants/risk-levels";
import { logger } from "../shared/utils/logger";

// ==========================================================
// CONSTANTS
// ==========================================================

const HISTORY_KEY = "clickshield_history";

const MAX_STORED_RECORDS = 200;

const MAX_SIGNAL_TYPES = 6;
const MAX_DETAILS = 20;
const MAX_DETAIL_LENGTH = 500;

const MAX_ID_LENGTH = 128;
const MAX_HOSTNAME_LENGTH = 253;
const MAX_URL_LENGTH = 2048;

const DUPLICATE_WINDOW_MS = 30 * 1000;

const DEFAULT_RETENTION_DAYS = 30;

const VALID_SIGNAL_TYPES = new Set<SignalType>([
  "FAKE_CAPTCHA",
  "SUSPICIOUS_INSTRUCTION",
  "CLIPBOARD_MANIPULATION",
  "EXECUTION_INSTRUCTION",
  "SUSPICIOUS_DOMAIN",
  "DOMAIN_IMPERSONATION",
]);

const VALID_RISK_LEVELS = new Set<RiskLevel>([
  "LOW",
  "SUSPICIOUS",
  "HIGH",
  "CRITICAL",
]);

const VALID_ACTIONS = new Set<ThreatRecord["action"]>([
  "NONE",
  "CAUTION_SHOWN",
  "WARNING_DISPLAYED",
  "COPY_INTERCEPTED",
]);

// ==========================================================
// VALIDATION
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

/**
 * Derive the expected risk level from a risk score.
 */
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

/**
 * Validate and normalize a stored threat record.
 *
 * Storage data is not trusted blindly, even when it
 * originally came from ClickShield.
 */
function normalizeThreatRecord(
  value: unknown
): ThreatRecord | null {
  if (!isRecord(value)) {
    return null;
  }

  const {
    id,
    hostname,
    url,
    timestamp,
    riskScore,
    riskLevel,
    signals,
    details,
    action,
  } = value;

  // --------------------------------------------------------
  // 1. Record identifier
  // --------------------------------------------------------

  if (
    typeof id !== "string" ||
    !id.trim() ||
    id.length > MAX_ID_LENGTH
  ) {
    return null;
  }

  // --------------------------------------------------------
  // 2. Hostname
  // --------------------------------------------------------

  if (
    typeof hostname !== "string" ||
    !hostname.trim() ||
    hostname.length > MAX_HOSTNAME_LENGTH
  ) {
    return null;
  }

  // --------------------------------------------------------
  // 3. URL
  // --------------------------------------------------------

  if (
    typeof url !== "string" ||
    url.length > MAX_URL_LENGTH
  ) {
    return null;
  }

  // --------------------------------------------------------
  // 4. Timestamp
  // --------------------------------------------------------

  if (
    typeof timestamp !== "number" ||
    !Number.isFinite(timestamp) ||
    timestamp < 0
  ) {
    return null;
  }

  // --------------------------------------------------------
  // 5. Risk score
  // --------------------------------------------------------

  if (
    typeof riskScore !== "number" ||
    !Number.isFinite(riskScore) ||
    riskScore < 0 ||
    riskScore > 100
  ) {
    return null;
  }

  // --------------------------------------------------------
  // 6. Risk level
  // --------------------------------------------------------

  if (
    typeof riskLevel !== "string" ||
    !VALID_RISK_LEVELS.has(riskLevel as RiskLevel)
  ) {
    return null;
  }

  // Reject inconsistent score and risk-level combinations.
  if (getRiskLevel(riskScore) !== riskLevel) {
    return null;
  }

  // --------------------------------------------------------
  // 7. Signal categories
  // --------------------------------------------------------

  if (
    !Array.isArray(signals) ||
    signals.length === 0 ||
    signals.length > MAX_SIGNAL_TYPES ||
    !signals.every(
      (signal) =>
        typeof signal === "string" &&
        VALID_SIGNAL_TYPES.has(signal as SignalType)
    )
  ) {
    return null;
  }

  const normalizedSignals = [
    ...new Set(signals as SignalType[]),
  ];

  // --------------------------------------------------------
  // 8. Details
  // --------------------------------------------------------

  if (
    !Array.isArray(details) &&
    details !== undefined
  ) {
    return null;
  }

  if (
    Array.isArray(details) &&
    !details.every(
      (detail) => typeof detail === "string"
    )
  ) {
    return null;
  }

  // --------------------------------------------------------
  // 9. Action
  // --------------------------------------------------------

  if (
    typeof action !== "string" ||
    !VALID_ACTIONS.has(action as ThreatRecord["action"])
  ) {
    return null;
  }

  // --------------------------------------------------------
  // 10. Return normalized record
  // --------------------------------------------------------

  return {
    id: id.trim(),

    hostname: hostname
      .trim()
      .toLowerCase()
      .replace(/\.$/, ""),

    url: url.trim(),

    timestamp,

    riskScore,

    riskLevel: riskLevel as RiskLevel,

    signals: normalizedSignals,

    ...(Array.isArray(details)
      ? {
          details: (details as string[])
            .slice(0, MAX_DETAILS)
            .map((detail) =>
              detail.slice(0, MAX_DETAIL_LENGTH)
            ),
        }
      : {}),

    action: action as ThreatRecord["action"],
  };
}

// ==========================================================
// RETENTION
// ==========================================================

async function getRetentionCutoff(): Promise<number> {
  const settings = await SettingsRepository.getSettings();

  const retentionDays =
    Number.isSafeInteger(settings.historyRetentionDays) &&
    settings.historyRetentionDays >= 1 &&
    settings.historyRetentionDays <= 3650
      ? settings.historyRetentionDays
      : DEFAULT_RETENTION_DAYS;

  return (
    Date.now() -
    retentionDays * 24 * 60 * 60 * 1000
  );
}

function applyRetention(
  history: ThreatRecord[],
  cutoffTime: number
): ThreatRecord[] {
  return history
    .filter((record) => record.timestamp >= cutoffTime)
    .sort((a, b) => b.timestamp - a.timestamp)
    .slice(0, MAX_STORED_RECORDS);
}

// ==========================================================
// DEDUPLICATION
// ==========================================================

/**
 * Create a fingerprint for an individual threat.
 *
 * Records on different URLs, with different evidence or
 * different intervention actions remain distinct.
 */
function createThreatFingerprint(
  record: ThreatRecord
): string {
  const normalizedSignals = [
    ...new Set(record.signals),
  ].sort();

  const normalizedDetails = [
    ...(record.details || []),
  ].map((detail) => detail.trim().toLowerCase()).sort();

  return JSON.stringify({
    hostname: record.hostname.toLowerCase(),

    url: record.url,

    riskLevel: record.riskLevel,

    signals: normalizedSignals,

    details: normalizedDetails,

    action: record.action,
  });
}

function isDuplicateThreat(
  history: ThreatRecord[],
  record: ThreatRecord
): boolean {
  const fingerprint = createThreatFingerprint(record);

  return history.some((existing) => {
    if (
      createThreatFingerprint(existing) !== fingerprint
    ) {
      return false;
    }

    return (
      Math.abs(
        existing.timestamp - record.timestamp
      ) < DUPLICATE_WINDOW_MS
    );
  });
}

// ==========================================================
// REPOSITORY
// ==========================================================

export class ThreatRepository {
  /**
   * Serialize all history modifications.
   *
   * Prevents simultaneous add, prune and clear operations
   * from accidentally overwriting one another.
   */
  private static mutationQueue: Promise<void> =
    Promise.resolve();

  private static enqueueMutation<T>(
    operation: () => Promise<T>
  ): Promise<T> {
    const task = this.mutationQueue.then(operation);

    this.mutationQueue = task.then(
      () => undefined,
      () => undefined
    );

    return task;
  }

  // ========================================================
  // INTERNAL STORAGE ACCESS
  // ========================================================

  private static async readHistory(): Promise<ThreatRecord[]> {
    const result = await chrome.storage.local.get(
      HISTORY_KEY
    );

    const stored = result[HISTORY_KEY];

    if (!Array.isArray(stored)) {
      return [];
    }

    return stored
      .map(normalizeThreatRecord)
      .filter(
        (record): record is ThreatRecord =>
          record !== null
      )
      .sort((a, b) => b.timestamp - a.timestamp);
  }

  private static async saveHistory(
    history: ThreatRecord[]
  ): Promise<void> {
    await chrome.storage.local.set({
      [HISTORY_KEY]: history,
    });
  }

  // ========================================================
  // GET ALL
  // ========================================================

  static async getAll(): Promise<ThreatRecord[]> {
    try {
      const history = await this.readHistory();

      return history.slice(0, MAX_STORED_RECORDS);
    } catch (error) {
      logger.error(
        "Failed to retrieve ClickShield threat history:",
        error
      );

      return [];
    }
  }

  // ========================================================
  // ADD RECORD
  // ========================================================

  static async addRecord(
    input: ThreatRecord
  ): Promise<void> {
    return this.enqueueMutation(async () => {
      // ----------------------------------------------------
      // 1. Validate incoming record
      // ----------------------------------------------------

      const record = normalizeThreatRecord(input);

      if (!record) {
        logger.warn(
          "Rejected invalid ClickShield threat record."
        );

        throw new TypeError(
          "Invalid ClickShield threat record."
        );
      }

      try {
        // --------------------------------------------------
        // 2. Retrieve existing records
        // --------------------------------------------------

        const history = await this.readHistory();

        const cutoffTime = await getRetentionCutoff();

        // --------------------------------------------------
        // 3. Remove expired records
        // --------------------------------------------------

        const activeHistory = applyRetention(
          history,
          cutoffTime
        );

        const historyNeedsPruning =
          activeHistory.length !== history.length;

        // --------------------------------------------------
        // 4. Check duplicates
        // --------------------------------------------------

        if (
          isDuplicateThreat(activeHistory, record)
        ) {
          logger.debug(
            "Duplicate ClickShield threat record ignored:",
            record.hostname
          );

          // Persist retention pruning even when the new
          // record is a duplicate.
          if (historyNeedsPruning) {
            await this.saveHistory(activeHistory);
          }

          return;
        }

        // --------------------------------------------------
        // 5. Insert newest record first
        // --------------------------------------------------

        const updatedHistory = applyRetention(
          [record, ...activeHistory],
          cutoffTime
        );

        await this.saveHistory(updatedHistory);

        // --------------------------------------------------
        // 6. Increment statistics
        // --------------------------------------------------

        try {
          await StatisticsRepository.increment(
            "threatsDetected"
          );
        } catch (statisticsError) {
          logger.error(
            "Threat history was saved, but statistics update failed. Attempting rollback:",
            statisticsError
          );

          // Roll back the new history entry so a future
          // retry has an opportunity to update statistics.
          try {
            await this.saveHistory(activeHistory);
          } catch (rollbackError) {
            logger.error(
              "Unable to roll back threat history after statistics failure:",
              rollbackError
            );
          }

          throw statisticsError;
        }

        // --------------------------------------------------
        // 7. Log successful storage
        // --------------------------------------------------

        logger.info(
          "Threat record stored:",
          {
            hostname: record.hostname,
            riskLevel: record.riskLevel,
            riskScore: record.riskScore,
            signals: record.signals,
          }
        );
      } catch (error) {
        logger.error(
          "Failed to add ClickShield threat record:",
          error
        );

        throw error;
      }
    });
  }

  // ========================================================
  // PRUNE EXPIRED RECORDS
  // ========================================================

  static async pruneExpiredRecords(): Promise<number> {
    return this.enqueueMutation(async () => {
      try {
        const history = await this.readHistory();

        const cutoffTime = await getRetentionCutoff();

        const kept = applyRetention(
          history,
          cutoffTime
        );

        const removedCount =
          history.length - kept.length;

        // Persist when expired records or excess records
        // have been removed.
        if (removedCount > 0) {
          await this.saveHistory(kept);

          logger.info(
            `Pruned ${removedCount} expired or excess threat records.`
          );
        }

        return removedCount;
      } catch (error) {
        logger.error(
          "Failed to prune ClickShield threat history:",
          error
        );

        return 0;
      }
    });
  }

  // ========================================================
  // CLEAR HISTORY
  // ========================================================

  static async clearAll(): Promise<void> {
    return this.enqueueMutation(async () => {
      try {
        await this.saveHistory([]);

        logger.info(
          "ClickShield threat history cleared by user."
        );
      } catch (error) {
        logger.error(
          "Failed to clear ClickShield threat history:",
          error
        );

        throw error;
      }
    });
  }
}
