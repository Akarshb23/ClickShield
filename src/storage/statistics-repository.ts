
import type { SecurityStatistics } from "../shared/types/threat";

import { logger } from "../shared/utils/logger";

// ==========================================================
// CONSTANTS
// ==========================================================

const STATS_KEY = "clickshield_stats";

const DEFAULT_STATS: SecurityStatistics = {
  pagesScanned: 0,
  threatsDetected: 0,
  interventions: 0,
};

const VALID_FIELDS = new Set<keyof SecurityStatistics>([
  "pagesScanned",
  "threatsDetected",
  "interventions",
]);

// ==========================================================
// TYPES
// ==========================================================

type StatisticsRecord = Record<string, unknown>;

// ==========================================================
// VALIDATION
// ==========================================================

function isRecord(
  value: unknown
): value is StatisticsRecord {
  return (
    typeof value === "object" &&
    value !== null &&
    !Array.isArray(value)
  );
}

/**
 * Return a fresh copy of default statistics.
 */
function getDefaultStatistics(): SecurityStatistics {
  return { ...DEFAULT_STATS };
}

/**
 * Normalize statistics retrieved from Chrome Storage.
 *
 * Invalid counters are reset individually instead of
 * invalidating the entire statistics object.
 */
function normalizeStatistics(
  value: unknown
): SecurityStatistics {
  if (!isRecord(value)) {
    return getDefaultStatistics();
  }

  const normalizeCounter = (
    counter: unknown
  ): number => {
    if (
      typeof counter !== "number" ||
      !Number.isSafeInteger(counter) ||
      counter < 0
    ) {
      return 0;
    }

    return counter;
  };

  return {
    pagesScanned: normalizeCounter(value.pagesScanned),

    threatsDetected: normalizeCounter(
      value.threatsDetected
    ),

    interventions: normalizeCounter(
      value.interventions
    ),
  };
}

/**
 * Validate a statistics field at runtime.
 *
 * TypeScript types do not protect against malformed
 * messages or JavaScript callers.
 */
function isValidStatisticsField(
  field: unknown
): field is keyof SecurityStatistics {
  return (
    typeof field === "string" &&
    VALID_FIELDS.has(
      field as keyof SecurityStatistics
    )
  );
}

// ==========================================================
// STORAGE ACCESS
// ==========================================================

/**
 * Retrieve and normalize stored statistics.
 *
 * Unlike getStatistics(), this internal method allows
 * storage errors to propagate to mutation operations.
 */
async function readStoredStatistics(): Promise<SecurityStatistics> {
  const result = await chrome.storage.local.get(STATS_KEY);

  return normalizeStatistics(result[STATS_KEY]);
}

/**
 * Persist a complete normalized statistics object.
 */
async function saveStatistics(
  statistics: SecurityStatistics
): Promise<void> {
  await chrome.storage.local.set({
    [STATS_KEY]: { ...statistics },
  });
}

// ==========================================================
// REPOSITORY
// ==========================================================

export class StatisticsRepository {
  /**
   * Serialize all statistics mutations.
   *
   * Prevents overlapping increments and resets from
   * overwriting one another within this service-worker context.
   */
  private static mutationQueue: Promise<void> =
    Promise.resolve();

  /**
   * Execute a mutation after all previously queued
   * mutations have completed.
   *
   * A failed operation does not break the queue.
   */
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
  // GET STATISTICS
  // ========================================================

  static async getStatistics(): Promise<SecurityStatistics> {
    try {
      return await readStoredStatistics();
    } catch (error) {
      logger.error(
        "Failed to retrieve ClickShield statistics:",
        error
      );

      return getDefaultStatistics();
    }
  }

  // ========================================================
  // INCREMENT STATISTICS
  // ========================================================

  static async increment(
    field: keyof SecurityStatistics
  ): Promise<SecurityStatistics> {
    // Reject unknown properties at runtime as well.
    if (!isValidStatisticsField(field)) {
      throw new TypeError(
        `Invalid statistics field: ${String(field)}`
      );
    }

    return this.enqueueMutation(async () => {
      try {
        // Always retrieve the latest values inside
        // the serialized operation.
        const statistics = await readStoredStatistics();

        const currentValue = statistics[field];

        // Prevent unsafe integer overflow.
        if (
          currentValue >= Number.MAX_SAFE_INTEGER
        ) {
          throw new RangeError(
            `Statistics counter ${field} reached its maximum safe integer.`
          );
        }

        const updated: SecurityStatistics = {
          ...statistics,
          [field]: currentValue + 1,
        };

        await saveStatistics(updated);

        logger.debug(
          `ClickShield statistic incremented: ${field}`,
          updated[field]
        );

        return { ...updated };
      } catch (error) {
        logger.error(
          `Failed to increment ClickShield statistic ${field}:`,
          error
        );

        throw error;
      }
    });
  }

  // ========================================================
  // RESET STATISTICS
  // ========================================================

  static async reset(): Promise<void> {
    return this.enqueueMutation(async () => {
      try {
        const defaults = getDefaultStatistics();

        await saveStatistics(defaults);

        logger.info(
          "ClickShield statistics reset to defaults."
        );
      } catch (error) {
        logger.error(
          "Failed to reset ClickShield statistics:",
          error
        );

        throw error;
      }
    });
  }
}
