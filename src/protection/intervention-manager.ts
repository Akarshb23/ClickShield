import type { ScanResult } from "../shared/types/signal";
import type { InterventionShownMessage } from "../shared/types/messages";

import { correlateSignals } from "../engine/signal-correlator";
import { RISK_THRESHOLDS } from "../shared/constants/risk-levels";

import { WarningOverlay } from "./warning-overlay";
import { CopyInterceptor } from "./copy-interceptor";

import { logger } from "../shared/utils/logger";

const INTERVENTION_CONFIRMATION_RETRY_DELAYS = [100, 200, 400, 600, 800] as const;

const RETRYABLE_CONFIRMATION_ERRORS = new Set([
  "No current scan state exists for this tab.",
  "The tab no longer has a qualifying active threat state.",
]);

const RETRYABLE_TRANSPORT_ERROR_PATTERNS = [
  /receiving end does not exist/i,
  /could not establish connection/i,
  /message port closed/i,
  /service worker.*(stopped|inactive|not running)/i,
];

export class InterventionManager {
  private static userDismissed = false;
  private static isInitialized = false;
  private static isOverlayActive = false;

  /** Prevent intervention initialization and overlay display inside child frames. */
  private static isTopFrame(): boolean {
    try {
      return typeof window !== "undefined" && window === window.top;
    } catch {
      return false;
    }
  }

  static initialize(): void {
    if (!this.isTopFrame() || this.isInitialized) {
      return;
    }

    try {
      CopyInterceptor.arm({
        onIntervention: (reason) => {
          logger.warn("ClickShield active intervention triggered:", reason);
        },
      });

      this.isInitialized = true;
      logger.info("ClickShield InterventionManager initialized.");
    } catch (error) {
      logger.error(
        "Failed to initialize ClickShield intervention manager:",
        error
      );
    }
  }

  /** Validate incoming scan results before using them for an intervention decision. */
  private static isValidScanResult(
    scanResult: unknown
  ): scanResult is ScanResult {
    if (!scanResult || typeof scanResult !== "object") {
      return false;
    }

    const result = scanResult as ScanResult;
    const validRiskLevels = ["LOW", "SUSPICIOUS", "HIGH", "CRITICAL"];

    return (
      typeof result.score === "number" &&
      Number.isFinite(result.score) &&
      result.score >= 0 &&
      result.score <= 100 &&
      validRiskLevels.includes(result.level) &&
      Array.isArray(result.signals) &&
      (result.hostname === undefined || typeof result.hostname === "string") &&
      (result.url === undefined || typeof result.url === "string")
    );
  }

  /** Create an opaque ID so the background can count each displayed overlay once. */
  private static createInterventionId(): string {
    if (
      typeof crypto !== "undefined" &&
      typeof crypto.randomUUID === "function"
    ) {
      return crypto.randomUUID();
    }

    if (typeof crypto === "undefined" || !crypto.getRandomValues) {
      throw new Error("A secure random source is unavailable.");
    }

    const bytes = new Uint8Array(16);
    crypto.getRandomValues(bytes);

    const randomPart = Array.from(bytes, (byte) =>
      byte.toString(16).padStart(2, "0")
    ).join("");

    return `${Date.now()}-${randomPart}`;
  }

  private static getResponseError(response: unknown): string | null {
    if (
      typeof response === "object" &&
      response !== null &&
      "error" in response &&
      typeof response.error === "string" &&
      response.error.trim()
    ) {
      return response.error;
    }

    return null;
  }

  private static isRetryableTransportError(error: unknown): boolean {
    const message = error instanceof Error ? error.message : String(error);
    return RETRYABLE_TRANSPORT_ERROR_PATTERNS.some((pattern) =>
      pattern.test(message)
    );
  }

  /**
   * Notify the background only after the overlay is confirmed visible.
   * The same ID is reused for every attempt so the service worker can safely
   * deduplicate a confirmation whose response was lost after it was counted.
   */
  private static async reportInterventionShown(
    interventionId: string
  ): Promise<void> {
    if (typeof chrome === "undefined" || !chrome.runtime?.sendMessage) {
      logger.warn(
        "ClickShield warning was displayed, but runtime messaging is unavailable."
      );
      return;
    }

    const message: InterventionShownMessage = {
      type: "INTERVENTION_SHOWN",
      payload: { interventionId },
    };

    for (
      let attempt = 0;
      attempt <= INTERVENTION_CONFIRMATION_RETRY_DELAYS.length;
      attempt += 1
    ) {
      try {
        const response: unknown = await chrome.runtime.sendMessage(message);
        const responseError = this.getResponseError(response);

        if (responseError) {
          const canRetry =
            (RETRYABLE_CONFIRMATION_ERRORS.has(responseError) ||
              this.isRetryableTransportError(responseError)) &&
            attempt < INTERVENTION_CONFIRMATION_RETRY_DELAYS.length;

          if (canRetry) {
            const delay = INTERVENTION_CONFIRMATION_RETRY_DELAYS[attempt];
            logger.debug(
              "Intervention confirmation was temporarily rejected; retrying.",
              { attempt: attempt + 1, delay, reason: responseError }
            );
            await new Promise<void>((resolve) => setTimeout(resolve, delay));
            continue;
          }

          logger.warn(
            "Background rejected the intervention confirmation:",
            responseError
          );
          return;
        }

        if (
          typeof response === "object" &&
          response !== null &&
          "success" in response &&
          response.success === true
        ) {
          logger.info("ClickShield intervention display confirmed.", {
            interventionId,
          });
          return;
        }

        logger.warn(
          "Background returned an unexpected intervention confirmation response."
        );
        return;
      } catch (error) {
        const canRetry =
          this.isRetryableTransportError(error) &&
          attempt < INTERVENTION_CONFIRMATION_RETRY_DELAYS.length;

        if (canRetry) {
          const delay = INTERVENTION_CONFIRMATION_RETRY_DELAYS[attempt];
          logger.debug(
            "Intervention confirmation transport failed temporarily; retrying.",
            { attempt: attempt + 1, delay }
          );
          await new Promise<void>((resolve) => setTimeout(resolve, delay));
          continue;
        }

        logger.warn(
          "Could not report the displayed ClickShield intervention:",
          error
        );
        return;
      }
    }

    logger.warn(
      "ClickShield could not confirm the displayed intervention after retrying."
    );
  }

  /**
   * Determine whether an intervention is necessary. ClickFix classification is
   * delegated to the central signal correlator. The original score is retained
   * because the content scanner has already applied the user's sensitivity setting.
   */
  static evaluateAndIntervene(scanResult: ScanResult): void {
    if (!this.isTopFrame()) {
      return;
    }

    if (!this.isValidScanResult(scanResult)) {
      logger.debug("Invalid ClickShield scan result received.");
      return;
    }

    this.initialize();
    if (!this.isInitialized) {
      return;
    }

    if (this.userDismissed) {
      return;
    }

    try {
      if (this.isOverlayActive || WarningOverlay.isVisible()) {
        this.isOverlayActive = WarningOverlay.isVisible();
        return;
      }

      const verdict = correlateSignals(scanResult.signals, {
        hostname: scanResult.hostname,
        url: scanResult.url,
      });

      const isClickFixAttack = verdict.isClickFixAttack;
      const isActionableClickFix =
        isClickFixAttack &&
        scanResult.score >= RISK_THRESHOLDS.SUSPICIOUS;
      const isCriticalThreat = scanResult.score >= RISK_THRESHOLDS.CRITICAL;

      if (!isActionableClickFix && !isCriticalThreat) {
        return;
      }

      const normalizedResult: ScanResult = {
        ...scanResult,
        signals: verdict.signals,
      };

      logger.warn("ClickShield intervention triggered:", {
        hostname: scanResult.hostname,
        score: scanResult.score,
        level: scanResult.level,
        isClickFixAttack,
        attackVector: verdict.primaryAttackVector,
        recommendedAction: verdict.recommendedAction,
      });

      WarningOverlay.show(normalizedResult, () => {
        this.userDismissed = true;
        this.isOverlayActive = false;

        logger.info(
          "User dismissed ClickShield warning for current session."
        );
      });

      this.isOverlayActive = WarningOverlay.isVisible();

      if (!this.isOverlayActive) {
        logger.warn(
          "ClickShield warning overlay could not be displayed; intervention was not counted."
        );
        return;
      }

      const interventionId = this.createInterventionId();
      void this.reportInterventionShown(interventionId);
    } catch (error) {
      this.isOverlayActive = false;
      logger.error(
        "Failed to evaluate or display ClickShield intervention:",
        error
      );
    }
  }

  /** Reset intervention dismissal state for a new scan session or configuration. */
  static resetSession(): void {
    this.userDismissed = false;
    this.isOverlayActive = false;

    try {
      WarningOverlay.hide();
      logger.info("ClickShield intervention session reset.");
    } catch (error) {
      logger.error(
        "Failed to reset ClickShield intervention session:",
        error
      );
    }
  }
}
