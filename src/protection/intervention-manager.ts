import type { ScanResult } from "../shared/types/signal";
import { WarningOverlay } from "./warning-overlay";
import { CopyInterceptor } from "./copy-interceptor";
import { logger } from "../shared/utils/logger";

export class InterventionManager {
  private static userDismissed = false;
  private static isInitialized = false;
  private static isOverlayActive = false;

  static initialize() {
    if (this.isInitialized) return;
    this.isInitialized = true;

    // Arm copy interceptor
    CopyInterceptor.arm({
      onIntervention: (reason) => {
        logger.info("Active intervention triggered:", reason);
      },
    });
  }

  static evaluateAndIntervene(scanResult: ScanResult): void {
    this.initialize();

    // Prevent duplicate overlays or running inside child frames
    if (this.userDismissed || this.isOverlayActive) return;
    if (typeof window !== "undefined" && window !== window.top) return;

    const types = new Set(scanResult.signals.map((s) => s.type));
    const isClickFixAttack =
      (types.has("FAKE_CAPTCHA") && types.has("EXECUTION_INSTRUCTION")) ||
      (types.has("SUSPICIOUS_INSTRUCTION") && types.has("EXECUTION_INSTRUCTION")) ||
      (types.has("FAKE_CAPTCHA") && types.has("SUSPICIOUS_INSTRUCTION"));

    // Trigger intervention overlay on high/critical threat or confirmed ClickFix attack signature
    if (
      (scanResult.score >= 60 || isClickFixAttack || scanResult.score >= 80) &&
      !WarningOverlay.isVisible()
    ) {
      this.isOverlayActive = true;
      logger.info("Displaying ClickShield intervention overlay for:", scanResult.hostname);

      WarningOverlay.show(scanResult, () => {
        this.userDismissed = true;
        this.isOverlayActive = false;
        logger.info("User dismissed ClickShield warning for current session.");
      });
    }
  }

  static resetSession(): void {
    this.userDismissed = false;
    this.isOverlayActive = false;
    WarningOverlay.hide();
  }
}

