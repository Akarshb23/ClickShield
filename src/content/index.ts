
import { scanPage } from "./page-scanner";

import { calculateRisk } from "../engine/risk-engine";

import { ClipboardGuard } from "./clipboard-guard";

import { DynamicDomObserver } from "./dom-observer";

import { InteractionMonitor } from "./event-monitor";

import { InterventionManager } from "../protection/intervention-manager";

import { DEFAULT_SETTINGS } from "../shared/constants/default-settings";

import {
  RISK_THRESHOLDS,
  SIGNAL_WEIGHTS,
} from "../shared/constants/risk-levels";

import { logger } from "../shared/utils/logger";

import type {
  ThreatSignal,
  ScanResult,
  RiskLevel,
} from "../shared/types/signal";

import type { ClickShieldSettings } from "../shared/types/settings";

// ==========================================================
// CONSTANTS
// ==========================================================

const SETTINGS_KEY = "clickshield_settings";
const ALLOWLIST_KEY = "clickshield_allowlist";

const SETTINGS_REQUEST_EVENT =
  "clickshield:protection-settings-request";

const PROTECTION_SETTINGS_EVENT =
  "clickshield:protection-settings";

const DYNAMIC_SIGNAL_TTL_MS = 2 * 60 * 1000;

const MAX_DYNAMIC_SIGNALS = 30;

const MAX_SIGNAL_REASON_LENGTH = 300;

const MAX_SIGNAL_SNIPPET_LENGTH = 100;

const MAX_ALLOWLIST_ENTRIES = 500;

// ==========================================================
// TYPES
// ==========================================================

interface DynamicSignalRecord {
  signal: ThreatSignal;
  expiresAt: number;
}

// ==========================================================
// VALID SIGNAL TYPES
// ==========================================================

const VALID_SIGNAL_TYPES = new Set<ThreatSignal["type"]>([
  "FAKE_CAPTCHA",
  "SUSPICIOUS_INSTRUCTION",
  "CLIPBOARD_MANIPULATION",
  "EXECUTION_INSTRUCTION",
  "SUSPICIOUS_DOMAIN",
  "DOMAIN_IMPERSONATION",
]);

// ==========================================================
// STATE
// ==========================================================

const dynamicSignals = new Map<string, DynamicSignalRecord>();

let lastReportedFingerprint: string | null = null;

let currentSettings: ClickShieldSettings = {
  ...DEFAULT_SETTINGS,
};

let allowlist: string[] = [];

let configurationReady = false;

let initialized = false;

let isTopFrame = false;

let settingsListenerInitialized = false;

let messageListenerInitialized = false;

let domObserver: DynamicDomObserver | null = null;

let dynamicSignalExpiryTimer: ReturnType<typeof setTimeout> | null =
  null;

// ==========================================================
// BASIC VALIDATION
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

// ==========================================================
// SETTINGS NORMALIZATION
// ==========================================================

/**
 * Validate stored settings field by field.
 *
 * Browser storage should not be assumed to contain valid
 * values merely because the TypeScript interface exists.
 */
function normalizeSettings(
  settings: unknown
): ClickShieldSettings {
  const value = isRecord(settings) ? settings : {};

  const sensitivity =
    value.detectionSensitivity;

  const validSensitivity =
    sensitivity === "low" ||
    sensitivity === "balanced" ||
    sensitivity === "aggressive";

  const retentionValue = value.historyRetentionDays;

  const retentionDays =
    typeof retentionValue === "number" &&
    Number.isFinite(retentionValue)
      ? Math.trunc(retentionValue)
      : DEFAULT_SETTINGS.historyRetentionDays;

  return {
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

    detectionSensitivity: validSensitivity
      ? sensitivity
      : DEFAULT_SETTINGS.detectionSensitivity,

    historyRetentionDays: Math.min(
      3650,
      Math.max(1, retentionDays)
    ),

    soundAlerts:
      typeof value.soundAlerts === "boolean"
        ? value.soundAlerts
        : DEFAULT_SETTINGS.soundAlerts,
  };
}

// ==========================================================
// ALLOWLIST NORMALIZATION
// ==========================================================

/**
 * Normalize a domain entry to its hostname.
 *
 * Accepts:
 * example.com
 * *.example.com
 * https://example.com
 *
 * Rejects entries containing credentials, ports,
 * paths, query strings or fragments.
 */
function normalizeAllowlistEntry(
  entry: string
): string | null {
  let candidate = entry.trim().toLowerCase();

  if (!candidate || candidate.length > 2048) {
    return null;
  }

  // Support wildcard entries as domain entries.
  if (candidate.startsWith("*.")) {
    candidate = candidate.slice(2);
  }

  if (!candidate || candidate.includes("*")) {
    return null;
  }

  try {
    const hasScheme = /^[a-z][a-z0-9+.-]*:\/\//i.test(
      candidate
    );

    if (
      hasScheme &&
      !/^https?:\/\//i.test(candidate)
    ) {
      return null;
    }

    // Bare hostname entries must not contain URL components.
    if (
      !hasScheme &&
      /[\/\\?#@\s]/.test(candidate)
    ) {
      return null;
    }

    const url = new URL(
      hasScheme
        ? candidate
        : `https://${candidate}`
    );

    if (
      (url.protocol !== "https:" &&
        url.protocol !== "http:") ||
      url.username ||
      url.password ||
      url.port ||
      url.pathname !== "/" ||
      url.search ||
      url.hash
    ) {
      return null;
    }

    const hostname = url.hostname
      .toLowerCase()
      .replace(/\.$/, "");

    return hostname || null;
  } catch {
    return null;
  }
}

/**
 * Validate and deduplicate the stored allowlist.
 */
function normalizeAllowlist(
  value: unknown
): string[] {
  if (!Array.isArray(value)) {
    return [];
  }

  const normalized = new Set<string>();

  for (const entry of value.slice(0, MAX_ALLOWLIST_ENTRIES)) {
    if (typeof entry !== "string") {
      continue;
    }

    const hostname = normalizeAllowlistEntry(entry);

    if (hostname) {
      normalized.add(hostname);
    }
  }

  return Array.from(normalized);
}

// ==========================================================
// CONFIGURATION
// ==========================================================

async function loadConfiguration(): Promise<void> {
  try {
    const stored = await chrome.storage.local.get([
      SETTINGS_KEY,
      ALLOWLIST_KEY,
    ]);

    currentSettings = normalizeSettings(
      stored[SETTINGS_KEY]
    );

    allowlist = normalizeAllowlist(
      stored[ALLOWLIST_KEY]
    );

    configurationReady = true;
  } catch (error) {
    logger.warn(
      "Failed to load ClickShield configuration:",
      error
    );

    // Fail closed if configuration cannot be retrieved.
    currentSettings = {
      ...DEFAULT_SETTINGS,
      protectionEnabled: false,
      clipboardProtection: false,
    };

    allowlist = [];

    configurationReady = true;
  }
}

// ==========================================================
// FRAME DETECTION
// ==========================================================

function detectTopFrame(): boolean {
  try {
    return (
      typeof window !== "undefined" &&
      window === window.top
    );
  } catch {
    return false;
  }
}

// ==========================================================
// ALLOWLIST
// ==========================================================

function isCurrentHostAllowlisted(): boolean {
  const hostname = (
    window.location.hostname || "local-file"
  )
    .toLowerCase()
    .replace(/\.$/, "");

  if (!hostname) {
    return false;
  }

  return allowlist.some((domain) => {
    return (
      hostname === domain ||
      hostname.endsWith(`.${domain}`)
    );
  });
}

// ==========================================================
// PROTECTION STATE
// ==========================================================

function isProtectionActive(): boolean {
  return (
    configurationReady &&
    currentSettings.protectionEnabled &&
    !isCurrentHostAllowlisted()
  );
}

function isClipboardProtectionActive(): boolean {
  return (
    isProtectionActive() &&
    currentSettings.clipboardProtection
  );
}

// ==========================================================
// MAIN WORLD SETTINGS SYNCHRONIZATION
// ==========================================================

/**
 * Broadcast current protection state to the injected
 * MAIN-world clipboard monitor.
 *
 * Note: window CustomEvents are page-visible and are not
 * an authenticated channel against a hostile webpage.
 * They must not be treated as a security boundary.
 */
function broadcastProtectionSettings(): void {
  try {
    window.dispatchEvent(
      new CustomEvent(PROTECTION_SETTINGS_EVENT, {
        detail: {
          protectionEnabled: isProtectionActive(),
          clipboardProtection: isClipboardProtectionActive(),
        },
      })
    );
  } catch (error) {
    logger.debug(
      "Unable to broadcast ClickShield protection settings:",
      error
    );
  }
}

function handleSettingsRequest(): void {
  if (!configurationReady) {
    return;
  }

  broadcastProtectionSettings();
}

// ==========================================================
// DETECTION SENSITIVITY
// ==========================================================

/**
 * Apply the configured sensitivity multiplier to the
 * authoritative weights assigned by the risk engine.
 *
 * Missing weights fall back to SIGNAL_WEIGHTS.
 */
function applyDetectionSensitivity(
  result: ScanResult
): ScanResult {
  const multipliers: Record<
    ClickShieldSettings["detectionSensitivity"],
    number
  > = {
    low: 0.8,
    balanced: 1,
    aggressive: 1.2,
  };

  const multiplier =
    multipliers[currentSettings.detectionSensitivity];

  const adjustedSignals = result.signals.map((signal) => {
    const configuredWeight =
      SIGNAL_WEIGHTS[signal.type] ?? 0;

    const originalWeight =
      typeof signal.weight === "number" &&
      Number.isFinite(signal.weight)
        ? signal.weight
        : configuredWeight;

    const safeWeight = Math.min(
      100,
      Math.max(0, originalWeight)
    );

    const adjustedWeight = Math.min(
      100,
      Math.max(0, Math.round(safeWeight * multiplier))
    );

    return {
      ...signal,
      weight: adjustedWeight,
    };
  });

  const adjustedScore = Math.min(
    100,
    adjustedSignals.reduce(
      (total, signal) =>
        total + (signal.weight ?? 0),
      0
    )
  );

  let level: RiskLevel = "LOW";

  if (adjustedScore >= RISK_THRESHOLDS.CRITICAL) {
    level = "CRITICAL";
  } else if (adjustedScore >= RISK_THRESHOLDS.HIGH) {
    level = "HIGH";
  } else if (
    adjustedScore >= RISK_THRESHOLDS.SUSPICIOUS
  ) {
    level = "SUSPICIOUS";
  }

  return {
    ...result,
    score: adjustedScore,
    level,
    signals: adjustedSignals,
  };
}

// ==========================================================
// DYNAMIC SIGNAL MANAGEMENT
// ==========================================================

function getSignalKey(signal: ThreatSignal): string {
  return `${signal.type}:${signal.reason.toLowerCase()}`;
}

/**
 * Validate and normalize dynamic signals before storing them.
 *
 * This also prevents unnecessarily large signal records.
 */
function normalizeSignal(
  signal: unknown
): ThreatSignal | null {
  if (
    !isRecord(signal) ||
    !VALID_SIGNAL_TYPES.has(
      signal.type as ThreatSignal["type"]
    )
  ) {
    return null;
  }

  if (
    typeof signal.reason !== "string" ||
    !signal.reason.trim()
  ) {
    return null;
  }

  const reason = signal.reason
    .trim()
    .slice(0, MAX_SIGNAL_REASON_LENGTH);

  const normalized: ThreatSignal = {
    type: signal.type as ThreatSignal["type"],
    reason,
  };

  if (typeof signal.snippet === "string") {
    normalized.snippet = signal.snippet.slice(
      0,
      MAX_SIGNAL_SNIPPET_LENGTH
    );
  }

  if (
    typeof signal.weight === "number" &&
    Number.isFinite(signal.weight)
  ) {
    normalized.weight = Math.min(
      100,
      Math.max(0, signal.weight)
    );
  }

  return normalized;
}

/**
 * Remove expired signals.
 *
 * Dynamic events are temporary evidence. Static page evidence
 * continues to be collected independently by scanPage().
 */
function pruneExpiredDynamicSignals(): boolean {
  const now = Date.now();

  let changed = false;

  for (const [key, record] of dynamicSignals.entries()) {
    if (record.expiresAt <= now) {
      dynamicSignals.delete(key);
      changed = true;
    }
  }

  return changed;
}

/**
 * Clear all dynamic signals and their expiry timer.
 */
function clearDynamicSignals(): void {
  dynamicSignals.clear();

  if (dynamicSignalExpiryTimer !== null) {
    clearTimeout(dynamicSignalExpiryTimer);
    dynamicSignalExpiryTimer = null;
  }
}

/**
 * Maintain a single timer for the next signal expiration.
 */
function scheduleDynamicSignalExpiry(): void {
  if (dynamicSignalExpiryTimer !== null) {
    clearTimeout(dynamicSignalExpiryTimer);
    dynamicSignalExpiryTimer = null;
  }

  if (dynamicSignals.size === 0) {
    return;
  }

  let earliestExpiry = Infinity;

  for (const record of dynamicSignals.values()) {
    earliestExpiry = Math.min(
      earliestExpiry,
      record.expiresAt
    );
  }

  const delay = Math.max(
    0,
    earliestExpiry - Date.now()
  );

  dynamicSignalExpiryTimer = setTimeout(() => {
    dynamicSignalExpiryTimer = null;

    const expired = pruneExpiredDynamicSignals();

    if (expired) {
      logger.debug(
        "Expired ClickShield dynamic threat signals."
      );

      executeScan();
    } else {
      scheduleDynamicSignalExpiry();
    }
  }, delay);
}

/**
 * Add a new dynamic signal or refresh the expiry of an
 * existing matching signal.
 *
 * Repeated evidence refreshes its TTL without generating
 * another identical background report.
 */
function addDynamicSignal(
  signal: ThreatSignal
): boolean {
  const normalized = normalizeSignal(signal);

  if (!normalized) {
    return false;
  }

  const key = getSignalKey(normalized);

  const existing = dynamicSignals.get(key);

  if (existing) {
    // Reinsert to maintain insertion order for eviction.
    dynamicSignals.delete(key);

    dynamicSignals.set(key, {
      signal: normalized,
      expiresAt: Date.now() + DYNAMIC_SIGNAL_TTL_MS,
    });

    scheduleDynamicSignalExpiry();

    return false;
  }

  // Bound memory usage if a page produces many distinct signals.
  if (dynamicSignals.size >= MAX_DYNAMIC_SIGNALS) {
    const oldestKey = dynamicSignals.keys().next().value;

    if (oldestKey !== undefined) {
      dynamicSignals.delete(oldestKey);
    }
  }

  dynamicSignals.set(key, {
    signal: normalized,
    expiresAt: Date.now() + DYNAMIC_SIGNAL_TTL_MS,
  });

  scheduleDynamicSignalExpiry();

  return true;
}

// ==========================================================
// SCAN RESULT VALIDATION
// ==========================================================

function isValidScanResult(
  result: ScanResult
): boolean {
  return (
    !!result &&
    typeof result === "object" &&
    Number.isFinite(result.score) &&
    result.score >= 0 &&
    result.score <= 100 &&
    Array.isArray(result.signals)
  );
}

// ==========================================================
// SCAN RESULT FINGERPRINTING
// ==========================================================

/**
 * Generate a stable fingerprint independent of the scan
 * timestamp.
 *
 * This prevents DOM mutations from repeatedly reporting
 * identical results to the background service worker.
 */
function createScanFingerprint(
  result: ScanResult
): string {
  const signalFingerprint = result.signals
    .map((signal) => ({
      type: signal.type,
      reason: signal.reason,
      weight: signal.weight ?? 0,
    }))
    .sort((a, b) => {
      const first = `${a.type}:${a.reason}`;
      const second = `${b.type}:${b.reason}`;

      return first.localeCompare(second);
    });

  return JSON.stringify({
    hostname: result.hostname || "",
    url: result.url || "",
    score: result.score,
    level: result.level,
    signals: signalFingerprint,
  });
}

// ==========================================================
// BACKGROUND COMMUNICATION
// ==========================================================

function reportScanResult(result: ScanResult): void {
  if (!isValidScanResult(result)) {
    return;
  }

  const fingerprint = createScanFingerprint(result);

  // Do not create duplicate history entries or statistics
  // for identical scan results.
  if (fingerprint === lastReportedFingerprint) {
    return;
  }

  const previousFingerprint = lastReportedFingerprint;

  // Reserve the fingerprint before sending to avoid
  // duplicate messages from rapidly scheduled scans.
  lastReportedFingerprint = fingerprint;

  try {
    chrome.runtime
      .sendMessage({
        type: "SCAN_RESULT",
        payload: result,
      })
      .catch(() => {
        // Permit a future scan to retry if communication fails.
        if (lastReportedFingerprint === fingerprint) {
          lastReportedFingerprint = previousFingerprint;
        }
      });
  } catch (error) {
    if (lastReportedFingerprint === fingerprint) {
      lastReportedFingerprint = previousFingerprint;
    }

    logger.debug(
      "Unable to communicate with ClickShield background:",
      error
    );
  }
}

// ==========================================================
// SCANNING
// ==========================================================

function executeScan(
  _forceNotify = false
): ScanResult | null {
  try {
    // Page-level scanning and reporting belong to the top frame.
    if (!isTopFrame || !configurationReady) {
      return null;
    }

    const context = {
      hostname: window.location.hostname || "local-file",
      url: window.location.href,
    };

    // ------------------------------------------------------
    // Protection disabled or website allowlisted
    // ------------------------------------------------------

    if (!isProtectionActive()) {
      clearDynamicSignals();

      InterventionManager.resetSession();

      const inactiveResult = calculateRisk([], context);

      reportScanResult(inactiveResult);

      return inactiveResult;
    }

    // ------------------------------------------------------
    // Remove expired signals before each scan
    // ------------------------------------------------------

    pruneExpiredDynamicSignals();

    scheduleDynamicSignalExpiry();

    // ------------------------------------------------------
    // Static and dynamic detection
    // ------------------------------------------------------

    const pageSignals = scanPage();

    const activeDynamicSignals = Array.from(
      dynamicSignals.values()
    ).map((record) => record.signal);

    const combinedSignals = [
      ...pageSignals,
      ...activeDynamicSignals,
    ];

    const baseResult = calculateRisk(
      combinedSignals,
      context
    );

    const result = applyDetectionSensitivity(baseResult);

    // ------------------------------------------------------
    // Intervention
    // ------------------------------------------------------

    InterventionManager.evaluateAndIntervene(result);

    // ------------------------------------------------------
    // Background reporting
    // ------------------------------------------------------

    reportScanResult(result);

    return result;
  } catch (error) {
    logger.debug(
      "Scan error or context invalidated:",
      error
    );

    return null;
  }
}

// ==========================================================
// DYNAMIC THREAT HANDLING
// ==========================================================

function canProcessSignal(
  signal: ThreatSignal
): boolean {
  if (
    !signal ||
    !VALID_SIGNAL_TYPES.has(signal.type)
  ) {
    return false;
  }

  if (!isProtectionActive()) {
    return false;
  }

  if (
    signal.type === "CLIPBOARD_MANIPULATION" &&
    !isClipboardProtectionActive()
  ) {
    return false;
  }

  return true;
}

function handleDynamicThreat(
  signal: ThreatSignal
): void {
  const normalized = normalizeSignal(signal);

  if (!normalized || !canProcessSignal(normalized)) {
    return;
  }

  const added = addDynamicSignal(normalized);

  // Only a genuinely new signal requires an immediate scan.
  if (added) {
    executeScan();
  }
}

// ==========================================================
// SETTINGS CHANGE LISTENER
// ==========================================================

function initializeSettingsListener(): void {
  if (settingsListenerInitialized) {
    return;
  }

  try {
    chrome.storage.onChanged.addListener(
      (changes, areaName) => {
        if (areaName !== "local") {
          return;
        }

        let configurationChanged = false;

        // --------------------------------------------------
        // Settings update
        // --------------------------------------------------

        if (changes[SETTINGS_KEY]) {
          currentSettings = normalizeSettings(
            changes[SETTINGS_KEY].newValue
          );

          configurationChanged = true;
        }

        // --------------------------------------------------
        // Allowlist update
        // --------------------------------------------------

        if (changes[ALLOWLIST_KEY]) {
          allowlist = normalizeAllowlist(
            changes[ALLOWLIST_KEY].newValue
          );

          configurationChanged = true;
        }

        if (!configurationChanged) {
          return;
        }

        logger.info(
          "ClickShield protection configuration changed."
        );

        // Update MAIN-world protection state.
        broadcastProtectionSettings();

        // --------------------------------------------------
        // Protection disabled
        // --------------------------------------------------

        if (!isProtectionActive()) {
          clearDynamicSignals();

          domObserver?.stop();

          InterventionManager.resetSession();
        } else if (isTopFrame) {
          // ------------------------------------------------
          // Protection enabled
          // ------------------------------------------------

          domObserver?.start(
            document.body || document.documentElement
          );

          InterventionManager.initialize();
        }

        // Only the top frame performs page-level scans.
        // Subframes report their own interaction signals.
        if (isTopFrame) {
          executeScan();
        }
      }
    );

    settingsListenerInitialized = true;
  } catch (error) {
    logger.error(
      "Failed to initialize ClickShield settings listener:",
      error
    );
  }
}

// ==========================================================
// POPUP COMMUNICATION
// ==========================================================

function initializeMessageListener(): void {
  if (messageListenerInitialized) {
    return;
  }

  try {
    chrome.runtime.onMessage.addListener(
      (message, _sender, sendResponse) => {
        if (
          !message ||
          typeof message !== "object" ||
          !("type" in message)
        ) {
          return false;
        }

        const messageType = message.type;

        if (
          messageType !== "TRIGGER_RESCAN" &&
          messageType !== "GET_LIVE_SCAN"
        ) {
          return false;
        }

        // A user-requested rescan explicitly begins a new
        // intervention session.
        //
        // GET_LIVE_SCAN must not reset dismissal state.
        if (messageType === "TRIGGER_RESCAN") {
          InterventionManager.resetSession();

          if (isProtectionActive()) {
            InterventionManager.initialize();
          }
        }

        const result = executeScan();

        sendResponse({
          status: "OK",
          result,
        });

        return false;
      }
    );

    messageListenerInitialized = true;
  } catch (error) {
    logger.error(
      "Failed to initialize ClickShield message listener:",
      error
    );
  }
}

// ==========================================================
// SUBFRAME COMMUNICATION
// ==========================================================

function reportSubframeThreat(
  signal: ThreatSignal
): void {
  const normalized = normalizeSignal(signal);

  if (
    !normalized ||
    !canProcessSignal(normalized)
  ) {
    return;
  }

  try {
    chrome.runtime
      .sendMessage({
        type: "SUBFRAME_THREAT",
        payload: normalized,
      })
      .catch(() => {
        // The frame may have been detached or the extension
        // context may have been invalidated.
      });
  } catch {
    // Ignore communication errors from detached frames.
  }
}

// ==========================================================
// SUBFRAME INITIALIZATION
// ==========================================================

function initializeSubframe(): void {
  logger.debug(
    "ClickShield subframe protection initialized:",
    window.location.hostname
  );

  ClipboardGuard.initialize({
    onThreatDetected: reportSubframeThreat,
  });

  InteractionMonitor.initialize({
    onInteractionThreat: reportSubframeThreat,
  });
}

// ==========================================================
// INITIALIZATION
// ==========================================================

async function initContentScript(): Promise<void> {
  if (initialized) {
    return;
  }

  initialized = true;

  isTopFrame = detectTopFrame();

  // Wait for the configuration load started at script execution.
  await configurationPromise;

  initializeSettingsListener();

  // Publish settings to MAIN-world interceptors.
  broadcastProtectionSettings();

  // --------------------------------------------------------
  // Subframe initialization
  // --------------------------------------------------------

  if (!isTopFrame) {
    initializeSubframe();
    return;
  }

  logger.info(
    "ClickShield initialized on top frame:",
    window.location.hostname || window.location.href
  );

  // --------------------------------------------------------
  // 1. Intervention system
  // --------------------------------------------------------

  if (isProtectionActive()) {
    InterventionManager.initialize();
  }

  // --------------------------------------------------------
  // 2. Initial scan
  // --------------------------------------------------------

  executeScan();

  // --------------------------------------------------------
  // 3. Dynamic DOM observer
  // --------------------------------------------------------

  domObserver = new DynamicDomObserver({
    onMutation: () => {
      executeScan();
    },
    debounceMs: 500,
  });

  if (isProtectionActive()) {
    domObserver.start(
      document.body || document.documentElement
    );
  }

  // --------------------------------------------------------
  // 4. Clipboard protection
  // --------------------------------------------------------

  ClipboardGuard.initialize({
    onThreatDetected: handleDynamicThreat,
  });

  // --------------------------------------------------------
  // 5. Interaction monitoring
  // --------------------------------------------------------

  InteractionMonitor.initialize({
    onInteractionThreat: handleDynamicThreat,
  });

  // --------------------------------------------------------
  // 6. Popup communication
  // --------------------------------------------------------

  initializeMessageListener();
}

// ==========================================================
// ENTRY POINT
// ==========================================================

// Install MAIN-world settings request listener immediately.
window.addEventListener(
  SETTINGS_REQUEST_EVENT,
  handleSettingsRequest
);

// Begin loading configuration immediately.
const configurationPromise = loadConfiguration();

// Initialize after the document is ready.
if (document.readyState === "loading") {
  document.addEventListener(
    "DOMContentLoaded",
    () => {
      void initContentScript();
    },
    { once: true }
  );
} else {
  void initContentScript();
}
