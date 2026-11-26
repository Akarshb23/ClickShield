import { StorageManager } from "../storage/storage-manager";

import {
  BADGE_COLORS,
  RISK_THRESHOLDS,
} from "../shared/constants/risk-levels";

import { calculateRisk } from "../engine/risk-engine";
import { correlateSignals } from "../engine/signal-correlator";
import { logger } from "../shared/utils/logger";

import type {
  ScanResult,
  RiskLevel,
  ThreatSignal,
  SignalType,
} from "../shared/types/signal";

import type { TabState } from "../shared/types/messages";
import type { ClickShieldSettings } from "../shared/types/settings";

// ==========================================================
// CONSTANTS
// ==========================================================

const VALID_SIGNAL_TYPES = new Set<SignalType>([
  "FAKE_CAPTCHA",
  "SUSPICIOUS_INSTRUCTION",
  "CLIPBOARD_MANIPULATION",
  "EXECUTION_INSTRUCTION",
  "SUSPICIOUS_DOMAIN",
  "DOMAIN_IMPERSONATION",
]);

const SENSITIVITY_MULTIPLIERS: Record<
  ClickShieldSettings["detectionSensitivity"],
  number
> = {
  low: 0.8,
  balanced: 1,
  aggressive: 1.2,
};

const SUBFRAME_SIGNAL_TTL_MS = 2 * 60 * 1000;
const MAX_SUBFRAME_SIGNALS = 50;
const MAX_INCOMING_SIGNALS = 100;
const MAX_URL_LENGTH = 2048;
const MAX_HOSTNAME_LENGTH = 253;
const FUTURE_TIMESTAMP_TOLERANCE_MS = 30 * 1000;
const INTERVENTION_RECEIPTS_KEY = "clickshield_intervention_receipts";
const INTERVENTION_RECEIPT_TTL_MS = 24 * 60 * 60 * 1000;
const MAX_INTERVENTION_RECEIPTS = 500;
const INTERVENTION_ID_PATTERN = /^[a-zA-Z0-9-]{16,80}$/;

const TAB_TOP_SCAN_PREFIX = "clickshield_top_scan_";
const TAB_SUBFRAME_PREFIX = "clickshield_subframe_signals_";
const TAB_LAST_PAGE_PREFIX = "clickshield_last_page_";

// ==========================================================
// TYPES
// ==========================================================

interface TopFrameSnapshot {
  hostname: string;
  url: string;
  signals: ThreatSignal[];
  timestamp: number;
}

interface SubframeSignalRecord {
  frameId: number;
  signal: ThreatSignal;
  receivedAt: number;
}

interface InterventionReceipt {
  id: string;
  tabId: number;
  recordedAt: number;
}

// ==========================================================
// PER-TAB OPERATION QUEUE
// ==========================================================

/**
 * Serialize state-changing operations per tab.
 *
 * Chrome can deliver content-script messages close together.
 * Without a queue, two handlers could both read the same
 * session state and then overwrite each other's updates.
 */
const tabOperationQueues = new Map<number, Promise<void>>();

// Intervention receipts are shared by all tabs, so their read/write/count
// sequence must be serialized globally to avoid lost updates.
let interventionOperationQueue: Promise<void> = Promise.resolve();

function enqueueInterventionOperation<T>(
  operation: () => Promise<T>
): Promise<T> {
  const task = interventionOperationQueue.then(operation);
  interventionOperationQueue = task.then(
    () => undefined,
    () => undefined
  );
  return task;
}

function enqueueTabOperation<T>(
  tabId: number,
  operation: () => Promise<T>
): Promise<T> {
  const previous =
    tabOperationQueues.get(tabId) ?? Promise.resolve();

  const task = previous.then(operation);

  const queueEntry = task.then(
    () => undefined,
    () => undefined
  );

  tabOperationQueues.set(tabId, queueEntry);

  void queueEntry.then(() => {
    if (tabOperationQueues.get(tabId) === queueEntry) {
      tabOperationQueues.delete(tabId);
    }
  });

  return task;
}

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

function sanitizeThreatSignal(
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

  const signal: ThreatSignal = {
    type: value.type as SignalType,
    reason: value.reason.trim().slice(0, 500),
  };

  if (typeof value.snippet === "string") {
    const snippet = value.snippet.slice(0, 100);
    if (snippet) {
      signal.snippet = snippet;
    }
  }

  // Incoming weights are intentionally discarded. The risk
  // engine assigns the authoritative weight for each type.
  return signal;
}

function sanitizeThreatSignals(
  value: unknown
): ThreatSignal[] {
  if (!Array.isArray(value)) {
    return [];
  }

  return value
    .slice(0, MAX_INCOMING_SIGNALS)
    .map(sanitizeThreatSignal)
    .filter(
      (signal): signal is ThreatSignal => signal !== null
    );
}

function filterSignalsBySettings(
  signals: ThreatSignal[],
  clipboardProtectionEnabled: boolean
): ThreatSignal[] {
  if (clipboardProtectionEnabled) {
    return signals;
  }

  return signals.filter(
    (signal) => signal.type !== "CLIPBOARD_MANIPULATION"
  );
}

// ==========================================================
// URL AND HOSTNAME VALIDATION
// ==========================================================

function parsePageUrl(value: string): URL | null {
  if (
    typeof value !== "string" ||
    !value.trim() ||
    value.length > MAX_URL_LENGTH
  ) {
    return null;
  }

  try {
    const parsed = new URL(value);

    if (
      parsed.protocol !== "http:" &&
      parsed.protocol !== "https:" &&
      parsed.protocol !== "file:"
    ) {
      return null;
    }

    if (parsed.username || parsed.password) {
      return null;
    }

    return parsed;
  } catch {
    return null;
  }
}

function getTabHostname(url?: string): string {
  if (!url) {
    return "unknown";
  }

  const parsed = parsePageUrl(url);

  if (!parsed) {
    return "unknown";
  }

  if (parsed.protocol === "file:") {
    return "local-file";
  }

  const hostname = parsed.hostname.toLowerCase().replace(/\.$/, "");

  return hostname && hostname.length <= MAX_HOSTNAME_LENGTH
    ? hostname
    : "unknown";
}

/**
 * Prefer the browser-provided tab URL as the authority.
 * A content-script URL is accepted only when it belongs to
 * the same origin as the browser's current tab URL.
 */
function resolveTopFrameUrl(
  candidateUrl: unknown,
  browserUrl: string
): string {
  const browserParsed = parsePageUrl(browserUrl);
  const candidateParsed =
    typeof candidateUrl === "string"
      ? parsePageUrl(candidateUrl)
      : null;

  if (!browserParsed) {
    return candidateParsed?.href ?? "";
  }

  if (!candidateParsed) {
    return browserParsed.href;
  }

  const sameOrigin =
    candidateParsed.protocol === browserParsed.protocol &&
    candidateParsed.host.toLowerCase() ===
      browserParsed.host.toLowerCase();

  return sameOrigin
    ? candidateParsed.href
    : browserParsed.href;
}

function normalizeHostnameFallback(value: unknown): string {
  if (typeof value !== "string") {
    return "unknown";
  }

  const candidate = value.trim().toLowerCase().replace(/\.$/, "");

  if (!candidate || candidate.length > MAX_HOSTNAME_LENGTH) {
    return "unknown";
  }

  if (candidate === "local-file") {
    return candidate;
  }

  try {
    const parsed = new URL(`https://${candidate}`);

    if (
      parsed.username ||
      parsed.password ||
      parsed.port ||
      parsed.pathname !== "/" ||
      parsed.hostname !== candidate
    ) {
      return "unknown";
    }

    return parsed.hostname;
  } catch {
    return "unknown";
  }
}


/** Compare page identity while ignoring hash-only navigation changes. */
function urlsReferToSamePage(firstUrl: string, secondUrl: string): boolean {
  const first = parsePageUrl(firstUrl);
  const second = parsePageUrl(secondUrl);

  if (!first || !second) {
    return false;
  }

  return (
    first.protocol === second.protocol &&
    first.host.toLowerCase() === second.host.toLowerCase() &&
    first.pathname === second.pathname &&
    first.search === second.search
  );
}

async function loadInterventionReceipts(): Promise<InterventionReceipt[]> {
  const result = await chrome.storage.session.get(INTERVENTION_RECEIPTS_KEY);
  const stored = result[INTERVENTION_RECEIPTS_KEY];

  if (!Array.isArray(stored)) {
    return [];
  }

  const now = Date.now();
  return stored
    .filter((item): item is Record<string, unknown> => isRecord(item))
    .filter(
      (item) =>
        typeof item.id === "string" &&
        INTERVENTION_ID_PATTERN.test(item.id) &&
        typeof item.tabId === "number" &&
        Number.isSafeInteger(item.tabId) &&
        item.tabId >= 0 &&
        typeof item.recordedAt === "number" &&
        Number.isFinite(item.recordedAt) &&
        item.recordedAt <= now + FUTURE_TIMESTAMP_TOLERANCE_MS &&
        now - item.recordedAt <= INTERVENTION_RECEIPT_TTL_MS
    )
    .map((item) => ({
      id: item.id as string,
      tabId: item.tabId as number,
      recordedAt: item.recordedAt as number,
    }))
    .slice(-MAX_INTERVENTION_RECEIPTS);
}

async function saveInterventionReceipts(
  receipts: InterventionReceipt[]
): Promise<void> {
  await chrome.storage.session.set({
    [INTERVENTION_RECEIPTS_KEY]: receipts.slice(-MAX_INTERVENTION_RECEIPTS),
  });
}

// ==========================================================
// RISK CALCULATION
// ==========================================================

/**
 * Recalculate risk from normalized signals.
 *
 * Incoming content-script scores and weights are not trusted
 * as authoritative background values. Sensitivity is applied
 * exactly once in this background calculation.
 */
function calculateEffectiveRisk(
  signals: ThreatSignal[],
  sensitivity: ClickShieldSettings["detectionSensitivity"],
  context: {
    hostname?: string;
    url?: string;
  }
): ScanResult {
  const baseResult = calculateRisk(signals, context);
  const multiplier = SENSITIVITY_MULTIPLIERS[sensitivity];

  const adjustedSignals = baseResult.signals.map((signal) => {
    const baseWeight =
      typeof signal.weight === "number" &&
      Number.isFinite(signal.weight)
        ? signal.weight
        : 0;

    const adjustedWeight = Math.min(
      100,
      Math.max(0, Math.round(baseWeight * multiplier))
    );

    return {
      ...signal,
      weight: adjustedWeight,
    };
  });

  const adjustedScore = Math.min(
    100,
    Math.max(
      0,
      adjustedSignals.reduce(
        (total, signal) => total + (signal.weight ?? 0),
        0
      )
    )
  );

  return {
    ...baseResult,
    score: adjustedScore,
    level: getRiskLevel(adjustedScore),
    signals: adjustedSignals,
    timestamp: Date.now(),
  };
}

// ==========================================================
// SESSION STORAGE KEYS
// ==========================================================

function getTopScanKey(tabId: number): string {
  return `${TAB_TOP_SCAN_PREFIX}${tabId}`;
}

function getSubframeSignalsKey(tabId: number): string {
  return `${TAB_SUBFRAME_PREFIX}${tabId}`;
}

function getLastPageKey(tabId: number): string {
  return `${TAB_LAST_PAGE_PREFIX}${tabId}`;
}

// ==========================================================
// TOP-FRAME SNAPSHOT STORAGE
// ==========================================================

async function saveTopFrameSnapshot(
  tabId: number,
  snapshot: TopFrameSnapshot
): Promise<void> {
  await chrome.storage.session.set({
    [getTopScanKey(tabId)]: snapshot,
  });
}

async function getTopFrameSnapshot(
  tabId: number
): Promise<TopFrameSnapshot | null> {
  try {
    const key = getTopScanKey(tabId);
    const result = await chrome.storage.session.get(key);
    const stored = result[key];

    if (!isRecord(stored)) {
      return null;
    }

    if (
      typeof stored.hostname !== "string" ||
      typeof stored.url !== "string" ||
      typeof stored.timestamp !== "number" ||
      !Number.isFinite(stored.timestamp) ||
      stored.timestamp < 0 ||
      stored.timestamp > Date.now() + FUTURE_TIMESTAMP_TOLERANCE_MS ||
      !Array.isArray(stored.signals)
    ) {
      return null;
    }

    return {
      hostname: stored.hostname,
      url: stored.url,
      timestamp: stored.timestamp,
      signals: sanitizeThreatSignals(stored.signals),
    };
  } catch (error) {
    logger.debug(
      "Unable to retrieve top-frame scan snapshot:",
      error
    );

    return null;
  }
}

// ==========================================================
// SUBFRAME SIGNAL STORAGE
// ==========================================================

/**
 * Load valid, unexpired subframe signals.
 *
 * Subframe evidence remains separate from the top-frame scan
 * so subsequent top-frame scans cannot overwrite it.
 */
async function getSubframeSignals(
  tabId: number
): Promise<SubframeSignalRecord[]> {
  try {
    const key = getSubframeSignalsKey(tabId);
    const result = await chrome.storage.session.get(key);
    const stored = result[key];

    if (!Array.isArray(stored)) {
      return [];
    }

    const now = Date.now();
    const latestByFrameAndType = new Map<string, SubframeSignalRecord>();

    for (const item of stored) {
      if (!isRecord(item)) {
        continue;
      }

      const signal = sanitizeThreatSignal(item.signal);

      if (
        !signal ||
        typeof item.frameId !== "number" ||
        !Number.isInteger(item.frameId) ||
        item.frameId <= 0 ||
        typeof item.receivedAt !== "number" ||
        !Number.isFinite(item.receivedAt) ||
        item.receivedAt < 0 ||
        item.receivedAt > now + FUTURE_TIMESTAMP_TOLERANCE_MS ||
        now - item.receivedAt > SUBFRAME_SIGNAL_TTL_MS
      ) {
        continue;
      }

      const record: SubframeSignalRecord = {
        frameId: item.frameId,
        signal,
        receivedAt: item.receivedAt,
      };

      const keyForSignal = `${record.frameId}:${signal.type}`;
      const existing = latestByFrameAndType.get(keyForSignal);

      if (!existing || record.receivedAt > existing.receivedAt) {
        latestByFrameAndType.set(keyForSignal, record);
      }
    }

    const records = Array.from(latestByFrameAndType.values())
      .sort((a, b) => b.receivedAt - a.receivedAt)
      .slice(0, MAX_SUBFRAME_SIGNALS);

    // Repair malformed, expired, duplicate or oversized session data.
    const needsRepair =
      records.length !== stored.length ||
      stored.some((item, index) => {
        const record = records[index];
        return (
          !record ||
          !isRecord(item) ||
          item.frameId !== record.frameId ||
          item.receivedAt !== record.receivedAt
        );
      });

    if (needsRepair) {
      await chrome.storage.session.set({
        [key]: records,
      });
    }

    return records;
  } catch (error) {
    logger.debug(
      "Unable to retrieve subframe signals:",
      error
    );

    return [];
  }
}

async function saveSubframeSignals(
  tabId: number,
  records: SubframeSignalRecord[]
): Promise<void> {
  const boundedRecords = [...records]
    .sort((a, b) => b.receivedAt - a.receivedAt)
    .slice(0, MAX_SUBFRAME_SIGNALS);

  await chrome.storage.session.set({
    [getSubframeSignalsKey(tabId)]: boundedRecords,
  });
}

/**
 * Insert or refresh one signal category per frame.
 * Repeated evidence refreshes the TTL instead of remaining
 * close to expiry while the frame continues reporting it.
 */
function upsertSubframeSignal(
  records: SubframeSignalRecord[],
  frameId: number,
  signal: ThreatSignal,
  receivedAt: number
): SubframeSignalRecord[] {
  const next = records.filter(
    (record) =>
      !(
        record.frameId === frameId &&
        record.signal.type === signal.type
      )
  );

  next.push({
    frameId,
    signal,
    receivedAt,
  });

  return next;
}

function filterSubframeSignalsBySettings(
  records: SubframeSignalRecord[],
  settings: ClickShieldSettings
): SubframeSignalRecord[] {
  if (settings.clipboardProtection) {
    return records;
  }

  return records.filter(
    (record) => record.signal.type !== "CLIPBOARD_MANIPULATION"
  );
}

// ==========================================================
// COMBINED SIGNALS
// ==========================================================

function combineFrameSignals(
  topSignals: ThreatSignal[],
  subframeRecords: SubframeSignalRecord[]
): ThreatSignal[] {
  return [
    ...topSignals,
    ...subframeRecords.map((record) => record.signal),
  ];
}

// ==========================================================
// SCAN FINGERPRINT
// ==========================================================

function createStateFingerprint(
  state: TabState
): string {
  const signals = state.signals
    .map((signal) => ({
      type: signal.type,
      reason: signal.reason,
    }))
    .sort((a, b) => {
      const first = `${a.type}:${a.reason}`;
      const second = `${b.type}:${b.reason}`;
      return first.localeCompare(second);
    });

  return JSON.stringify({
    hostname: state.hostname,
    url: state.url,
    score: state.score,
    level: state.level,
    signals,
  });
}

// ==========================================================
// PAGE SCAN STATISTICS
// ==========================================================

/**
 * Count a URL once per browser session.
 *
 * Reserve the URL before incrementing and restore the previous
 * value if the counter update fails, allowing a later retry.
 */
async function incrementPageScanOnce(
  tabId: number,
  url: string
): Promise<void> {
  if (!url) {
    return;
  }

  const key = getLastPageKey(tabId);
  let previousUrl: unknown;

  try {
    const stored = await chrome.storage.session.get(key);
    previousUrl = stored[key];

    if (previousUrl === url) {
      return;
    }

    await chrome.storage.session.set({
      [key]: url,
    });

    try {
      await StorageManager.incrementStats("pagesScanned");
    } catch (error) {
      // Restore the previous URL so a later scan can retry.
      if (typeof previousUrl === "string") {
        await chrome.storage.session.set({
          [key]: previousUrl,
        });
      } else {
        await chrome.storage.session.remove(key);
      }

      throw error;
    }
  } catch (error) {
    logger.debug(
      "Unable to update page scan statistics:",
      error
    );
  }
}

// ==========================================================
// BADGE MANAGEMENT
// ==========================================================

async function updateTabBadge(
  tabId: number,
  score: number,
  level: RiskLevel
): Promise<void> {
  try {
    await chrome.action.setBadgeText({
      tabId,
      text: score > 0 ? String(score) : "",
    });

    await chrome.action.setBadgeBackgroundColor({
      tabId,
      color: BADGE_COLORS[level] || BADGE_COLORS.LOW,
    });
  } catch {
    // The tab may have closed or become unavailable.
  }
}

// ==========================================================
// NOTIFICATIONS
// ==========================================================

async function notifyCriticalThreat(
  hostname: string,
  settings: ClickShieldSettings
): Promise<void> {
  if (!settings.notificationsEnabled) {
    return;
  }

  try {
    await chrome.notifications.create({
      type: "basic",
      iconUrl: chrome.runtime.getURL("icons/icon128.png"),
      title: "ClickShield: High Risk Detected",
      message:
        `Suspicious activity detected on ${hostname}. ` +
        "Do not copy or execute untrusted commands.",
      priority: 2,
    });
  } catch (error) {
    logger.debug(
      "Unable to display ClickShield notification:",
      error
    );
  }
}

// ==========================================================
// THREAT HISTORY
// ==========================================================

async function recordThreatIfChanged(
  previousState: TabState | null,
  nextState: TabState,
  notifySettings?: ClickShieldSettings
): Promise<void> {
  if (nextState.score < RISK_THRESHOLDS.SUSPICIOUS) {
    return;
  }

  const previousFingerprint = previousState
    ? createStateFingerprint(previousState)
    : null;

  const nextFingerprint = createStateFingerprint(nextState);

  // Avoid writing identical threat history repeatedly.
  if (previousFingerprint === nextFingerprint) {
    return;
  }

  await StorageManager.addThreatRecord({
    id:
      `threat-${Date.now()}-` +
      Math.random().toString(36).substring(2, 7),
    hostname: nextState.hostname,
    url: nextState.url,
    timestamp: Date.now(),
    riskScore: nextState.score,
    riskLevel: nextState.level,
    signals: nextState.signals.map((signal) => signal.type),
    details: nextState.signals.map((signal) => signal.reason),
    // The service worker cannot prove that the page overlay was
    // displayed or that a clipboard operation was intercepted.
    // The display confirmation arrives separately. The history row is
    // created before that asynchronous confirmation is processed.
    action: "NONE",
  });

  const enteredCriticalRisk =
    nextState.score >= RISK_THRESHOLDS.CRITICAL &&
    (
      !previousState ||
      previousState.score < RISK_THRESHOLDS.CRITICAL ||
      previousState.hostname !== nextState.hostname ||
      previousState.url !== nextState.url
    );

  if (enteredCriticalRisk && notifySettings) {
    await notifyCriticalThreat(
      nextState.hostname,
      notifySettings
    );
  }
}

// ==========================================================
// TAB RESULT PERSISTENCE
// ==========================================================

async function persistTabResult(
  tabId: number,
  result: ScanResult,
  hostname: string,
  url: string,
  settings: ClickShieldSettings,
  notifySettings: ClickShieldSettings | undefined = settings
): Promise<TabState> {
  const previousState = await StorageManager.getTabState(tabId);

  const nextState: TabState = {
    score: result.score,
    level: result.level,
    signals: result.signals,
    hostname,
    url,
    timestamp: Date.now(),
    protectionEnabled: settings.protectionEnabled,
    isAllowlisted: false,
  };

  await StorageManager.setTabState(tabId, nextState);

  await updateTabBadge(
    tabId,
    result.score,
    result.level
  );

  await recordThreatIfChanged(
    previousState,
    nextState,
    notifySettings
  );

  return nextState;
}

// ==========================================================
// CLEAR TAB SCAN DATA
// ==========================================================

async function clearTabScanData(
  tabId: number
): Promise<void> {
  try {
    await chrome.storage.session.remove([
      getTopScanKey(tabId),
      getSubframeSignalsKey(tabId),
      getLastPageKey(tabId),
    ]);
  } catch (error) {
    logger.debug(
      "Unable to clear ClickShield tab scan data:",
      error
    );
  }
}

// ==========================================================
// TOP-FRAME SCAN PROCESSING
// ==========================================================

async function handleTopFrameScan(
  payload: unknown,
  sender: chrome.runtime.MessageSender
): Promise<Record<string, unknown>> {
  const tabId = sender.tab?.id;

  if (tabId === undefined) {
    return { success: false };
  }

  if (sender.frameId !== 0) {
    return {
      success: false,
      ignored: "subframe",
    };
  }

  if (!isRecord(payload)) {
    return {
      success: false,
      error: "Invalid scan payload",
    };
  }

  if (
    typeof payload.score !== "number" ||
    !Number.isFinite(payload.score) ||
    payload.score < 0 ||
    payload.score > 100 ||
    !Array.isArray(payload.signals)
  ) {
    return {
      success: false,
      error: "Invalid scan result",
    };
  }

  const settings = await StorageManager.getSettings();

  // Prefer the browser's current tab URL and accept a content
  // script URL only when it has the same origin.
  const browserUrl = sender.tab?.url || "";
  const url = resolveTopFrameUrl(payload.url, browserUrl);

  const browserHostname = getTabHostname(browserUrl);
  const hostname =
    browserHostname !== "unknown"
      ? browserHostname
      : getTabHostname(url) !== "unknown"
        ? getTabHostname(url)
        : normalizeHostnameFallback(payload.hostname);

  const effectiveHostname = hostname || "unknown";
  const isAllowed = await StorageManager.isAllowlisted(effectiveHostname);

  // --------------------------------------------------------
  // Protection disabled or website allowlisted
  // --------------------------------------------------------

  if (!settings.protectionEnabled || isAllowed) {
    await clearTabScanData(tabId);

    const emptyResult = calculateRisk([], {
      hostname: effectiveHostname,
      url,
    });

    const inactiveState: TabState = {
      score: 0,
      level: "LOW",
      signals: [],
      hostname: effectiveHostname,
      url,
      timestamp: Date.now(),
      protectionEnabled: settings.protectionEnabled,
      isAllowlisted: isAllowed,
    };

    await StorageManager.setTabState(tabId, inactiveState);
    await updateTabBadge(tabId, 0, "LOW");

    return {
      success: true,
      effectiveScore: emptyResult.score,
      effectiveLevel: "LOW",
    };
  }

  // --------------------------------------------------------
  // Sanitize top-frame signals
  // --------------------------------------------------------

  const topSignals = filterSignalsBySettings(
    sanitizeThreatSignals(payload.signals),
    settings.clipboardProtection
  );

  // --------------------------------------------------------
  // Store top-frame evidence separately
  // --------------------------------------------------------

  const snapshot: TopFrameSnapshot = {
    hostname: effectiveHostname,
    url,
    signals: topSignals,
    timestamp: Date.now(),
  };

  await saveTopFrameSnapshot(tabId, snapshot);

  // --------------------------------------------------------
  // Retrieve active subframe evidence
  // --------------------------------------------------------

  let subframeRecords = await getSubframeSignals(tabId);

  const filteredSubframeRecords = filterSubframeSignalsBySettings(
    subframeRecords,
    settings
  );

  if (filteredSubframeRecords.length !== subframeRecords.length) {
    subframeRecords = filteredSubframeRecords;
    await saveSubframeSignals(tabId, subframeRecords);
  }

  // --------------------------------------------------------
  // Combine and recalculate
  // --------------------------------------------------------

  const combinedSignals = combineFrameSignals(
    topSignals,
    subframeRecords
  );

  const result = calculateEffectiveRisk(
    combinedSignals,
    settings.detectionSensitivity,
    {
      hostname: effectiveHostname,
      url,
    }
  );

  // --------------------------------------------------------
  // Persist combined tab state
  // --------------------------------------------------------

  // No intervention is claimed here. The content script owns
  // overlay display and copy interception; neither is confirmed
  // by receiving a SCAN_RESULT message.
  await persistTabResult(
    tabId,
    result,
    effectiveHostname,
    url,
    settings,
    settings
  );

  // Count a page only once per distinct URL.
  await incrementPageScanOnce(tabId, url);

  logger.debug(
    "ClickShield top-frame scan completed:",
    {
      hostname: effectiveHostname,
      score: result.score,
      level: result.level,
      topFrameSignals: topSignals.length,
      subframeSignals: subframeRecords.length,
    }
  );

  return {
    success: true,
    effectiveScore: result.score,
    effectiveLevel: result.level,
    subframeSignals: subframeRecords.length,
  };
}

// ==========================================================
// SUBFRAME THREAT PROCESSING
// ==========================================================

async function handleSubframeThreat(
  payload: unknown,
  sender: chrome.runtime.MessageSender
): Promise<Record<string, unknown>> {
  const tabId = sender.tab?.id;

  if (tabId === undefined) {
    return { success: false };
  }

  // Only genuine child frames may submit this message.
  if (
    typeof sender.frameId !== "number" ||
    sender.frameId <= 0
  ) {
    return {
      success: false,
      error: "Invalid subframe sender",
    };
  }

  const signal = sanitizeThreatSignal(payload);

  if (!signal) {
    return {
      success: false,
      error: "Invalid threat signal",
    };
  }

  const settings = await StorageManager.getSettings();

  // --------------------------------------------------------
  // Protection configuration
  // --------------------------------------------------------

  if (!settings.protectionEnabled) {
    return {
      success: false,
      ignored: "protection_disabled",
    };
  }

  if (
    signal.type === "CLIPBOARD_MANIPULATION" &&
    !settings.clipboardProtection
  ) {
    return {
      success: false,
      ignored: "clipboard_protection_disabled",
    };
  }

  // --------------------------------------------------------
  // Determine top-level tab context
  // --------------------------------------------------------

  const topSnapshot = await getTopFrameSnapshot(tabId);
  const browserUrl = sender.tab?.url || "";

  const hostname =
    topSnapshot?.hostname || getTabHostname(browserUrl);

  const url =
    topSnapshot?.url || browserUrl;

  if (hostname === "unknown") {
    return {
      success: false,
      ignored: "unknown_tab_hostname",
    };
  }

  const isAllowed = await StorageManager.isAllowlisted(hostname);

  if (isAllowed) {
    return {
      success: false,
      ignored: "allowlisted",
    };
  }

  // --------------------------------------------------------
  // Retrieve and update subframe evidence
  // --------------------------------------------------------

  const records = await getSubframeSignals(tabId);
  const updatedRecords = upsertSubframeSignal(
    records,
    sender.frameId,
    signal,
    Date.now()
  );

  await saveSubframeSignals(tabId, updatedRecords);

  // --------------------------------------------------------
  // Combine evidence from both contexts
  // --------------------------------------------------------

  const topSignals = topSnapshot?.signals || [];
  const combinedSignals = combineFrameSignals(
    topSignals,
    updatedRecords
  );

  const result = calculateEffectiveRisk(
    combinedSignals,
    settings.detectionSensitivity,
    {
      hostname,
      url,
    }
  );

  // A subframe detection is not proof that a copy was
  // successfully intercepted or that an overlay was shown.
  await persistTabResult(
    tabId,
    result,
    hostname,
    url,
    settings,
    settings
  );

  logger.warn(
    "ClickShield subframe threat processed:",
    {
      hostname,
      frameId: sender.frameId,
      signalType: signal.type,
      score: result.score,
      level: result.level,
    }
  );

  return {
    success: true,
    effectiveScore: result.score,
    effectiveLevel: result.level,
    subframeSignals: updatedRecords.length,
  };
}

/**
 * Count a warning only when a top-frame content script confirms that the
 * warning overlay is currently visible for the active, qualifying tab state.
 */
async function handleInterventionShown(
  payload: unknown,
  sender: chrome.runtime.MessageSender
): Promise<Record<string, unknown>> {
  const tabId = sender.tab?.id;

  if (
    tabId === undefined ||
    !Number.isSafeInteger(tabId) ||
    tabId < 0 ||
    sender.frameId !== 0
  ) {
    return { success: false, error: "Intervention confirmation must come from a top-level tab frame." };
  }

  if (!isRecord(payload)) {
    return { success: false, error: "Invalid intervention confirmation payload." };
  }

  const interventionId = payload.interventionId;
  if (
    typeof interventionId !== "string" ||
    !INTERVENTION_ID_PATTERN.test(interventionId)
  ) {
    return { success: false, error: "Invalid intervention identifier." };
  }

  let browserTab: chrome.tabs.Tab;
  try {
    browserTab = await chrome.tabs.get(tabId);
  } catch {
    return { success: false, error: "The source tab is no longer available." };
  }

  const currentUrl = browserTab.url || sender.tab?.url || "";
  const currentHostname = getTabHostname(currentUrl);
  if (!currentUrl || currentHostname === "unknown") {
    return { success: false, error: "The source tab does not have a verifiable page URL." };
  }

  if (typeof sender.url === "string" && !urlsReferToSamePage(sender.url, currentUrl)) {
    return { success: false, error: "Intervention confirmation came from a stale document." };
  }

  const [storedState, currentSettings] = await Promise.all([
    StorageManager.getTabState(tabId),
    StorageManager.getSettings(),
  ]);

  if (!isRecord(storedState)) {
    return { success: false, error: "No current scan state exists for this tab." };
  }

  if (!currentSettings.protectionEnabled) {
    return { success: false, error: "Protection is currently disabled." };
  }

  if (
    typeof storedState.score !== "number" ||
    !Number.isFinite(storedState.score) ||
    storedState.score < RISK_THRESHOLDS.SUSPICIOUS ||
    storedState.score > 100 ||
    typeof storedState.hostname !== "string" ||
    storedState.hostname.toLowerCase() !== currentHostname.toLowerCase() ||
    typeof storedState.url !== "string" ||
    !urlsReferToSamePage(storedState.url, currentUrl) ||
    storedState.protectionEnabled !== true ||
    storedState.isAllowlisted === true
  ) {
    return { success: false, error: "The tab no longer has a qualifying active threat state." };
  }

  if (await StorageManager.isAllowlisted(currentHostname)) {
    return { success: false, error: "Interventions are not counted for allowlisted domains." };
  }

  const signals = sanitizeThreatSignals(storedState.signals);
  if (signals.length === 0) {
    return { success: false, error: "The current scan contains no valid threat signals." };
  }

  const verdict = correlateSignals(signals, {
    hostname: currentHostname,
    url: currentUrl,
  });
  const isActionableClickFix =
    verdict.isClickFixAttack &&
    storedState.score >= RISK_THRESHOLDS.SUSPICIOUS;
  const isCriticalThreat = storedState.score >= RISK_THRESHOLDS.CRITICAL;

  if (!isActionableClickFix && !isCriticalThreat) {
    return { success: false, error: "The current scan does not qualify for an intervention." };
  }

  const receipts = await loadInterventionReceipts();
  if (receipts.some((receipt) => receipt.id === interventionId)) {
    return { success: true, counted: false, duplicate: true };
  }

  // Reserve the ID before incrementing so redelivered messages cannot count
  // the same displayed warning twice. Roll the reservation back on failure.
  const nextReceipts = [
    ...receipts,
    { id: interventionId, tabId, recordedAt: Date.now() },
  ].slice(-MAX_INTERVENTION_RECEIPTS);

  await saveInterventionReceipts(nextReceipts);

  try {
    await StorageManager.incrementStats("interventions");
  } catch (error) {
    await saveInterventionReceipts(receipts).catch((rollbackError) => {
      logger.error("Failed to roll back an intervention receipt:", rollbackError);
    });
    throw error;
  }

  logger.info("ClickShield warning intervention recorded:", {
    tabId,
    hostname: currentHostname,
    score: storedState.score,
    interventionId,
  });

  return { success: true, counted: true, duplicate: false };
}

// ==========================================================
// FRAME NAVIGATION HANDLING
// ==========================================================

/**
 * Remove evidence belonging to a subframe when that frame
 * navigates. A reused frame ID must not carry evidence from
 * the previous document into the new document.
 */
async function handleSubframeNavigation(
  tabId: number,
  frameId: number
): Promise<void> {
  const records = await getSubframeSignals(tabId);
  const remaining = records.filter(
    (record) => record.frameId !== frameId
  );

  if (remaining.length === records.length) {
    return;
  }

  await saveSubframeSignals(tabId, remaining);

  const snapshot = await getTopFrameSnapshot(tabId);

  if (!snapshot) {
    return;
  }

  const settings = await StorageManager.getSettings();
  const isAllowed = await StorageManager.isAllowlisted(
    snapshot.hostname
  );

  if (!settings.protectionEnabled || isAllowed) {
    await clearTabScanData(tabId);

    const emptyState: TabState = {
      score: 0,
      level: "LOW",
      signals: [],
      hostname: snapshot.hostname,
      url: snapshot.url,
      timestamp: Date.now(),
      protectionEnabled: settings.protectionEnabled,
      isAllowlisted: isAllowed,
    };

    await StorageManager.setTabState(tabId, emptyState);
    await updateTabBadge(tabId, 0, "LOW");
    return;
  }

  const activeRecords = filterSubframeSignalsBySettings(
    remaining,
    settings
  );

  const result = calculateEffectiveRisk(
    combineFrameSignals(snapshot.signals, activeRecords),
    settings.detectionSensitivity,
    {
      hostname: snapshot.hostname,
      url: snapshot.url,
    }
  );

  // A frame navigation should not itself trigger a new
  // critical notification.
  await persistTabResult(
    tabId,
    result,
    snapshot.hostname,
    snapshot.url,
    settings,
    undefined
  );
}

// ==========================================================
// EXTENSION LIFECYCLE
// ==========================================================

chrome.runtime.onInstalled.addListener((details) => {
  logger.info(
    "ClickShield extension installed/updated:",
    details.reason
  );

  void StorageManager.initializeDefaults().catch((error) => {
    logger.error(
      "ClickShield installation initialization failed:",
      error
    );
  });
});

chrome.runtime.onStartup.addListener(() => {
  void StorageManager.initializeDefaults()
    .then(() => {
      logger.info(
        "ClickShield browser startup initialization completed."
      );
    })
    .catch((error) => {
      logger.error(
        "ClickShield startup initialization failed:",
        error
      );
    });
});

// ==========================================================
// MESSAGE HANDLER
// ==========================================================

async function handleIncomingMessage(
  message: unknown,
  sender: chrome.runtime.MessageSender
): Promise<unknown> {
  if (!isRecord(message) || typeof message.type !== "string") {
    return {
      error: "Invalid message payload",
    };
  }

  const type = message.type;
  const payload = message.payload;

  switch (type) {
    // ------------------------------------------------------
    // 1. TOP-FRAME SCAN
    // ------------------------------------------------------

    case "SCAN_RESULT": {
      const tabId = sender.tab?.id;

      if (tabId === undefined) {
        return { success: false };
      }

      return enqueueTabOperation(
        tabId,
        () => handleTopFrameScan(payload, sender)
      );
    }

    // ------------------------------------------------------
    // 2. SUBFRAME THREAT
    // ------------------------------------------------------

    case "SUBFRAME_THREAT": {
      const tabId = sender.tab?.id;

      if (tabId === undefined) {
        return { success: false };
      }

      return enqueueTabOperation(
        tabId,
        () => handleSubframeThreat(payload, sender)
      );
    }

    // ------------------------------------------------------
    // 3. CONFIRMED WARNING OVERLAY
    // ------------------------------------------------------

    case "INTERVENTION_SHOWN": {
      const tabId = sender.tab?.id;
      if (tabId === undefined) {
        return { success: false, error: "Intervention confirmation requires a browser tab." };
      }

      return enqueueTabOperation(tabId, () =>
        enqueueInterventionOperation(() =>
          handleInterventionShown(payload, sender)
        )
      );
    }

    // ------------------------------------------------------
    // 4. TAB STATE
    // ------------------------------------------------------

    case "GET_TAB_STATE": {
      const tabId = isRecord(payload) ? payload.tabId : undefined;

      if (
        typeof tabId !== "number" ||
        !Number.isSafeInteger(tabId) ||
        tabId < 0
      ) {
        return { state: null };
      }

      const state = await StorageManager.getTabState(tabId);
      return { state };
    }

    // ------------------------------------------------------
    // 5. SETTINGS
    // ------------------------------------------------------

    case "GET_SETTINGS": {
      const settings = await StorageManager.getSettings();
      return { settings };
    }

    case "UPDATE_SETTINGS": {
      if (!isRecord(payload)) {
        return {
          error: "Invalid settings payload",
        };
      }

      const updated = await StorageManager.updateSettings(
        payload as Partial<ClickShieldSettings>
      );

      return {
        settings: updated,
      };
    }

    // ------------------------------------------------------
    // 6. STATISTICS
    // ------------------------------------------------------

    case "GET_STATISTICS": {
      const stats = await StorageManager.getStatistics();
      return { stats };
    }

    // ------------------------------------------------------
    // 7. THREAT HISTORY
    // ------------------------------------------------------

    case "GET_THREAT_HISTORY": {
      const history = await StorageManager.getThreatHistory();
      return { history };
    }

    case "CLEAR_HISTORY": {
      await StorageManager.clearThreatHistory();
      return { success: true };
    }

    // ------------------------------------------------------
    // 8. ALLOWLIST
    // ------------------------------------------------------

    case "GET_ALLOWLIST": {
      const allowlist = await StorageManager.getAllowlist();
      return { allowlist };
    }

    case "ALLOWLIST_ADD": {
      const hostname = isRecord(payload)
        ? payload.hostname
        : undefined;

      if (
        typeof hostname !== "string" ||
        !hostname.trim()
      ) {
        return {
          error: "Invalid hostname",
        };
      }

      const list = await StorageManager.addToAllowlist(hostname);
      return { allowlist: list };
    }

    case "ALLOWLIST_REMOVE": {
      const hostname = isRecord(payload)
        ? payload.hostname
        : undefined;

      if (
        typeof hostname !== "string" ||
        !hostname.trim()
      ) {
        return {
          error: "Invalid hostname",
        };
      }

      const list = await StorageManager.removeFromAllowlist(hostname);
      return { allowlist: list };
    }

    default:
      return {
        error: "Unknown message type",
      };
  }
}

// ==========================================================
// MESSAGE LISTENER
// ==========================================================

chrome.runtime.onMessage.addListener(
  (message, sender, sendResponse) => {
    // Reject external messages.
    if (sender.id !== chrome.runtime.id) {
      return false;
    }

    handleIncomingMessage(message, sender)
      .then((response) => {
        sendResponse(response);
      })
      .catch((error: unknown) => {
        logger.error(
          "ClickShield message handling failed:",
          error
        );

        sendResponse({
          error:
            error instanceof Error
              ? error.message
              : "Unknown message handling error",
        });
      });

    return true;
  }
);

// ==========================================================
// TAB CLEANUP
// ==========================================================

chrome.tabs.onRemoved.addListener((tabId) => {
  void enqueueTabOperation(tabId, async () => {
    await Promise.all([
      StorageManager.clearTabState(tabId),
      clearTabScanData(tabId),
    ]);
  }).catch((error) => {
    logger.debug(
      `Unable to clean ClickShield data for closed tab ${tabId}:`,
      error
    );
  });
});

// ==========================================================
// NAVIGATION HANDLING
// ==========================================================

chrome.webNavigation?.onCommitted?.addListener((details) => {
  void enqueueTabOperation(details.tabId, async () => {
    if (details.frameId === 0) {
      // Clear the previous page's badge.
      await chrome.action.setBadgeText({
        tabId: details.tabId,
        text: "",
      }).catch(() => undefined);

      // Clear previous page's session state and frame evidence.
      await Promise.all([
        StorageManager.clearTabState(details.tabId),
        clearTabScanData(details.tabId),
      ]);

      return;
    }

    // A child frame navigation invalidates evidence from its
    // previous document, even when Chrome reuses the frame ID.
    await handleSubframeNavigation(
      details.tabId,
      details.frameId
    );
  }).catch((error) => {
    logger.debug(
      "ClickShield navigation cleanup failed:",
      error
    );
  });
});
