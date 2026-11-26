
import type { ThreatSignal } from "../shared/types/signal";

import { logger } from "../shared/utils/logger";
import { DEFAULT_SETTINGS } from "../shared/constants/default-settings";

// ==========================================================
// TYPES
// ==========================================================

export interface ClipboardGuardCallbacks {
  onThreatDetected: (signal: ThreatSignal) => void;
  onIntervention?: (reason: string) => void;
}

interface SuspiciousCopyDetail {
  timestamp?: number;
  hasCommandSyntax?: boolean;
  snippet?: string;
}

// ==========================================================
// CONSTANTS
// ==========================================================

const SETTINGS_KEY = "clickshield_settings";
const ALLOWLIST_KEY = "clickshield_allowlist";

const SUSPICIOUS_COPY_EVENT =
  "clickshield:suspicious-copy";

const MAX_SELECTED_TEXT_LENGTH = 20000;
const MAX_REASON_LENGTH = 300;
const MAX_ALLOWLIST_ENTRIES = 500;

const PROGRAMMATIC_EVENT_MAX_AGE_MS = 30000;
const REPORT_COOLDOWN_MS = 2000;

// ==========================================================
// COMMAND DETECTION
// ==========================================================

const SUSPICIOUS_COMMAND_REGEX =
  /\b(?:powershell(?:\.exe)?|pwsh|cmd(?:\.exe)?|mshta(?:\.exe)?|bitsadmin(?:\.exe)?|certutil(?:\.exe)?|regsvr32(?:\.exe)?|rundll32(?:\.exe)?|wscript(?:\.exe)?|cscript(?:\.exe)?|invoke-expression|invoke-webrequest|downloadstring|start-process|osascript)\b|\b(?:irm|iex)\s+|\b(?:curl|wget)\b[^\r\n]{0,500}\|\s*(?:iex|invoke-expression|sh|bash|powershell|pwsh)\b|\b(?:bash|sh)\s+-c\b|\[convert\]::frombase64string/i;

const BLATANT_ATTACK_REGEX =
  /\b(?:powershell|pwsh)\b[^\r\n]{0,300}(?:-w(?:indowstyle)?\s+hidden|-e(?:nc(?:odedcommand)?)?\b|-nop\b)|\b(?:irm|iex)\b[^\r\n]{0,300}https?:\/\/|\bcertutil\b[^\r\n]{0,300}-urlcache|\bmshta\b[^\r\n]{0,200}https?:\/\/|\b(?:curl|wget)\b[^\r\n]{0,300}\|\s*(?:ba)?sh\b|\b(?:curl|wget)\b[^\r\n]{0,300}\|\s*(?:iex|invoke-expression)\b/i;

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

// ==========================================================
// CLIPBOARD GUARD
// ==========================================================

export class ClipboardGuard {
  private static isInitialized = false;

  private static configurationReady = false;

  private static protectionEnabled = false;

  private static clipboardProtectionEnabled = false;

  private static allowlist: string[] = [];

  private static configurationRevision = 0;

  private static lastThreatReportAt = 0;

  private static callbacks: ClipboardGuardCallbacks | null =
    null;

  // ========================================================
  // INITIALIZATION
  // ========================================================

  static initialize(
    callbacks: ClipboardGuardCallbacks
  ): void {
    this.callbacks = callbacks;

    if (this.isInitialized) {
      return;
    }

    try {
      // Register the storage listener before loading the
      // initial configuration to avoid missing updates.
      if (typeof chrome !== "undefined" && chrome.storage?.onChanged) {
        chrome.storage.onChanged.addListener(
          (changes, areaName) => {
            this.handleStorageChanges(changes, areaName);
          }
        );
      }

      // Listen for programmatic clipboard notifications
      // from the MAIN-world clipboard monitor.
      window.addEventListener(
        SUSPICIOUS_COPY_EVENT,
        (event: Event) => {
          this.handleProgrammaticClipboardThreat(event);
        }
      );

      // Listen during window capture phase.
      //
      // This executes before the document-level capture
      // listener installed by CopyInterceptor.
      window.addEventListener(
        "copy",
        (event: ClipboardEvent) => {
          this.handleNativeCopy(event);
        },
        true
      );

      this.isInitialized = true;

      void this.loadConfiguration();

      logger.info(
        "ClickShield ClipboardGuard initialized."
      );
    } catch (error) {
      logger.error(
        "Failed to initialize ClickShield ClipboardGuard:",
        error
      );

      this.configurationReady = false;
    }
  }

  // ========================================================
  // CONFIGURATION
  // ========================================================

  private static async loadConfiguration(): Promise<void> {
    const revision = this.configurationRevision;

    if (typeof chrome === "undefined" || !chrome.storage?.local) {
      this.protectionEnabled = true;
      this.clipboardProtectionEnabled = true;
      this.allowlist = [];
      this.configurationReady = true;
      return;
    }

    try {
      const stored = await chrome.storage.local.get([
        SETTINGS_KEY,
        ALLOWLIST_KEY,
      ]);

      // Do not overwrite newer storage updates.
      if (revision !== this.configurationRevision) {
        return;
      }

      this.applySettings(stored[SETTINGS_KEY]);

      this.applyAllowlist(stored[ALLOWLIST_KEY]);

      this.configurationReady = true;

      logger.info(
        "ClickShield clipboard configuration loaded."
      );
    } catch (error) {
      if (revision !== this.configurationRevision) {
        return;
      }

      logger.warn(
        "Unable to load clipboard protection settings:",
        error
      );

      // Fail closed when configuration cannot be established.
      this.protectionEnabled = false;
      this.clipboardProtectionEnabled = false;
      this.allowlist = [];

      this.configurationReady = true;
    }
  }

  private static handleStorageChanges(
    changes: {
      [key: string]: chrome.storage.StorageChange;
    },
    areaName: string
  ): void {
    if (areaName !== "local") {
      return;
    }

    if (
      !changes[SETTINGS_KEY] &&
      !changes[ALLOWLIST_KEY]
    ) {
      return;
    }

    this.configurationRevision++;

    if (changes[SETTINGS_KEY]) {
      this.applySettings(
        changes[SETTINGS_KEY].newValue
      );
    }

    if (changes[ALLOWLIST_KEY]) {
      this.applyAllowlist(
        changes[ALLOWLIST_KEY].newValue
      );
    }

    this.configurationReady = true;

    logger.debug(
      "ClickShield clipboard settings synchronized from storage."
    );
  }

  // ========================================================
  // SETTINGS NORMALIZATION
  // ========================================================

  private static applySettings(value: unknown): void {
    const settings = isRecord(value) ? value : {};

    this.protectionEnabled =
      typeof settings.protectionEnabled === "boolean"
        ? settings.protectionEnabled
        : DEFAULT_SETTINGS.protectionEnabled;

    this.clipboardProtectionEnabled =
      typeof settings.clipboardProtection === "boolean"
        ? settings.clipboardProtection
        : DEFAULT_SETTINGS.clipboardProtection;
  }

  // ========================================================
  // ALLOWLIST NORMALIZATION
  // ========================================================

  private static normalizeDomain(
    entry: string
  ): string | null {
    let candidate = entry.trim().toLowerCase();

    if (!candidate || candidate.length > 2048) {
      return null;
    }

    if (candidate.startsWith("*.")) {
      candidate = candidate.slice(2);
    }

    if (candidate.includes("*")) {
      return null;
    }

    try {
      const hasScheme =
        /^[a-z][a-z0-9+.-]*:\/\//i.test(candidate);

      if (
        hasScheme &&
        !/^https?:\/\//i.test(candidate)
      ) {
        return null;
      }

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
        (url.protocol !== "http:" &&
          url.protocol !== "https:") ||
        url.username ||
        url.password ||
        url.port ||
        url.pathname !== "/" ||
        url.search ||
        url.hash
      ) {
        return null;
      }

      return (
        url.hostname
          .toLowerCase()
          .replace(/\.$/, "") || null
      );
    } catch {
      return null;
    }
  }

  private static applyAllowlist(value: unknown): void {
    if (!Array.isArray(value)) {
      this.allowlist = [];
      return;
    }

    const normalized = new Set<string>();

    for (
      const entry of value.slice(0, MAX_ALLOWLIST_ENTRIES)
    ) {
      if (typeof entry !== "string") {
        continue;
      }

      const hostname = this.normalizeDomain(entry);

      if (hostname) {
        normalized.add(hostname);
      }
    }

    this.allowlist = Array.from(normalized);
  }

  // ========================================================
  // PROTECTION STATE
  // ========================================================

  private static isProtectionActive(): boolean {
    if (
      !this.configurationReady ||
      !this.protectionEnabled ||
      !this.clipboardProtectionEnabled
    ) {
      return false;
    }

    try {
      const hostname = (
        window.location.hostname || "local-file"
      )
        .toLowerCase()
        .replace(/\.$/, "");

      if (!hostname) {
        return false;
      }

      const isAllowlisted = this.allowlist.some(
        (domain) =>
          hostname === domain ||
          hostname.endsWith(`.${domain}`)
      );

      return !isAllowlisted;
    } catch {
      return false;
    }
  }

  // ========================================================
  // SENSITIVE CONTENT VALIDATION
  // ========================================================

  private static isSensitiveInput(
    input: HTMLInputElement | HTMLTextAreaElement
  ): boolean {
    if (
      input instanceof HTMLInputElement &&
      (
        input.type === "password" ||
        input.type === "hidden"
      )
    ) {
      return true;
    }

    const autocomplete = (
      input.getAttribute("autocomplete") || ""
    ).toLowerCase();

    return /(?:^|\s)(?:current-password|new-password|one-time-code|cc-number|cc-csc|cc-exp|cc-exp-month|cc-exp-year)(?:\s|$)/.test(
      autocomplete
    );
  }

  private static isInsideEditableContent(
    element: Element | null
  ): boolean {
    if (!element) {
      return false;
    }

    try {
      return (
        element instanceof HTMLElement &&
        element.isContentEditable
      );
    } catch {
      return true;
    }
  }

  // ========================================================
  // SELECTED TEXT EXTRACTION
  // ========================================================

  private static getSelectedText(
    event: ClipboardEvent
  ): string {
    try {
      // ----------------------------------------------------
      // 1. Document selection
      // ----------------------------------------------------

      const selection = document.getSelection();

      if (
        selection &&
        !selection.isCollapsed &&
        selection.toString()
      ) {
        const anchorElement =
          selection.anchorNode instanceof Element
            ? selection.anchorNode
            : selection.anchorNode?.parentElement || null;

        const focusElement =
          selection.focusNode instanceof Element
            ? selection.focusNode
            : selection.focusNode?.parentElement || null;

        // Do not inspect editable user content.
        if (
          this.isInsideEditableContent(anchorElement) ||
          this.isInsideEditableContent(focusElement)
        ) {
          return "";
        }

        return selection
          .toString()
          .slice(0, MAX_SELECTED_TEXT_LENGTH);
      }

      // ----------------------------------------------------
      // 2. Input and textarea selection
      // ----------------------------------------------------

      const eventPath =
        typeof event.composedPath === "function"
          ? event.composedPath()
          : [];

      const eventInput = eventPath.find(
        (
          item
        ): item is HTMLInputElement | HTMLTextAreaElement =>
          item instanceof HTMLInputElement ||
          item instanceof HTMLTextAreaElement
      );

      const activeElement =
        eventInput ||
        (
          document.activeElement instanceof HTMLInputElement ||
          document.activeElement instanceof HTMLTextAreaElement
            ? document.activeElement
            : null
        );

      if (!activeElement) {
        return "";
      }

      if (this.isSensitiveInput(activeElement)) {
        return "";
      }

      if (
        this.isInsideEditableContent(activeElement)
      ) {
        return "";
      }

      const start = activeElement.selectionStart;

      const end = activeElement.selectionEnd;

      if (
        start === null ||
        end === null ||
        end <= start
      ) {
        return "";
      }

      return activeElement.value.slice(
        start,
        Math.min(
          end,
          start + MAX_SELECTED_TEXT_LENGTH
        )
      );
    } catch {
      return "";
    }
  }

  // ========================================================
  // EVENT TARGET CONTEXT
  // ========================================================

  private static getEventElement(
    event: Event
  ): Element | null {
    try {
      const path = event.composedPath();

      for (const item of path) {
        if (item instanceof Element) {
          return item;
        }
      }

      const target = event.target;

      if (target instanceof Element) {
        return target;
      }

      if (target instanceof Node) {
        return target.parentElement;
      }

      return null;
    } catch {
      return null;
    }
  }

  private static isDeceptiveContext(
    event: ClipboardEvent
  ): boolean {
    try {
      const target = this.getEventElement(event);

      const interactiveElement = target?.closest(
        "button, a, [role='button']"
      );

      if (!interactiveElement) {
        return false;
      }

      const context = [
        interactiveElement.textContent || "",
        interactiveElement.getAttribute("aria-label") || "",
        interactiveElement.getAttribute("title") || "",
      ]
        .join(" ")
        .slice(0, 1000);

      return /verify|human|solve|captcha|turnstile|recaptcha|fix|update|download|code|command|continue/i.test(
        context
      );
    } catch {
      return false;
    }
  }

  // ========================================================
  // COMMAND CLASSIFICATION
  // ========================================================

  private static isSuspiciousCommand(
    text: string
  ): boolean {
    return SUSPICIOUS_COMMAND_REGEX.test(
      text.slice(0, MAX_SELECTED_TEXT_LENGTH)
    );
  }

  private static isBlatantAttack(
    text: string
  ): boolean {
    return BLATANT_ATTACK_REGEX.test(
      text.slice(0, MAX_SELECTED_TEXT_LENGTH)
    );
  }

  // ========================================================
  // PROGRAMMATIC CLIPBOARD THREATS
  // ========================================================

  /**
   * Process notifications from the MAIN-world monitor.
   *
   * CustomEvents are page-visible and can be forged by page
   * scripts. These reports are therefore treated as
   * untrusted, low-confidence evidence, not proof of an attack.
   *
   * Raw clipboard contents are never forwarded.
   */
  private static handleProgrammaticClipboardThreat(
    event: Event
  ): void {
    if (!this.isProtectionActive()) {
      return;
    }

    try {
      if (!(event instanceof CustomEvent)) {
        return;
      }

      const detail = event.detail as
        | SuspiciousCopyDetail
        | undefined;

      if (
        !detail ||
        detail.hasCommandSyntax !== true
      ) {
        return;
      }

      if (
        typeof detail.timestamp !== "number" ||
        !Number.isFinite(detail.timestamp) ||
        Math.abs(Date.now() - detail.timestamp) >
          PROGRAMMATIC_EVENT_MAX_AGE_MS
      ) {
        return;
      }

      logger.warn(
        "Suspicious programmatic clipboard operation detected."
      );

      const safeSnippet =
        typeof detail.snippet === "string" && detail.snippet.trim()
          ? detail.snippet.trim().slice(0, 100)
          : undefined;

      this.reportThreat(
        "Webpage script attempted a programmatic clipboard write containing suspicious system command syntax.",
        "Programmatic clipboard command detected.",
        safeSnippet
      );
    } catch (error) {
      logger.debug(
        "Error processing programmatic clipboard event:",
        error
      );
    }
  }

  // ========================================================
  // NATIVE COPY EVENT DETECTION
  // ========================================================

  private static handleNativeCopy(
    event: ClipboardEvent
  ): void {
    if (
      !event.isTrusted ||
      !this.isProtectionActive()
    ) {
      return;
    }

    try {
      const selection = this.getSelectedText(event);

      if (!selection) {
        return;
      }

      const hasCommandSyntax =
        this.isSuspiciousCommand(selection);

      if (!hasCommandSyntax) {
        return;
      }

      const isBlatantAttack =
        this.isBlatantAttack(selection);

      const isDeceptive =
        this.isDeceptiveContext(event);

      if (!isBlatantAttack && !isDeceptive) {
        return;
      }

      logger.warn(
        "Suspicious clipboard copy operation detected."
      );

      // Detection and reporting only.
      // CopyInterceptor is responsible for blocking
      // suspicious native copy operations.

      this.reportThreat(
        "User interaction triggered clipboard copying of executable command syntax.",
        "Verification-linked clipboard command detected."
      );
    } catch (error) {
      logger.debug(
        "Error in native clipboard copy monitoring:",
        error
      );
    }
  }

  // ========================================================
  // THREAT REPORTING
  // ========================================================

  private static reportThreat(
    reason: string,
    interventionReason: string,
    snippet?: string
  ): void {
    const now = Date.now();

    // Prevent repeated event spam from creating excessive
    // identical reports.
    if (
      now - this.lastThreatReportAt <
      REPORT_COOLDOWN_MS
    ) {
      return;
    }

    this.lastThreatReportAt = now;

    const signal: ThreatSignal = {
      type: "CLIPBOARD_MANIPULATION",
      reason: reason.slice(0, MAX_REASON_LENGTH),
      ...(snippet ? { snippet } : {}),
    };

    try {
      this.callbacks?.onThreatDetected(signal);

      this.callbacks?.onIntervention?.(
        interventionReason
      );
    } catch (error) {
      logger.debug(
        "Unable to report clipboard threat:",
        error
      );
    }
  }
}
