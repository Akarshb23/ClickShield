
import { logger } from "../shared/utils/logger";
import { DEFAULT_SETTINGS } from "../shared/constants/default-settings";

import type { ClickShieldSettings } from "../shared/types/settings";

// ==========================================================
// TYPES
// ==========================================================

export interface CopyInterventionResult {
  wasBlocked: boolean;
  reason?: string;
}

interface CopyCallbacks {
  onIntervention: (reason: string) => void;
}

// ==========================================================
// CONSTANTS
// ==========================================================

const SETTINGS_KEY = "clickshield_settings";
const ALLOWLIST_KEY = "clickshield_allowlist";

const MAX_SELECTED_TEXT_LENGTH = 20000;

const MAX_CONTEXT_LENGTH = 1000;

/**
 * Recognizes potentially dangerous command-line content.
 *
 * This is a broad detection pattern. A match alone does not
 * automatically block copying; deceptive context or a
 * more specific attack pattern is also required.
 */
const DANGEROUS_COMMAND_REGEX =
  /\b(?:powershell(?:\.exe)?|pwsh|cmd(?:\.exe)?|mshta(?:\.exe)?|bitsadmin(?:\.exe)?|certutil(?:\.exe)?|regsvr32(?:\.exe)?|rundll32(?:\.exe)?|wscript(?:\.exe)?|cscript(?:\.exe)?|invoke-expression|invoke-webrequest|downloadstring|start-process|osascript)\b|\b(?:irm|iex)\s+|\b(?:curl|wget)\b[^\r\n]{0,500}\|\s*(?:iex|invoke-expression|sh|bash|powershell|pwsh)\b|\b(?:bash|sh)\s+-c\b|\[convert\]::frombase64string/i;

/**
 * Recognizes more specific attack-like command combinations.
 *
 * These patterns are used as stronger evidence when deciding
 * whether a clipboard operation should be blocked.
 */
const BLATANT_ATTACK_REGEX =
  /\b(?:powershell|pwsh)\b[^\r\n]{0,300}(?:-w(?:indowstyle)?\s+hidden|-e(?:nc(?:odedcommand)?)?\b|-nop\b)|\b(?:irm|iex)\b[^\r\n]{0,300}https?:\/\/|\bcertutil\b[^\r\n]{0,300}-urlcache|\bmshta\b[^\r\n]{0,200}https?:\/\/|\b(?:curl|wget)\b[^\r\n]{0,300}\|\s*(?:ba)?sh\b|\b(?:curl|wget)\b[^\r\n]{0,300}\|\s*(?:iex|invoke-expression)\b/i;

// ==========================================================
// COPY INTERCEPTOR
// ==========================================================

export class CopyInterceptor {
  private static isArmed = false;

  private static configurationReady = false;

  private static protectionEnabled = false;

  private static clipboardProtectionEnabled = false;

  private static allowlist: string[] = [];

  /**
   * Incremented whenever a storage update is received.
   * Prevents older asynchronous configuration loads from
   * overwriting newer settings.
   */
  private static configurationRevision = 0;

  private static callbacks: CopyCallbacks | null = null;

  // ========================================================
  // INITIALIZATION
  // ========================================================

  /**
   * Initialize the interceptor.
   *
   * The listener is installed only once, but settings
   * continue to update dynamically through Chrome Storage.
   */
  static arm(callbacks: CopyCallbacks): void {
    this.callbacks = callbacks;

    if (this.isArmed) {
      return;
    }

    try {
      // Register storage listener before requesting initial
      // settings to avoid missing configuration changes.
      chrome.storage.onChanged.addListener(
        (changes, areaName) => {
          this.handleStorageChanges(changes, areaName);
        }
      );

      // Capture-phase listener runs before ordinary
      // page-level copy event handlers.
      document.addEventListener(
        "copy",
        (event: ClipboardEvent) => {
          this.handleCopyEvent(event);
        },
        true
      );

      this.isArmed = true;

      void this.loadConfiguration();

      logger.info(
        "ClickShield CopyInterceptor armed."
      );
    } catch (error) {
      logger.error(
        "Failed to arm ClickShield CopyInterceptor:",
        error
      );
    }
  }

  // ========================================================
  // CONFIGURATION
  // ========================================================

  private static async loadConfiguration(): Promise<void> {
    const revision = this.configurationRevision;

    try {
      const stored = await chrome.storage.local.get([
        SETTINGS_KEY,
        ALLOWLIST_KEY,
      ]);

      // Do not overwrite newer settings received while loading.
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
      // A failed older request must not override newer settings.
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

    logger.info(
      "ClickShield clipboard protection settings updated."
    );
  }

  private static applySettings(value: unknown): void {
    const settings =
      value &&
      typeof value === "object" &&
      !Array.isArray(value)
        ? (value as Partial<ClickShieldSettings>)
        : {};

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

  /**
   * Normalize an allowlist entry to a hostname.
   *
   * Invalid URLs, credentials, ports and URL paths
   * are rejected.
   */
  private static normalizeDomain(
    entry: string
  ): string | null {
    let candidate = entry.trim().toLowerCase();

    if (!candidate || candidate.length > 2048) {
      return null;
    }

    // Support wildcard entries safely.
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

    for (const entry of value.slice(0, 500)) {
      if (typeof entry !== "string") {
        continue;
      }

      const domain = this.normalizeDomain(entry);

      if (domain) {
        normalized.add(domain);
      }
    }

    this.allowlist = Array.from(normalized);
  }

  // ========================================================
  // PROTECTION STATE
  // ========================================================

  private static isProtectionActive(): boolean {
    if (!this.configurationReady) {
      return false;
    }

    if (
      !this.protectionEnabled ||
      !this.clipboardProtectionEnabled
    ) {
      return false;
    }

    try {
      const hostname = window.location.hostname
        .toLowerCase()
        .replace(/\.$/, "");

      if (!hostname) {
        return false;
      }

      const isAllowlisted = this.allowlist.some(
        (domain) => {
          return (
            hostname === domain ||
            hostname.endsWith(`.${domain}`)
          );
        }
      );

      return !isAllowlisted;
    } catch {
      return false;
    }
  }

  // ========================================================
  // EDITABLE CONTENT VALIDATION
  // ========================================================

  /**
   * Determine whether a selection belongs to editable
   * user-controlled content.
   *
   * Such content is excluded from clipboard inspection.
   */
  private static isInsideEditableContent(
    element: Element | null
  ): boolean {
    let current = element;

    while (current) {
      if (
        current instanceof HTMLElement &&
        current.isContentEditable
      ) {
        return true;
      }

      if (current.parentElement) {
        current = current.parentElement;
        continue;
      }

      const root = current.getRootNode();

      if (root instanceof ShadowRoot) {
        current = root.host;
        continue;
      }

      break;
    }

    return false;
  }

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

  // ========================================================
  // SELECTION EXTRACTION
  // ========================================================

  /**
   * Obtain selected text without reading password fields,
   * sensitive autocomplete fields or contenteditable content.
   *
   * Only the selected portion of an eligible input or
   * textarea is inspected, never its complete value.
   */
  private static getSelectedText(
    event: ClipboardEvent
  ): string {
    try {
      // ----------------------------------------------------
      // 1. Standard document selection
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

        // Do not inspect user-authored editable content.
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
      // 2. Input / textarea selection
      // ----------------------------------------------------

      const eventPath =
        typeof event.composedPath === "function"
          ? event.composedPath()
          : [];

      const pathElement = eventPath.find(
        (item): item is HTMLInputElement | HTMLTextAreaElement => {
          return (
            item instanceof HTMLInputElement ||
            item instanceof HTMLTextAreaElement
          );
        }
      );

      const activeElement =
        pathElement ||
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
        Math.min(end, start + MAX_SELECTED_TEXT_LENGTH)
      );
    } catch {
      return "";
    }
  }

  // ========================================================
  // THREAT DETECTION
  // ========================================================

  private static isDangerousPayload(
    text: string
  ): boolean {
    if (!text.trim()) {
      return false;
    }

    const candidate = text.slice(
      0,
      MAX_SELECTED_TEXT_LENGTH
    );

    return (
      DANGEROUS_COMMAND_REGEX.test(candidate) ||
      BLATANT_ATTACK_REGEX.test(candidate)
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
  // DECEPTIVE CONTEXT
  // ========================================================

  private static isDeceptiveContext(
    target: EventTarget | null
  ): boolean {
    try {
      const element =
        target instanceof Element ? target : null;

      if (!element) {
        return false;
      }

      const interactiveElement = element.closest(
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
        .slice(0, MAX_CONTEXT_LENGTH);

      return /verify|human|solve|turnstile|recaptcha|fix|update|download|code|command/i.test(
        context
      );
    } catch {
      return false;
    }
  }

  // ========================================================
  // COPY INTERCEPTION
  // ========================================================

  private static handleCopyEvent(
    event: ClipboardEvent
  ): void {
    // Ignore synthetic page-generated copy events.
    if (!event.isTrusted) {
      return;
    }

    // Respect global protection, clipboard protection
    // and website allowlisting.
    if (!this.isProtectionActive()) {
      return;
    }

    try {
      const selectedText = this.getSelectedText(event);

      if (!selectedText) {
        return;
      }

      const hasDangerousPayload =
        this.isDangerousPayload(selectedText);

      if (!hasDangerousPayload) {
        return;
      }

      const isBlatantAttack =
        this.isBlatantAttack(selectedText);

      const isDeceptive =
        this.isDeceptiveContext(event.target);

      // A strong command pattern is sufficient.
      // Otherwise, require deceptive page context.
      if (!isBlatantAttack && !isDeceptive) {
        return;
      }

      // ----------------------------------------------------
      // Block original copy operation
      // ----------------------------------------------------

      event.preventDefault();

      event.stopImmediatePropagation();
      event.stopPropagation();

      // ----------------------------------------------------
      // Replace clipboard contents with harmless text
      // ----------------------------------------------------

      const replacement =
        "[ClickShield Blocked: Dangerous terminal command payload intercepted]";

      try {
        event.clipboardData?.setData(
          "text/plain",
          replacement
        );
      } catch (error) {
        logger.debug(
          "Unable to replace clipboard contents:",
          error
        );
      }

      logger.warn(
        "ClickShield intervention: malicious clipboard payload blocked!"
      );

      // ----------------------------------------------------
      // Notify intervention callback
      // ----------------------------------------------------

      try {
        this.callbacks?.onIntervention(
          "Malicious clipboard payload neutralized"
        );
      } catch (error) {
        logger.error(
          "ClickShield clipboard intervention callback failed:",
          error
        );
      }
    } catch (error) {
      logger.debug(
        "Error during copy interception:",
        error
      );
    }
  }
}
