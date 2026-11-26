/**
 * ClickShield MAIN-world clipboard monitor.
 *
 * Monitors navigator.clipboard.writeText() and document.execCommand("copy").
 * Suspicious operations are blocked only when both global protection and
 * clipboard protection are enabled.
 *
 * The CLICKSHIELD_TEST_ONLY marker is a harmless, exact-match fixture token.
 * It exists solely so the local positive-test page can verify the clipboard
 * reporting path without placing a real command on the clipboard.
 */

(function () {
  const monitorWindow = window as Window & {
    __CLICKSHIELD_MAIN_MONITOR_ACTIVE__?: boolean;
  };

  if (monitorWindow.__CLICKSHIELD_MAIN_MONITOR_ACTIVE__) return;
  monitorWindow.__CLICKSHIELD_MAIN_MONITOR_ACTIVE__ = true;

  const SETTINGS_EVENT = "clickshield:protection-settings";
  const SETTINGS_REQUEST_EVENT = "clickshield:protection-settings-request";
  const SUSPICIOUS_COPY_EVENT = "clickshield:suspicious-copy";

  const MAX_INSPECTED_TEXT_LENGTH = 20_000;
  const MAX_REPORTED_SNIPPET_LENGTH = 100;
  const MAX_SETTINGS_REQUEST_ATTEMPTS = 50;

  interface ProtectionSettingsDetail {
    protectionEnabled: boolean;
    clipboardProtection: boolean;
  }

  let protectionEnabled = false;
  let clipboardProtectionEnabled = false;
  let settingsReceived = false;

  function isClipboardProtectionActive(): boolean {
    return (
      settingsReceived &&
      protectionEnabled &&
      clipboardProtectionEnabled
    );
  }

  // Real command indicators. A broad match alone is not sufficient to block.
  const SUSPICIOUS_COMMAND_REGEX =
    /\b(?:powershell(?:\.exe)?|pwsh|cmd(?:\.exe)?|mshta(?:\.exe)?|bitsadmin(?:\.exe)?|certutil(?:\.exe)?|regsvr32(?:\.exe)?|rundll32(?:\.exe)?|wscript(?:\.exe)?|cscript(?:\.exe)?|invoke-expression|invoke-webrequest|downloadstring|start-process|osascript)\b|\b(?:irm|iex)\s+|\b(?:curl|wget)\b[^\r\n]{0,500}\|\s*(?:iex|invoke-expression|sh|bash|powershell|pwsh)\b|\b(?:bash|sh)\s+-c\b|\[convert\]::frombase64string/i;

  const BLATANT_ATTACK_REGEX =
    /\b(?:powershell|pwsh)\b[^\r\n]{0,300}(?:-w(?:indowstyle)?\s+hidden|-e(?:nc(?:odedcommand)?)?\b|-nop\b)|\b(?:irm|iex)\b[^\r\n]{0,300}https?:\/\/|\bcertutil\b[^\r\n]{0,300}-urlcache|\bmshta\b[^\r\n]{0,200}https?:\/\/|\b(?:curl|wget)\b[^\r\n]{0,300}\|\s*(?:ba)?sh\b|\b(?:curl|wget)\b[^\r\n]{0,300}\|\s*(?:iex|invoke-expression)\b/i;

  // Harmless test-fixture marker; deliberately exact and narrow.
  const CLICKSHIELD_TEST_MARKER_REGEX = /^\s*echo\s+CLICKSHIELD_TEST_ONLY\s*$/i;

  function isSyntheticTestMarker(text: string): boolean {
    return CLICKSHIELD_TEST_MARKER_REGEX.test(text.trim());
  }

  function isSuspiciousCommand(text: unknown): text is string {
    if (typeof text !== "string" || text.length === 0) return false;

    const inspected = text.slice(0, MAX_INSPECTED_TEXT_LENGTH);
    return (
      SUSPICIOUS_COMMAND_REGEX.test(inspected) ||
      isSyntheticTestMarker(inspected)
    );
  }

  function isBlatantAttack(text: string): boolean {
    return BLATANT_ATTACK_REGEX.test(
      text.slice(0, MAX_INSPECTED_TEXT_LENGTH)
    );
  }

  // MAIN-world and isolated-world scripts execute independently. Request the
  // settings until the isolated content script responds or attempts expire.
  window.addEventListener(SETTINGS_EVENT, (event: Event) => {
    if (!(event instanceof CustomEvent)) return;

    const detail = event.detail as ProtectionSettingsDetail | undefined;
    if (
      !detail ||
      typeof detail.protectionEnabled !== "boolean" ||
      typeof detail.clipboardProtection !== "boolean"
    ) {
      return;
    }

    protectionEnabled = detail.protectionEnabled;
    clipboardProtectionEnabled = detail.clipboardProtection;
    settingsReceived = true;
  });

  let settingsRequestAttempts = 0;

  function requestProtectionSettings(): void {
    if (
      settingsReceived ||
      settingsRequestAttempts >= MAX_SETTINGS_REQUEST_ATTEMPTS
    ) {
      return;
    }

    settingsRequestAttempts += 1;
    window.dispatchEvent(new Event(SETTINGS_REQUEST_EVENT));
    window.setTimeout(requestProtectionSettings, 100);
  }

  requestProtectionSettings();

  function notifySuspiciousPayload(text: string): void {
    try {
      window.dispatchEvent(
        new CustomEvent(SUSPICIOUS_COPY_EVENT, {
          detail: {
            timestamp: Date.now(),
            hasCommandSyntax: true,
            snippet: text.slice(0, MAX_REPORTED_SNIPPET_LENGTH),
          },
        })
      );
    } catch {
      // Reporting must never interrupt page execution.
    }
  }

  function createClipboardBlockedError(): Error {
    try {
      return new DOMException(
        "ClickShield blocked a suspicious clipboard operation.",
        "NotAllowedError"
      );
    } catch {
      const error = new Error(
        "ClickShield blocked a suspicious clipboard operation."
      );
      error.name = "NotAllowedError";
      return error;
    }
  }

  function patchMethod(
    target: object,
    property: string,
    replacement: (...args: any[]) => any
  ): boolean {
    const mutableTarget = target as unknown as Record<string, unknown>;

    try {
      Object.defineProperty(target, property, {
        configurable: true,
        writable: true,
        value: replacement,
      });

      if (mutableTarget[property] === replacement) return true;
    } catch {
      // Try assignment as a fallback.
    }

    try {
      mutableTarget[property] = replacement;
      return mutableTarget[property] === replacement;
    } catch {
      return false;
    }
  }

  function isInsideEditableContent(element: Element | null): boolean {
    let current = element;

    try {
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
    } catch {
      return true;
    }
  }

  function isSensitiveInput(
    input: HTMLInputElement | HTMLTextAreaElement
  ): boolean {
    if (
      input instanceof HTMLInputElement &&
      (input.type === "password" || input.type === "hidden")
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

  function getSelectedTextForCopy(): string {
    try {
      const selection = document.getSelection();

      if (selection && !selection.isCollapsed && selection.toString()) {
        const anchorElement =
          selection.anchorNode instanceof Element
            ? selection.anchorNode
            : selection.anchorNode?.parentElement || null;
        const focusElement =
          selection.focusNode instanceof Element
            ? selection.focusNode
            : selection.focusNode?.parentElement || null;

        if (
          isInsideEditableContent(anchorElement) ||
          isInsideEditableContent(focusElement)
        ) {
          return "";
        }

        return selection.toString().slice(0, MAX_INSPECTED_TEXT_LENGTH);
      }

      const activeElement = document.activeElement;
      if (
        !activeElement ||
        (!(activeElement instanceof HTMLInputElement) &&
          !(activeElement instanceof HTMLTextAreaElement))
      ) {
        return "";
      }

      if (
        isSensitiveInput(activeElement) ||
        isInsideEditableContent(activeElement)
      ) {
        return "";
      }

      const start = activeElement.selectionStart;
      const end = activeElement.selectionEnd;
      if (start === null || end === null || end <= start) return "";

      return activeElement.value.slice(
        start,
        Math.min(end, start + MAX_INSPECTED_TEXT_LENGTH)
      );
    } catch {
      return "";
    }
  }

  function isDeceptiveContext(target: Element | null): boolean {
    try {
      if (!target) return false;

      const interactiveElement = target.closest(
        "button, a, [role='button']"
      );
      if (!interactiveElement) return false;

      const context = [
        interactiveElement.textContent || "",
        interactiveElement.getAttribute("aria-label") || "",
        interactiveElement.getAttribute("title") || "",
      ]
        .join(" ")
        .slice(0, 1000);

      return /verify|verification|human|solve|turnstile|recaptcha|fix|update|download|code|command|clipboard|copy/i.test(
        context
      );
    } catch {
      return false;
    }
  }

  function shouldBlockPayload(
    text: string,
    contextElement: Element | null
  ): boolean {
    if (!isSuspiciousCommand(text)) return false;

    // The benign fixture token is blocked only in a verification/copy context.
    // Real high-confidence attack patterns can be blocked independently.
    if (isSyntheticTestMarker(text)) {
      return isDeceptiveContext(contextElement);
    }

    return (
      isBlatantAttack(text) ||
      isDeceptiveContext(contextElement)
    );
  }

  // 1. navigator.clipboard.writeText()
  try {
    const clipboard = navigator.clipboard;

    if (clipboard && typeof clipboard.writeText === "function") {
      const originalWriteText = clipboard.writeText.bind(clipboard);

      const guardedWriteText = function (text: string): Promise<void> {
        if (isClipboardProtectionActive() && typeof text === "string") {
          const inspectedText = text.slice(0, MAX_INSPECTED_TEXT_LENGTH);
          const contextElement =
            document.activeElement instanceof Element
              ? document.activeElement
              : null;

          if (shouldBlockPayload(inspectedText, contextElement)) {
            notifySuspiciousPayload(inspectedText);
            return Promise.reject(createClipboardBlockedError());
          }
        }

        // Preserve native clipboard permission and user-activation behavior.
        return originalWriteText(text);
      };

      if (!patchMethod(clipboard, "writeText", guardedWriteText)) {
        console.warn(
          "[ClickShield] Could not patch navigator.clipboard.writeText."
        );
      }
    }
  } catch (error) {
    console.debug(
      "[ClickShield] Clipboard writeText patch failed:",
      error
    );
  }

  // 2. document.execCommand("copy")
  try {
    if (typeof document.execCommand === "function") {
      const originalExecCommand = document.execCommand.bind(document);

      const guardedExecCommand = function (
        commandId: string,
        showUI?: boolean,
        value?: string
      ): boolean {
        try {
          if (
            isClipboardProtectionActive() &&
            typeof commandId === "string" &&
            commandId.trim().toLowerCase() === "copy"
          ) {
            const selectedText = getSelectedTextForCopy();
            const selection = document.getSelection();
            const selectionTarget =
              selection?.anchorNode instanceof Element
                ? selection.anchorNode
                : selection?.anchorNode?.parentElement || null;
            const contextElement =
              selectionTarget ||
              (document.activeElement instanceof Element
                ? document.activeElement
                : null);

            if (
              selectedText &&
              shouldBlockPayload(selectedText, contextElement)
            ) {
              notifySuspiciousPayload(selectedText);
              return false;
            }
          }
        } catch (error) {
          console.debug(
            "[ClickShield] execCommand inspection failed:",
            error
          );
        }

        return originalExecCommand(commandId, showUI, value);
      };

      if (!patchMethod(document, "execCommand", guardedExecCommand)) {
        console.warn(
          "[ClickShield] Could not patch document.execCommand."
        );
      }
    }
  } catch (error) {
    console.debug(
      "[ClickShield] execCommand patch failed:",
      error
    );
  }
})();
