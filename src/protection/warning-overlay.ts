import type { ScanResult } from "../shared/types/signal";
import { sanitizeText } from "../shared/utils/sanitizer";
import { SafeNavigation } from "./safe-navigation";

export class WarningOverlay {
  private static hostElement: HTMLElement | null = null;
  private static shadowRoot: ShadowRoot | null = null;
  private static keyHandler: ((e: KeyboardEvent) => void) | null = null;

  static show(scanResult: ScanResult, onDismiss?: () => void) {
    if (this.hostElement) return; // Prevent duplicate overlays

    this.hostElement = document.createElement("div");
    this.hostElement.setAttribute("data-clickshield-ignore", "true");
    this.hostElement.id = "clickshield-security-warning";

    this.shadowRoot = this.hostElement.attachShadow({ mode: "closed" });

    // Identify if brand impersonation was detected
    const impersonationSignal = scanResult.signals.find(
      (s) => s.type === "DOMAIN_IMPERSONATION"
    );
    const officialUrl = impersonationSignal?.snippet
      ? SafeNavigation.getAuthenticDestination(impersonationSignal.snippet)
      : null;

    const styles = `
      :host {
        all: initial;
        position: fixed;
        inset: 0;
        z-index: 2147483647;
        display: flex;
        align-items: center;
        justify-content: center;
        background: rgba(5, 5, 5, 0.92);
        backdrop-filter: blur(12px);
        font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
        color: #F5F5F5;
        padding: 20px;
        box-sizing: border-box;
      }
      .modal {
        background: #0E0E0E;
        border: 2px solid #DC2626;
        box-shadow: 0 0 60px rgba(220, 38, 38, 0.4), 0 25px 50px -12px rgba(0, 0, 0, 0.9);
        border-radius: 8px;
        max-width: 580px;
        width: 100%;
        padding: 28px;
        box-sizing: border-box;
        animation: fadeIn 0.2s cubic-bezier(0.16, 1, 0.3, 1);
      }
      @keyframes fadeIn {
        from { opacity: 0; transform: scale(0.96); }
        to { opacity: 1; transform: scale(1); }
      }
      .header-tag {
        display: inline-flex;
        align-items: center;
        gap: 6px;
        background: rgba(220, 38, 38, 0.15);
        border: 1px solid rgba(220, 38, 38, 0.4);
        color: #F87171;
        font-family: monospace;
        font-size: 11px;
        font-weight: 700;
        letter-spacing: 0.1em;
        padding: 4px 10px;
        border-radius: 4px;
        text-transform: uppercase;
        margin-bottom: 14px;
      }
      .title {
        font-size: 22px;
        font-weight: 900;
        font-family: monospace;
        color: #FFFFFF;
        margin: 0 0 6px 0;
        letter-spacing: -0.02em;
      }
      .subtitle {
        font-size: 13px;
        color: #A3A3A3;
        line-height: 1.5;
        margin: 0 0 20px 0;
      }
      .section-label {
        font-family: monospace;
        font-size: 11px;
        font-weight: 700;
        color: #E5B83B;
        text-transform: uppercase;
        letter-spacing: 0.08em;
        margin-bottom: 8px;
      }
      .signals-box {
        background: #141414;
        border: 1px solid #262626;
        border-left: 3px solid #E5B83B;
        border-radius: 4px;
        padding: 12px 14px;
        margin-bottom: 18px;
        max-height: 140px;
        overflow-y: auto;
      }
      .signal-row {
        display: flex;
        align-items: flex-start;
        gap: 8px;
        font-family: monospace;
        font-size: 11px;
        color: #D4D4D4;
        margin-bottom: 6px;
      }
      .signal-row:last-child {
        margin-bottom: 0;
      }
      .signal-icon {
        color: #E5B83B;
        flex-shrink: 0;
      }
      .recommendation-box {
        background: #121212;
        border: 1px solid #262626;
        border-radius: 4px;
        padding: 12px 14px;
        margin-bottom: 24px;
        font-size: 12px;
        line-height: 1.5;
        color: #E5E5E5;
      }
      .actions-container {
        display: flex;
        flex-wrap: wrap;
        gap: 10px;
        justify-content: flex-end;
      }
      button {
        font-family: monospace;
        font-size: 12px;
        font-weight: 700;
        padding: 10px 18px;
        border-radius: 4px;
        cursor: pointer;
        transition: all 0.15s ease;
        border: 1px solid transparent;
      }
      .btn-leave {
        background: #DC2626;
        color: #FFFFFF;
      }
      .btn-leave:hover, .btn-leave:focus {
        background: #EF4444;
        outline: 2px solid #FFFFFF;
      }
      .btn-official {
        background: #1E1E1E;
        color: #E5B83B;
        border-color: #E5B83B;
      }
      .btn-official:hover, .btn-official:focus {
        background: #282828;
      }
      .btn-dismiss {
        background: transparent;
        color: #737373;
        border-color: #262626;
      }
      .btn-dismiss:hover, .btn-dismiss:focus {
        background: #171717;
        color: #A3A3A3;
      }
    `;

    const signalsList = scanResult.signals
      .map(
        (s) => `
        <div class="signal-row">
          <span class="signal-icon">⚡</span>
          <div>
            <strong>${sanitizeText(s.type.replace(/_/g, " "))}:</strong>
            <span>${sanitizeText(s.reason)}</span>
          </div>
        </div>
      `
      )
      .join("");

    this.shadowRoot.innerHTML = `
      <style>${styles}</style>
      <div class="modal" role="alertdialog" aria-modal="true" aria-labelledby="cs-title">
        <div class="header-tag">
          <span>●</span> CLICKSHIELD INTERVENTION · THREAT SCORE ${scanResult.score}/100
        </div>
        <h2 id="cs-title" class="title">Suspected ClickFix Attack Detected</h2>
        <p class="subtitle">
          This website is presenting a deceptive verification interface designed to trick you into copying and executing malicious commands into your system terminal.
        </p>

        <div class="section-label">Why this page was flagged</div>
        <div class="signals-box">
          ${signalsList}
        </div>

        <div class="section-label">Recommended safety action</div>
        <div class="recommendation-box">
          Do not press <strong>Win + R</strong>, do not open PowerShell or Command Prompt, and do not paste content from this page.
        </div>

        <div class="actions-container">
          <button id="btn-dismiss" class="btn-dismiss" type="button">I Understand The Risk</button>
          ${
            officialUrl
              ? `<button id="btn-official" class="btn-official" type="button">Go To Official Service</button>`
              : ""
          }
          <button id="btn-leave" class="btn-leave" type="button" autofocus>Leave This Page</button>
        </div>
      </div>
    `;

    document.body.appendChild(this.hostElement);

    // Event listeners for actions
    const leaveBtn = this.shadowRoot.getElementById("btn-leave");
    const dismissBtn = this.shadowRoot.getElementById("btn-dismiss");
    const officialBtn = this.shadowRoot.getElementById("btn-official");

    leaveBtn?.addEventListener("click", () => SafeNavigation.leavePage());

    dismissBtn?.addEventListener("click", () => {
      this.hide();
      onDismiss?.();
    });

    officialBtn?.addEventListener("click", () => {
      if (officialUrl) window.location.href = officialUrl;
    });

    // Keyboard navigation (Trap focus and handle ESC)
    this.keyHandler = (e: KeyboardEvent) => {
      if (e.key === "Escape") {
        this.hide();
        onDismiss?.();
      }
    };
    window.addEventListener("keydown", this.keyHandler);

    // Auto-focus the primary safe action
    leaveBtn?.focus();
  }

  static hide() {
    if (this.keyHandler) {
      window.removeEventListener("keydown", this.keyHandler);
      this.keyHandler = null;
    }
    if (this.hostElement) {
      this.hostElement.remove();
      this.hostElement = null;
      this.shadowRoot = null;
    }
  }

  static isVisible(): boolean {
    return this.hostElement !== null;
  }
}
