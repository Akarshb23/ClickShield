import type { ScanResult } from "../shared/types/signal";
import { sanitizeText } from "../shared/utils/sanitizer";

export class WarningOverlay {
  private static hostElement: HTMLElement | null = null;
  private static shadowRoot: ShadowRoot | null = null;

  static show(scanResult: ScanResult, onDismiss?: () => void) {
    if (this.hostElement) return;

    this.hostElement = document.createElement("div");
    this.hostElement.setAttribute("data-clickshield-ignore", "true");
    this.hostElement.id = "clickshield-warning-host";

    this.shadowRoot = this.hostElement.attachShadow({ mode: "closed" });

    const styles = `
      :host {
        all: initial;
        position: fixed;
        inset: 0;
        z-index: 2147483647;
        display: flex;
        align-items: center;
        justify-content: center;
        background: rgba(0, 0, 0, 0.85);
        backdrop-filter: blur(8px);
        font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
        color: #f5f5f5;
      }
      .card {
        background: #111111;
        border: 2px solid #DC2626;
        border-radius: 8px;
        max-width: 520px;
        width: 90%;
        padding: 24px;
        box-shadow: 0 0 50px rgba(220, 38, 38, 0.3);
      }
      .header {
        display: flex;
        align-items: center;
        gap: 12px;
        margin-bottom: 16px;
      }
      .title {
        font-size: 18px;
        font-weight: 800;
        color: #DC2626;
        font-family: monospace;
      }
      .subtitle {
        font-size: 12px;
        color: #aaaaaa;
        font-family: monospace;
      }
      .body-text {
        font-size: 13px;
        line-height: 1.5;
        color: #e5e5e5;
        margin-bottom: 16px;
      }
      .signals {
        background: #181818;
        border: 1px solid #2a2a2a;
        border-radius: 4px;
        padding: 12px;
        margin-bottom: 20px;
        font-size: 11px;
        font-family: monospace;
      }
      .signal-item {
        color: #E5B83B;
        margin-bottom: 4px;
      }
      .actions {
        display: flex;
        gap: 12px;
        justify-content: flex-end;
      }
      button {
        padding: 10px 18px;
        border-radius: 4px;
        font-size: 12px;
        font-family: monospace;
        font-weight: bold;
        cursor: pointer;
        border: none;
      }
      .leave-btn {
        background: #DC2626;
        color: #ffffff;
      }
      .leave-btn:hover {
        background: #ef4444;
      }
      .dismiss-btn {
        background: #222222;
        color: #cccccc;
        border: 1px solid #333333;
      }
      .dismiss-btn:hover {
        background: #333333;
      }
    `;

    const signalsHtml = scanResult.signals
      .map(
        (s) =>
          `<div class="signal-item">⚠️ ${sanitizeText(s.type)}: ${sanitizeText(s.reason)}</div>`
      )
      .join("");

    this.shadowRoot.innerHTML = `
      <style>${styles}</style>
      <div class="card">
        <div class="header">
          <div>
            <div class="title">CLICKSHIELD INTERVENTION</div>
            <div class="subtitle">SUSPECTED CLICKFIX ATTACK DETECTED</div>
          </div>
        </div>
        <p class="body-text">
          This webpage is instructing you to copy and run system commands under the guise of human verification or CAPTCHA.
          <strong>Do not press Win+R, open PowerShell, or paste commands into your terminal.</strong>
        </p>
        <div class="signals">
          ${signalsHtml}
        </div>
        <div class="actions">
          <button id="cs-dismiss" class="dismiss-btn">I Understand The Risk</button>
          <button id="cs-leave" class="leave-btn">Leave Page</button>
        </div>
      </div>
    `;

    document.body.appendChild(this.hostElement);

    this.shadowRoot.getElementById("cs-leave")?.addEventListener("click", () => {
      window.location.href = "about:blank";
    });

    this.shadowRoot.getElementById("cs-dismiss")?.addEventListener("click", () => {
      this.hide();
      onDismiss?.();
    });
  }

  static hide() {
    if (this.hostElement) {
      this.hostElement.remove();
      this.hostElement = null;
      this.shadowRoot = null;
    }
  }
}

