# ClickShield — Privacy Policy

*Last updated: November 25, 2026*

ClickShield is committed to protecting user privacy. This Privacy Policy outlines how ClickShield handles data within the Google Chrome extension.

---

## 1. Single Purpose Description
ClickShield is a cybersecurity browser extension engineered to detect behavioral ClickFix attacks, fake human verification prompts, and dangerous operating system command-line copy instructions before users act on them.

---

## 2. Zero Telemetry & Local-First Processing
- **Zero Cloud Transmission**: All heuristic analysis, DOM scanning, threat scoring, and clipboard pattern matching occur **100% locally on your device**.
- **No Remote Servers**: ClickShield does not operate or communicate with any remote servers, analytics APIs, tracking beacons, or telemetry endpoints.
- **No Browsing History Collection**: ClickShield does not log, track, or record your browsing history. The extension only inspects the active DOM structure during live page viewing.

---

## 3. Data Storage & Retention
- **Local Storage Only**: Any settings (e.g. detection sensitivity, domain allowlists) and recorded threat logs are stored strictly inside your browser's local sandbox (`chrome.storage.local` and `chrome.storage.session`).
- **Automatic 30-Day Retention**: Threat history logs are automatically purged after 30 days (or your configured retention preference).
- **User Control & Deletion**: You can review, export to JSON, or wipe all stored threat history at any time through the ClickShield Security Command Center.

---

## 4. Clipboard Data Handling
- ClickShield does **NOT** read, store, or transmit personal text, passwords, or credentials copied to your system clipboard.
- The clipboard monitor only evaluates whether a copy event triggered by a pseudo-verification button contains terminal execution syntax (e.g. `powershell`, `cmd`, `irm | iex`).

---

## 5. Chrome Permissions Justification
ClickShield adheres strictly to the principle of least privilege:

| Permission | Technical Justification |
| :--- | :--- |
| `storage` | Required to store user preferences, trusted domain allowlists, and local threat audit logs. |
| `notifications` | Required to alert the user when a high-risk ClickFix attack vector is actively detected. |
| `webNavigation` | Required to reset per-tab risk state and badges when navigating to new web pages. |
| `host_permissions` (`http://*/*`, `https://*/*`) | Required to inject the behavioral content script to protect the user across visited websites. |

---

## 6. Open Source & Transparency
ClickShield is open-source software. You can inspect the source code and review the implementation at:
**https://github.com/Akarshb23/ClickShield**

