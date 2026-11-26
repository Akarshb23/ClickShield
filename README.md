# ClickShield 🛡️

> **Real-Time Behavioral Defense Against ClickFix Attacks & Fake CAPTCHAs**

**Live Website:** [https://clickshield-1j8.pages.dev/](https://clickshield-1j8.pages.dev/)  
**Repository:** [https://github.com/Akarshb23/ClickShield](https://github.com/Akarshb23/ClickShield)

ClickShield is a local-first **Manifest V3 Chrome extension** and security showcase built to detect and block **ClickFix** social-engineering attacks before a user is tricked into executing malicious commands. Instead of relying solely on static domain blocklists, ClickShield analyzes page intent, deceptive UI elements, terminal execution instructions, and programmatic clipboard writes in real time inside the browser.

---

## Problem Statement

Modern browser-based **ClickFix** attacks bypass traditional antivirus and URL blocklists by exploiting human trust rather than software vulnerabilities:

1. A webpage presents a **fake CAPTCHA**, browser update prompt, or simulated error (e.g., Cloudflare Turnstile or Windows/meeting error impersonation).
2. Clicking the prompt silently copies an obfuscated terminal payload (such as `powershell -WindowStyle Hidden ...`, `irm ... | iex`, `mshta`, or `curl | bash`) to the user's clipboard.
3. On-screen instructions coerce the user into pressing `Win + R`, opening PowerShell/CMD/Terminal, pasting (`Ctrl + V`), and pressing `Enter`.

Because the user manually executes the command, endpoint defenses and static blocklists often fail to stop the initial social-engineering lure.

---

## Proposed Solution

ClickShield provides a **browser-level behavioral defense layer** that intercepts ClickFix attacks prior to command execution:

- **Multi-Signal Feature Extraction**: Inspects DOM content, hidden/attribute payloads, iframes, keyboard/terminal instructions, domain anomalies, and brand impersonation claims.
- **MAIN-World Clipboard Monitoring**: Observes programmatic `navigator.clipboard.writeText` and `document.execCommand("copy")` calls in the page execution context and intercepts dangerous copy events.
- **Correlated Risk Scoring**: Evaluates deduplicated threat signals into a `0–100` risk score and four clear risk bands (`LOW`, `SUSPICIOUS`, `HIGH`, `CRITICAL`).
- **Tamper-Resistant Intervention**: Renders an isolated **closed Shadow DOM** warning modal with explainable reasons and one-click safe exit (`SafeNavigation`).
- **Local-First Privacy**: All scanning, storage, allowlisting, and telemetry remain 100% local in the browser with zero external API calls.

---

## Key Features

- **6 Modular Threat Detectors**:
  - `FAKE_CAPTCHA`: Detects fake human verification prompts lacking legitimate CAPTCHA provider infrastructure.
  - `SUSPICIOUS_INSTRUCTION`: Flags `Win + R`, Run dialog, and terminal copy-paste coercion sequences.
  - `EXECUTION_INSTRUCTION`: Identifies encoded/hidden PowerShell, download cradles (`irm`/`iex`), LOLBins (`mshta`, `certutil`, `bitsadmin`), and remote shell pipes (`curl | bash`).
  - `CLIPBOARD_MANIPULATION`: Captures programmatic clipboard writes and deceptive copy triggers carrying executable commands.
  - `SUSPICIOUS_DOMAIN`: Flags raw public IP hosts, Punycode (`xn--`), excessive subdomains, and high-abuse TLDs.
  - `DOMAIN_IMPERSONATION`: Detects pages claiming official brand verification on unrelated hostnames.
- **Active Copy Interception**: Neutralizes dangerous clipboard payloads during copy events before they reach the OS clipboard.
- **Isolated Warning Overlay**: Closed Shadow DOM modal (`WarningOverlay`) that cannot be styled over or dismissed by hostile page scripts.
- **Interactive Popup & Security Command Center**:
  - Popup UI with animated GSAP radial risk gauge, live indicator breakdown, one-click rescan, protection toggle, and domain allowlist control.
  - Full-page Dashboard with Recharts threat analytics, searchable threat history (30-day retention), and JSON audit log export.
- **Zero-Telemetry Offline Operation**: Works completely offline using `chrome.storage.local` and `chrome.storage.session`.

---

## Technologies Used

- **Extension Platform**: Chrome Extensions **Manifest V3** (`storage`, `notifications`, `webNavigation`, `activeTab`, `tabs`, `scripting`)
- **Frontend & UI**: **React 19**, **TypeScript**, **Tailwind CSS v4**, **Lucide React**
- **Data Visualization & Motion**: **GSAP** (radial risk gauge & scroll animations), **Recharts** (dashboard analytics), **Three.js** (3D WebGL crest on the showcase website)
- **Build & Bundling**: **Vite**, **@crxjs/vite-plugin**
- **Testing**: **Vitest**, **jsdom**

---

## Installation and Setup Instructions

### Prerequisites
- **Node.js** (v18+ recommended) and **npm**
- **Google Chrome** (or any Chromium-based browser such as Microsoft Edge / Brave)

### 1. Clone the Repository
```bash
git clone https://github.com/Akarshb23/ClickShield.git
cd ClickShield
```

### 2. Install Dependencies
```bash
npm install
```

### 3. Build the Extension
```bash
npm run build
```
This runs TypeScript type-checking (`tsc`) and bundles the extension into the `dist/` directory.

### 4. Load the Extension in Chrome
1. Open Google Chrome and navigate to `chrome://extensions/`.
2. Enable **Developer mode** using the toggle in the top-right corner.
3. Click **Load unpacked** and select the `dist/` folder inside `ClickShield`.
4. Pin **ClickShield** from the extensions toolbar menu to view the live risk badge.

---

## How to Run the Project

- **Run Automated Unit Tests**:
  ```bash
  npm run test
  ```
- **Run Interactive Demo Server & Test Fixtures**:
  ```bash
  npm run demo
  ```
  - **Test Harness Hub**: `http://localhost:4173/`
  - **Showcase Website**: `http://localhost:4173/website` (also live at [https://clickshield-1j8.pages.dev/](https://clickshield-1j8.pages.dev/))
- **Build & Package Extension ZIP**:
  ```bash
  npm run package
  ```
  Produces `clickshield-extension-v0.1.0.zip` from `dist/`.

---

## Project Architecture & Workflow

```text
Webpage (Top Frame + Subframes)
  ├── MAIN World: src/injected/clipboard-monitor.ts
  │     └─ Hooks navigator.clipboard.writeText & document.execCommand("copy")
  └── Isolated World: src/content/index.ts
        ├── page-scanner.ts + dom-observer.ts + event-monitor.ts + clipboard-guard.ts
        ├── Feature Detectors (src/engine/detectors/*)
        ├── Risk Engine & Signal Correlator (src/engine/risk-engine.ts, signal-correlator.ts)
        ├── Protection Layer (src/protection/intervention-manager.ts, warning-overlay.ts, copy-interceptor.ts)
        └── Background Service Worker (src/background/service-worker.ts)
              ├── Updates extension badge & Chrome notifications
              ├── Persists state, allowlist & 30-day threat history (src/storage/*)
              └── Powers Popup (src/popup/), Dashboard (src/dashboard/), & Options (src/options/)
```

### Additional Documentation
- [System Architecture](docs/ARCHITECTURE.md)
- [Detection Rules & Scoring Model](docs/DETECTION_RULES.md)
- [Threat Model & Security Boundaries](docs/THREAT_MODEL.md)
- [Testing & Quality Assurance Guide](docs/TESTING.md)
- [Demo & Presentation Guide](docs/DEMO_GUIDE.md)
- [Privacy Policy](docs/PRIVACY_POLICY.md)

---

## Team Members & Contributions

| Team Member | Role | Contributions |
| :--- | :--- | :--- |
| **Akshat Vats** | Backend Developer & Tester | Detection engine architecture, heuristic detectors, background service worker, storage repositories, and Vitest unit/fixture testing. |
| **Akarsh Bhardwaj** | Backend Developer & Tester | Risk scoring & signal correlation pipeline, clipboard monitoring/interception, Shadow DOM intervention logic, build/packaging, and end-to-end testing. |
| **Ananya Singh** | UI/UX Designer | Black-and-gold cybersecurity brutalist design system, popup/dashboard/overlay UX flows, interactive risk gauge experience, and showcase website design. |
| **Akshay Yadav** | Frontend Developer | React 19 popup, options, and Security Command Center dashboard implementation, GSAP/Recharts integrations, and responsive frontend styling. |
