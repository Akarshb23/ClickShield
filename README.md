# ClickShield 🛡️

> **Real-Time Behavioral Defense Against ClickFix Attacks & Fake CAPTCHAs**

ClickShield is a local-first Manifest V3 Chrome extension engineered to detect social-engineering attacks that trick users into running dangerous terminal commands disguised as human verification steps.

---

## Key Features
- **Multi-Vector Intent Analysis**: Analyzes page behavior and instructional sequences rather than static URL reputation.
- **Weighted Threat Engine**: Transparent scoring system (0–100) mapping to explainable risk levels (`LOW`, `SUSPICIOUS`, `HIGH`, `CRITICAL`).
- **Cybersecurity Brutalist UI**: Premium black-and-gold interface (`#E5B83B`) with live risk gauges and detection breakdown.
- **Local-First & Zero Telemetry**: Operates entirely within the browser sandbox with zero external server dependencies.
- **Full Security Command Center**: Dedicated dashboard for audit logs, telemetry, and domain allowlists.

---

## Quickstart

### 1. Install Dependencies
```bash
npm install
```

### 2. Build the Extension
```bash
npm run build
```
This outputs the ready-to-load extension into the `dist/` directory.

### 3. Load into Google Chrome
1. Open Google Chrome and navigate to `chrome://extensions/`.
2. Toggle on **Developer mode** in the top-right corner.
3. Click **Load unpacked**.
4. Select the `dist/` directory from the `ClickShield` project root.
5. Pin ClickShield to your Chrome toolbar.

### 4. Run Unit Tests
```bash
npm run test
```

---

## Safe Testing Fixtures
To verify detection without running real malware, test fixtures are provided under `tests/fixtures/`:
- `tests/fixtures/simulated-clickfix.html`: Harmless simulation of a fake human verification prompt directing PowerShell paste.
- `tests/fixtures/legitimate-captcha.html`: Normal baseline webpage.

---

## Architecture & Documentation
- [System Architecture](file:///d:/ClickSheild/docs/ARCHITECTURE.md)
- [Threat Model](file:///d:/ClickSheild/docs/THREAT_MODEL.md)

