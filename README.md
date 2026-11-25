# ClickShield 🛡️

> **Real-Time Behavioral Defense Against ClickFix Attacks & Fake CAPTCHAs**

ClickShield is a local-first Manifest V3 Chrome extension engineered to detect social-engineering attacks that trick users into running dangerous terminal commands disguised as human verification steps.

---

## Key Highlights

- **Intent-Based Heuristics**: Evaluates what a webpage directs the user to do rather than relying solely on static URL blocklists.
- **Multi-Vector Threat Engine**: Calculates a weighted risk score (0–100) mapping to explainable risk levels (`LOW`, `SUSPICIOUS`, `HIGH`, `CRITICAL`).
- **Closed Shadow DOM Overlays**: Injects isolated intervention modals that cannot be bypassed or tampered with by hostile page styles.
- **Active Clipboard Protection**: Neutralizes programmatic clipboard write hooks containing dangerous command syntax (`powershell`, `cmd`, `irm | iex`).
- **100% Local-First & Zero Telemetry**: Threat evaluation, logs, and allowlists remain entirely inside the local browser sandbox.
- **Cyberpunk Brutalist UI**: Dark & gold theme with animated GSAP risk meters and Recharts threat telemetry.

---

## Quickstart

### 1. Install Dependencies
```bash
npm install
```

### 2. Build Extension
```bash
npm run build
```
The compiled, ready-to-load extension is placed in `dist/`.

### 3. Load in Google Chrome
1. Navigate to `chrome://extensions/` in Chrome.
2. Toggle on **Developer mode** in the top-right corner.
3. Click **Load unpacked** and select the `dist/` directory inside `ClickShield`.
4. Pin the ClickShield shield icon to your toolbar.

### 4. Run Interactive Demo & Test Scenarios
```bash
npm run demo
```
- **Test Suite Hub**: `http://localhost:4173/`
- **Marketing Showcase & Simulator**: `http://localhost:4173/website`

### 5. Run Unit Tests
```bash
npm run test
```

### 6. Create Web Store ZIP Package
```bash
npm run package
```
Generates `clickshield-extension-v0.1.0.zip` ready for Chrome Web Store Developer Console upload.

---

## Documentation

- [System Architecture](docs/ARCHITECTURE.md)
- [Detection Rules & Scoring Model](docs/DETECTION_RULES.md)
- [Threat Model & Security Boundaries](docs/THREAT_MODEL.md)
- [Testing & Quality Assurance Guide](docs/TESTING.md)
- [Hackathon Demo & Presentation Script](docs/DEMO_GUIDE.md)
- [Privacy Policy](docs/PRIVACY_POLICY.md)
