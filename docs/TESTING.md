# ClickShield — Testing & Quality Assurance Guide

## Automated Test Suites
ClickShield uses [Vitest](https://vitest.dev/) and `jsdom` for isolated behavioral and unit testing.

To execute the complete test suite:
```bash
npm run test
```

### Covered Test Suites:
1. `tests/unit/risk-engine.test.ts`: Scoring bounds, signal deduplication, and max 100 capping.
2. `tests/unit/captcha-detector.test.ts`: Identifying fake CAPTCHA checkboxes vs authentic providers.
3. `tests/unit/instruction-detector.test.ts`: Catching `Win + R` and terminal paste social engineering.
4. `tests/unit/command-detector.test.ts`: Detecting encoded PowerShell, hidden windows, and in-memory cradles.
5. `tests/unit/domain-detector.test.ts`: High-abuse TLDs and Punycode spoofing detection.
6. `tests/unit/signal-correlator.test.ts`: Co-occurrence correlation proving ClickFix attack signatures.
7. `tests/unit/clipboard-guard.test.ts`: Event monitoring and programmatic clipboard write interceptors.
8. `tests/unit/safe-navigation.test.ts`: Immediate departure redirect and official destination resolution.
9. `tests/unit/warning-overlay.test.ts`: Shadow DOM injection and focus trapping.
10. `tests/unit/allowlist-repository.test.ts`: Exact and subdomain exception matching.
11. `tests/unit/threat-repository.test.ts`: Persistent logging, deduplication, and retention pruning.
12. `tests/unit/false-positive.test.ts`: Calibrating detectors against developer documentation and normal websites.
13. `tests/unit/message-handler.test.ts`: Input sanitization and unscannable URL schemes.

---

## Controlled Local Test Fixtures

ClickShield includes harmless, non-executable test fixtures located under `tests/fixtures/`:

### 1. Controlled ClickFix Attack Simulation
- **File**: [`tests/fixtures/simulated-clickfix.html`](file:///d:/ClickSheild/tests/fixtures/simulated-clickfix.html)
- **Vectors Simulated**: Mimicked verification box, instructions to press `Win + R`, and PowerShell paste prompt.
- **Expected Result**: Extension badge turns RED (Risk Score $\ge$ 80, CRITICAL), and the ClickShield intervention overlay appears.

### 2. Programmatic Clipboard Write Simulation
- **File**: [`tests/fixtures/simulated-clipboard.html`](file:///d:/ClickSheild/tests/fixtures/simulated-clipboard.html)
- **Vectors Simulated**: A verification button invoking `navigator.clipboard.writeText(...)` with PowerShell syntax.
- **Expected Result**: MAIN-world monitor intercepts the write, emits `clickshield:suspicious-copy`, and flags the session.

### 3. Developer Documentation (False-Positive Verification)
- **File**: [`tests/fixtures/developer-documentation.html`](file:///d:/ClickSheild/tests/fixtures/developer-documentation.html)
- **Vectors Simulated**: Educational technical documentation discussing PowerShell and `Invoke-WebRequest`.
- **Expected Result**: ClickShield identifies this as non-coercive (Risk Score < 30, LOW). No intervention modal is shown.

### 4. Normal Webpage Baseline
- **File**: [`tests/fixtures/normal-website.html`](file:///d:/ClickSheild/tests/fixtures/normal-website.html)
- **Expected Result**: Zero threat signals detected. Status: `PROTECTED`.

