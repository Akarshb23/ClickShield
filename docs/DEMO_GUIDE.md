# ClickShield — Hackathon Demo Guide & Presentation Script

## 3-Minute Live Hackathon Pitch Script

### Minute 1: The Problem (ClickFix Attacks)
> *"Traditional malicious URL filters only ask: 'Is this domain already on a blacklist?' Attackers easily bypass this by hosting attacks on legitimate cloud providers, compromised sites, or newly registered domains.*
>
> *ClickFix is a modern attack technique where malicious sites pretend to be Cloudflare Turnstile, Google reCAPTCHA, or Microsoft Support. They trick the user into pressing **Win + R**, pasting a copied PowerShell command, and pressing Enter — turning the human into the delivery mechanism.*
>
> *Meet **ClickShield**: A local-first behavioral cybersecurity extension that focuses on **what the website is trying to make you do**, rather than just where it is hosted."*

---

### Minute 2: The Live Demonstration

#### Scenario A: Legitimate Developer Documentation (No False Alarm)
1. Open [`tests/fixtures/developer-documentation.html`](file:///d:/ClickSheild/tests/fixtures/developer-documentation.html).
2. Click the ClickShield extension icon.
3. Show that the Risk Gauge is **0 / 100 (PROTECTED)**:
   > *"Notice that even though this article discusses PowerShell and `Invoke-WebRequest`, ClickShield recognizes that there are no coercive CAPTCHA tricks or deceptive instructions. Zero false positives."*

#### Scenario B: Active ClickFix Attack Simulation
1. Open [`tests/fixtures/simulated-clickfix.html`](file:///d:/ClickSheild/tests/fixtures/simulated-clickfix.html).
2. Point out what happens instantly:
   - The badge turns **RED (85/100, CRITICAL)**.
   - The **ClickShield Security Intervention Overlay** automatically emerges over the page.
   - Explain the breakdown: *"ClickShield caught fake CAPTCHA prompts combined with Win+R terminal instructions and PowerShell execution syntax."*
3. Show the **"Leave This Page"** button: clicking it safely terminates network requests and redirects to `about:blank`.

#### Scenario C: Clipboard Interception Guard
1. Open [`tests/fixtures/simulated-clipboard.html`](file:///d:/ClickSheild/tests/fixtures/simulated-clipboard.html).
2. Click the deceptive button **"Verify Human & Copy Code"**.
3. Show that ClickShield intercepts the programmatic clipboard write, preventing dangerous terminal payloads from silently residing in the clipboard.

---

### Minute 3: Security Command Dashboard & Architecture
1. Open the ClickShield Security Dashboard (`src/dashboard/index.html`).
2. Highlight:
   - **Interactive GSAP & Recharts telemetry**: Real-time signal distribution graph.
   - **Detailed Threat Inspector**: Click any logged threat to reveal exact triggers and actions.
   - **Audit Log Export**: One-click JSON export for enterprise or security logging.
   - **100% Local-First Guarantee**: Zero external cloud APIs, zero privacy leaks, zero latency.

---

## Controlled Local Demonstration URLs
| Target | Local File Path | Expected Behavior |
| :--- | :--- | :--- |
| **Normal Site** | `tests/fixtures/normal-website.html` | Status: `PROTECTED` (Score: 0) |
| **Benign Docs** | `tests/fixtures/developer-documentation.html` | Status: `LOW` (Score: <30, No Alert) |
| **ClickFix Attack** | `tests/fixtures/simulated-clickfix.html` | Status: `CRITICAL` (Score: 85, Shadow DOM Overlay) |
| **Clipboard Trap** | `tests/fixtures/simulated-clipboard.html` | Interception: Neutralizes command payload |

