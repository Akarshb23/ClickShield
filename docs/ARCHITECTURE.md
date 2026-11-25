# ClickShield — System Architecture

## Overview
ClickShield is a lightweight, local-first behavioral cybersecurity Chrome extension built on Manifest V3. It detects ClickFix attacks, fake verification pages, clipboard hijacking, and deceptive operating-system command instructions.

## Core Design Principles
1. **Local-First & Zero Telemetry**: Threat evaluation and data storage occur exclusively on the user's device. No browsing history or clipboard payloads are sent to remote servers.
2. **Behavioral Intent vs. Static URL Classification**: Instead of asking *"Is this domain on a known blocklist?"*, ClickShield asks *"What is this webpage trying to coerce the user into doing?"*
3. **Multi-Signal Correlation**: Threat scores reflect correlated heuristic signals (e.g. CAPTCHA verification prompt + PowerShell instructions + Copy-paste direction) rather than isolated keywords.
4. **Resilient Manifest V3 Lifecycle**: The service worker is ephemeral; tab states and historical records persist safely across worker termination via `chrome.storage.session` and `chrome.storage.local`.

## Component Responsibilities

```
                                  [Webpage DOM]
                                        │
                                        ▼
                               [Content Script]
                     (DOM Observer + Page Content Scanner)
                                        │
                                        ▼ (Message: SCAN_RESULT)
                           [Background Service Worker]
                   (Validates, Checks Allowlist, Updates Badge)
                                        │
                      ┌─────────────────┴─────────────────┐
                      ▼                                   ▼
             [chrome.storage]                   [React Popup / Dashboard]
       (Local History & Per-Tab State)       (Visual Risk Gauge & Breakdown)
```

### 1. Isolated Content Script (`src/content/`)
- Injected at `document_start`.
- Extracts visible prompts, headings, and buttons safely.
- Observes DOM mutations with debouncing to detect dynamically generated ClickFix prompts.
- Emits structured `SCAN_RESULT` messages to the service worker.

### 2. Risk Engine (`src/engine/`)
- Evaluates signals against weighted categories.
- Deduplicates signal types to prevent score skew.
- Determines risk tiers: `LOW` (0–29), `SUSPICIOUS` (30–59), `HIGH` (60–79), and `CRITICAL` (80–100).

### 3. Background Coordinator (`src/background/`)
- Manages installation defaults and lifecycle recovery.
- Updates extension badges and desktop notifications for critical threats.
- Restricts and validates all message senders and payloads.

### 4. User Interfaces (`src/popup/`, `src/dashboard/`, `src/options/`)
- Cyberpunk brutalist / black-and-gold styling.
- Compact popup (< 400px width) for real-time threat verdicts.
- Full security dashboard tab for statistics, log history, and allowlist control.

