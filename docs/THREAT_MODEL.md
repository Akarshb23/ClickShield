# ClickShield — Threat Model & Security Boundaries

## Target Attack Vectors

### 1. ClickFix Social Engineering
- **Technique**: Attackers display deceptive prompts mimicking Cloudflare Turnstile, Google reCAPTCHA, or Microsoft verification dialogs.
- **Goal**: Coerce the user into opening the system Run dialog (`Win + R`), opening terminal/PowerShell, and pasting a copied payload.
- **ClickShield Defense**: Correlates verification language with command-execution patterns, alerts the user, and flags the session.

### 2. Clipboard Hijacking
- **Technique**: Hooking user clicks or keystrokes to overwrite the system clipboard with an obfuscated PowerShell or shell command (`irm | iex`).
- **ClickShield Defense**: Identifies clipboard copy requests accompanied by suspicious terminal syntax and provides explainable warnings.

## Explicit Non-Goals & Boundaries
- **Operating System Execution**: ClickShield operates strictly as a browser extension. It cannot prevent a user from pasting and executing code in an external terminal window if the user ignores browser warnings.
- **Tamper Resistance against Malicious Page Context**: Code running in the webpage MAIN world has execution freedom. ClickShield uses isolated content scripts and Shadow DOM to isolate its warnings from page styles, but browser extensions cannot guarantee total immunity from hostile DOM interference.
- **Antivirus Replacement**: ClickShield is an early-warning, pre-execution defense layer designed to detect deceptive interaction flows before the user leaves the browser.

