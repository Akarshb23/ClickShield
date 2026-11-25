# ClickShield — Heuristic Detection Rules & Scoring Model

## Weighted Risk Scoring Model

Each detected category adds its configured weight to the raw score. Duplicate instances of the same category are deduplicated to avoid score skew. Total score is clamped to a maximum of 100.

| Threat Signal | Weight | Detection Criteria |
| :--- | :---: | :--- |
| `FAKE_CAPTCHA` | **+20** | Deceptive checkbox or verification text without legitimate provider iframes (`challenges.cloudflare.com`, `recaptcha.net`). |
| `SUSPICIOUS_INSTRUCTION` | **+15** | Page directs user to open Run dialog (`Win + R`), launch terminal, or paste and press Enter. |
| `CLIPBOARD_MANIPULATION` | **+25** | Programmatic `writeText` call or copy button interaction linked with command syntax. |
| `EXECUTION_INSTRUCTION` | **+25** | Encoded PowerShell, `-WindowStyle Hidden`, `irm | iex`, LOLBins (`mshta`, `certutil`), or remote shell pipes. |
| `DOMAIN_IMPERSONATION` | **+15** | Page displays Cloudflare Turnstile, Microsoft, Google, or Apple branding on an unrelated hostname. |
| `SUSPICIOUS_DOMAIN` | **+10** | High-abuse TLDs (`.top`, `.zip`, `.click`, `.xyz`), Punycode (`xn--`), or excessive subdomain depth. |

---

## Risk Level Tiers

| Score Range | Classification | Badge Color | System Action |
| :---: | :---: | :---: | :--- |
| **0 – 29** | `LOW` | `#16A34A` (Green) | Passive monitoring. No intrusive alerts. |
| **30 – 59** | `SUSPICIOUS` | `#D4A32C` (Amber) | Amber badge on extension icon. Contextual caution logged in popup. |
| **60 – 79** | `HIGH` | `#EA580C` (Orange) | Orange badge. Prominent threat breakdown displayed in popup. |
| **80 – 100** | `CRITICAL` | `#DC2626` (Red) | Red badge + system notification + **Shadow DOM Intervention Overlay**. |

---

## Behavioral Correlation Matrix

The **Signal Correlator** distinguishes between harmless technical articles and active ClickFix attacks:

$$\text{ClickFix Attack} = (\text{FAKE\_CAPTCHA} \land \text{EXECUTION\_INSTRUCTION}) \lor (\text{SUSPICIOUS\_INSTRUCTION} \land \text{EXECUTION\_INSTRUCTION})$$

- **Developer Article**: Discusses PowerShell $\to$ `EXECUTION_INSTRUCTION` only (Weight 25, score 25 $\implies$ `LOW` risk). **No intervention triggered.**
- **ClickFix Attack**: Claims human verification $\to$ instructs `Win + R` $\to$ copies PowerShell $\implies$ `FAKE_CAPTCHA` (20) + `SUSPICIOUS_INSTRUCTION` (15) + `EXECUTION_INSTRUCTION` (25) + `CLIPBOARD_MANIPULATION` (25) = **85** (`CRITICAL`). **Active intervention triggered.**

