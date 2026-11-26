
import type { ThreatSignal } from "../../shared/types/signal";

import {
  CAPTCHA_KEYWORDS,
  LEGITIMATE_CAPTCHA_IFRAMES,
} from "../rules/captcha-rules";

// ==========================================================
// TYPES
// ==========================================================

export interface CaptchaScanContext {
  text: string;
  hasIframes: boolean;
  iframeSources: string[];
  hasFakeCheckbox: boolean;
}

interface TrustedProvider {
  hostname: string;
  pathname?: string;
}

// ==========================================================
// CONSTANTS
// ==========================================================

const MAX_TEXT_LENGTH = 100_000;

const MAX_IFRAME_SOURCES = 100;

// ==========================================================
// PROVIDER CONFIGURATION
// ==========================================================

/**
 * Parse configured CAPTCHA providers.
 *
 * Supported formats:
 * google.com/recaptcha
 * recaptcha.net
 * challenges.cloudflare.com
 *
 * Invalid configuration entries are ignored.
 */
function parseTrustedProviders(): TrustedProvider[] {
  const providers: TrustedProvider[] = [];

  for (const entry of LEGITIMATE_CAPTCHA_IFRAMES) {
    if (
      typeof entry !== "string" ||
      !entry.trim()
    ) {
      continue;
    }

    try {
      const normalized = entry.trim();

      // Configuration entries may optionally contain
      // an HTTPS scheme.
      if (
        /^[a-z][a-z0-9+.-]*:\/\//i.test(normalized) &&
        !/^https:\/\//i.test(normalized)
      ) {
        continue;
      }

      const url = new URL(
        /^https:\/\//i.test(normalized)
          ? normalized
          : `https://${normalized}`
      );

      if (
        url.protocol !== "https:" ||
        url.username ||
        url.password ||
        url.port ||
        url.search ||
        url.hash
      ) {
        continue;
      }

      const hostname = url.hostname
        .toLowerCase()
        .replace(/\.$/, "");

      if (
        !hostname ||
        !/^[a-z0-9.-]+$/.test(hostname) ||
        hostname.length > 253
      ) {
        continue;
      }

      const pathname =
        url.pathname === "/"
          ? undefined
          : url.pathname.replace(/\/+$/, "") || "/";

      providers.push({
        hostname,
        pathname,
      });
    } catch {
      // Ignore malformed provider configuration.
    }
  }

  return providers;
}

const TRUSTED_PROVIDERS = parseTrustedProviders();

// ==========================================================
// HOSTNAME VALIDATION
// ==========================================================

/**
 * Validate provider hostnames using exact domain boundaries.
 *
 * Allowed:
 * challenges.cloudflare.com
 * subdomain.challenges.cloudflare.com
 *
 * Rejected:
 * challenges.cloudflare.com.attacker.com
 * attacker-cloudflare.com
 * cloudflare.com.attacker.net
 */
function matchesProviderHostname(
  hostname: string,
  trustedHostname: string
): boolean {
  const normalizedHostname = hostname
    .toLowerCase()
    .replace(/\.$/, "");

  const normalizedTrustedHostname = trustedHostname
    .toLowerCase()
    .replace(/\.$/, "");

  return (
    normalizedHostname === normalizedTrustedHostname ||
    normalizedHostname.endsWith(
      `.${normalizedTrustedHostname}`
    )
  );
}

// ==========================================================
// PATH VALIDATION
// ==========================================================

/**
 * Validate provider-specific paths when configured.
 *
 * For example, Google's reCAPTCHA entry requires:
 * /recaptcha
 * /recaptcha/api2/anchor
 *
 * But rejects:
 * /recaptcha-malicious
 */
function matchesProviderPath(
  pathname: string,
  trustedPath?: string
): boolean {
  if (!trustedPath) {
    return true;
  }

  const normalizedPath = pathname.toLowerCase();

  const expectedPath = trustedPath
    .toLowerCase()
    .replace(/\/+$/, "") || "/";

  return (
    normalizedPath === expectedPath ||
    normalizedPath.startsWith(`${expectedPath}/`)
  );
}

// ==========================================================
// IFRAME VALIDATION
// ==========================================================

/**
 * Determine whether an iframe originates from a recognized
 * CAPTCHA provider.
 *
 * Security checks:
 * - Absolute URL required.
 * - HTTPS required.
 * - Credentials rejected.
 * - Non-standard ports rejected.
 * - Hostname boundary validation.
 * - Provider-specific path validation.
 *
 * Query strings and fragments never determine trust.
 */
function isLegitimateCaptchaIframe(
  source: string
): boolean {
  if (
    typeof source !== "string" ||
    !source.trim()
  ) {
    return false;
  }

  try {
    const url = new URL(source.trim());

    if (
      url.protocol !== "https:" ||
      url.username ||
      url.password ||
      url.port
    ) {
      return false;
    }

    const hostname = url.hostname
      .toLowerCase()
      .replace(/\.$/, "");

    if (!hostname) {
      return false;
    }

    return TRUSTED_PROVIDERS.some((provider) => {
      return (
        matchesProviderHostname(
          hostname,
          provider.hostname
        ) &&
        matchesProviderPath(
          url.pathname,
          provider.pathname
        )
      );
    });
  } catch {
    // Malformed or relative URLs are never trusted.
    return false;
  }
}

/**
 * Determine whether at least one iframe has been verified
 * against a configured trusted provider.
 */
function hasLegitimateCaptchaProvider(
  iframeSources: string[]
): boolean {
  return iframeSources
    .slice(0, MAX_IFRAME_SOURCES)
    .some(isLegitimateCaptchaIframe);
}

// ==========================================================
// TEXT NORMALIZATION
// ==========================================================

/**
 * Normalize page text before keyword matching.
 *
 * NFKC handles compatibility characters.
 * Whitespace normalization prevents formatting differences
 * from bypassing phrase matching.
 */
function normalizeCaptchaText(text: string): string {
  return text
    .slice(0, MAX_TEXT_LENGTH)
    .normalize("NFKC")
    .toLowerCase()
    .replace(/[\u200B-\u200D\uFEFF]/g, "")
    .replace(/\s+/g, " ")
    .trim();
}

// ==========================================================
// CAPTCHA CLAIM DETECTION
// ==========================================================

function claimsCaptchaVerification(
  normalizedText: string
): boolean {
  return CAPTCHA_KEYWORDS.some((keyword) => {
    if (
      typeof keyword !== "string" ||
      !keyword.trim()
    ) {
      return false;
    }

    const normalizedKeyword = keyword
      .normalize("NFKC")
      .toLowerCase()
      .replace(/\s+/g, " ")
      .trim();

    return normalizedText.includes(normalizedKeyword);
  });
}

// ==========================================================
// MANUAL VERIFICATION DIRECTIVES
// ==========================================================

/**
 * Instructions associated with deceptive manual verification.
 *
 * These are evaluated separately from legitimate provider
 * detection because attackers can embed a real CAPTCHA iframe
 * alongside a malicious verification overlay.
 */
const MANUAL_SOLVING_DIRECTIVES: string[] = [
  // General manual verification
  "follow these steps to verify",
  "manual verification steps",
  "verification code will be generated",
  "to prove you are not a robot follow",
  "press the buttons below to verify",
  "click verify and follow instructions",

  // Command and clipboard instructions
  "copy and paste to fix",
  "paste the verification command",
  "copy and paste the command to verify",
  "paste the command and press enter",
  "run the command below to verify",
  "run the command to complete verification",

  // Windows Run instructions
  "press win + r to verify",
  "press win+r to verify",
  "press the windows key and r",
  "open the run dialog to verify",
];

/**
 * Detect explicit manual solving instructions.
 */
function containsManualSolvingDirective(
  normalizedText: string
): boolean {
  return MANUAL_SOLVING_DIRECTIVES.some(
    (directive) =>
      normalizedText.includes(
        directive.normalize("NFKC").toLowerCase()
      )
  );
}

// ==========================================================
// SIGNAL CREATION
// ==========================================================

function createFakeCaptchaSignal(
  reason: string,
  snippet?: string
): ThreatSignal {
  return {
    type: "FAKE_CAPTCHA",
    reason,
    ...(snippet ? { snippet } : {}),
  };
}

// ==========================================================
// MAIN DETECTOR
// ==========================================================

export function detectCaptchaAnomalies(
  context: CaptchaScanContext
): ThreatSignal[] {
  const signals: ThreatSignal[] = [];

  // --------------------------------------------------------
  // 1. Validate scan context
  // --------------------------------------------------------

  if (
    !context ||
    typeof context.text !== "string" ||
    !Array.isArray(context.iframeSources)
  ) {
    return signals;
  }

  if (
    typeof context.hasFakeCheckbox !== "boolean"
  ) {
    return signals;
  }

  // --------------------------------------------------------
  // 2. Normalize page text
  // --------------------------------------------------------

  const normalizedText = normalizeCaptchaText(
    context.text
  );

  if (!normalizedText) {
    return signals;
  }

  // --------------------------------------------------------
  // 3. Detect CAPTCHA claims and fake interfaces
  // --------------------------------------------------------

  const claimsCaptcha =
    claimsCaptchaVerification(normalizedText);

  const hasFakeCheckbox =
    context.hasFakeCheckbox;

  /**
   * A fake checkbox or a CAPTCHA claim establishes
   * verification-related context.
   *
   * Avoid interpreting generic manual instructions on
   * unrelated pages as fake CAPTCHA behavior.
   */
  if (!claimsCaptcha && !hasFakeCheckbox) {
    return signals;
  }

  // --------------------------------------------------------
  // 4. Verify actual provider iframe origins
  // --------------------------------------------------------

  const hasLegitIframe =
    hasLegitimateCaptchaProvider(
      context.iframeSources
    );

  // --------------------------------------------------------
  // 5. Detect simulated verification interfaces
  // --------------------------------------------------------

  if (
    hasFakeCheckbox &&
    !hasLegitIframe
  ) {
    signals.push(
      createFakeCaptchaSignal(
        "Simulated verification interface detected without a verified legitimate CAPTCHA provider.",
        "Custom checkbox or button mimicking CAPTCHA controls."
      )
    );
  }

  // --------------------------------------------------------
  // 6. Detect manual execution instructions
  // --------------------------------------------------------

  const hasManualSolvingDirectives =
    containsManualSolvingDirective(normalizedText);

  if (hasManualSolvingDirectives) {
    signals.push(
      createFakeCaptchaSignal(
        "Deceptive verification prompt requests manual actions or command execution to complete CAPTCHA verification."
      )
    );
  }

  // --------------------------------------------------------
  // 7. Return detected signals
  // --------------------------------------------------------

  return signals;
}
