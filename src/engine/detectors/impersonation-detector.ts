
import type { ThreatSignal } from "../../shared/types/signal";

// ==========================================================
// TYPES
// ==========================================================

interface BrandPattern {
  name: string;
  claimRegex: RegExp;
  legitimateDomains: string[];
  hostAliases?: string[];
}

interface HostAnalysis {
  hostname: string;
  labels: string[];
  decodedLabels: string[];
  tokens: string[];
}

// ==========================================================
// BRAND DATABASE
// ==========================================================

const MONITORED_BRANDS: BrandPattern[] = [
  {
    name: "Cloudflare",
    claimRegex:
      /\b(cloudflare\s+(turnstile|ddos|protection|ray\s*id)|checking\s+your\s+browser\s+before\s+accessing|ddos-guard)\b/i,
    legitimateDomains: [
      "cloudflare.com",
      "cloudflare-ipfs.com",
      "challenges.cloudflare.com",
    ],
  },
  {
    name: "Microsoft",
    claimRegex:
      /\b(microsoft\s+(support|security|windows\s+defender|account\s+verification)|windows\s+security\s+center|windows\s+update\s+required)\b/i,
    legitimateDomains: [
      "microsoft.com",
      "live.com",
      "office.com",
      "azure.com",
    ],
  },
  {
    name: "Google",
    claimRegex:
      /\b(google\s+(recaptcha|security\s+alert|workspace\s+verification|meet\s+audio\s+error))\b/i,
    legitimateDomains: [
      "google.com",
      "recaptcha.net",
      "gstatic.com",
    ],
  },
  {
    name: "Apple",
    claimRegex:
      /\b(apple\s+id\s+verification|icloud\s+security\s+checkpoint)\b/i,
    legitimateDomains: [
      "apple.com",
      "icloud.com",
    ],
  },
  {
    name: "Discord",
    claimRegex:
      /\b(discord\s+(verification|security\s+bot|human\s+check))\b/i,
    legitimateDomains: [
      "discord.com",
      "discordapp.com",
      "discord.gg",
    ],
  },
  {
    name: "Zoom",
    claimRegex:
      /\b(zoom\s+(audio\s+fix|connection\s+issue|meeting\s+verification))\b/i,
    legitimateDomains: [
      "zoom.us",
    ],
  },
  {
    name: "MetaMask",
    claimRegex:
      /\b(metamask\s+(security\s+update|wallet\s+verification))\b/i,
    legitimateDomains: [
      "metamask.io",
    ],
  },
  {
    name: "Steam",
    claimRegex:
      /\b(steam\s+(guard\s+verification|account\s+security\s+alert))\b/i,
    legitimateDomains: [
      "steampowered.com",
      "steamcommunity.com",
    ],
  },
];

// ==========================================================
// SUSPICIOUS HOSTNAME KEYWORDS
// ==========================================================

const SUSPICIOUS_HOST_TOKENS = new Set([
  "login",
  "signin",
  "verify",
  "verification",
  "security",
  "support",
  "update",
  "account",
  "captcha",
  "challenge",
  "wallet",
  "auth",
  "recovery",
  "confirm",
  "unlock",
  "restore",
  "official",
  "validation",
]);

// ==========================================================
// HOSTNAME NORMALIZATION
// ==========================================================

/**
 * Accepts either a hostname or an absolute HTTP/HTTPS URL.
 *
 * Invalid input is rejected rather than partially parsed.
 */
function normalizeHostname(input: string): string {
  if (typeof input !== "string") {
    return "";
  }

  const candidate = input.trim();

  if (!candidate || candidate.length > 2048) {
    return "";
  }

  try {
    let parsed: URL;

    if (/^https?:\/\//i.test(candidate)) {
      parsed = new URL(candidate);
    } else {
      // A bare hostname must not contain URL components.
      if (/[\/\\?#@\s]/.test(candidate)) {
        return "";
      }

      parsed = new URL(`https://${candidate}`);

      // A hostname input must not include an explicit port.
      if (parsed.port) {
        return "";
      }
    }

    if (
      parsed.protocol !== "http:" &&
      parsed.protocol !== "https:"
    ) {
      return "";
    }

    if (parsed.username || parsed.password) {
      return "";
    }

    const hostname = parsed.hostname
      .toLowerCase()
      .replace(/\.$/, "");

    if (!hostname || hostname.length > 253) {
      // Bracketed IPv6 addresses are handled separately.
      if (
        !hostname.startsWith("[") ||
        !hostname.endsWith("]")
      ) {
        return "";
      }
    }

    return hostname;
  } catch {
    return "";
  }
}

function isLocalHostname(hostname: string): boolean {
  return (
    hostname === "localhost" ||
    hostname === "127.0.0.1" ||
    hostname === "::1" ||
    hostname === "[::1]" ||
    hostname === "local-file"
  );
}

// ==========================================================
// PUNYCODE DECODING
// ==========================================================

const PUNYCODE_BASE = 36;
const PUNYCODE_TMIN = 1;
const PUNYCODE_TMAX = 26;
const PUNYCODE_SKEW = 38;
const PUNYCODE_DAMP = 700;
const PUNYCODE_INITIAL_BIAS = 72;
const PUNYCODE_INITIAL_N = 128;

/**
 * Converts a Punycode digit into its numeric value.
 *
 * a-z => 0-25
 * 0-9 => 26-35
 */
function decodePunycodeDigit(
  character: string
): number {
  const code = character.toLowerCase().charCodeAt(0);

  if (code >= 97 && code <= 122) {
    return code - 97;
  }

  if (code >= 48 && code <= 57) {
    return code - 48 + 26;
  }

  return -1;
}

/**
 * Implements the Punycode bias adaptation algorithm.
 */
function adaptPunycodeBias(
  delta: number,
  numberOfPoints: number,
  firstTime: boolean
): number {
  delta = firstTime
    ? Math.floor(delta / PUNYCODE_DAMP)
    : Math.floor(delta / 2);

  delta += Math.floor(delta / numberOfPoints);

  let k = 0;

  while (
    delta >
    ((PUNYCODE_BASE - PUNYCODE_TMIN) *
      PUNYCODE_TMAX) /
      2
  ) {
    delta = Math.floor(
      delta / (PUNYCODE_BASE - PUNYCODE_TMIN)
    );

    k += PUNYCODE_BASE;
  }

  return (
    k +
    Math.floor(
      ((PUNYCODE_BASE - PUNYCODE_TMIN + 1) *
        delta) /
        (delta + PUNYCODE_SKEW)
    )
  );
}

/**
 * Decodes one xn-- hostname label.
 *
 * Returns the original label if decoding fails.
 * This prevents malformed Punycode from breaking scanning.
 */
function decodePunycodeLabel(label: string): string {
  if (!label.startsWith("xn--")) {
    return label;
  }

  const input = label.slice(4);

  if (!input) {
    return label;
  }

  const output: number[] = [];

  let index = 0;
  let n = PUNYCODE_INITIAL_N;
  let i = 0;
  let bias = PUNYCODE_INITIAL_BIAS;

  const delimiter = input.lastIndexOf("-");

  if (delimiter >= 0) {
    for (const character of input.slice(0, delimiter)) {
      const code = character.charCodeAt(0);

      if (code > 0x7f) {
        return label;
      }

      output.push(code);
    }

    index = delimiter + 1;
  }

  try {
    while (index < input.length) {
      const oldI = i;
      let weight = 1;

      for (
        let k = PUNYCODE_BASE;
        ;
        k += PUNYCODE_BASE
      ) {
        if (index >= input.length) {
          return label;
        }

        const digit = decodePunycodeDigit(
          input[index++]
        );

        if (digit < 0) {
          return label;
        }

        if (
          digit >
          Math.floor(
            (Number.MAX_SAFE_INTEGER - i) / weight
          )
        ) {
          return label;
        }

        i += digit * weight;

        const threshold =
          k <= bias
            ? PUNYCODE_TMIN
            : k >= bias + PUNYCODE_TMAX
              ? PUNYCODE_TMAX
              : k - bias;

        if (digit < threshold) {
          break;
        }

        const multiplier = PUNYCODE_BASE - threshold;

        if (
          weight >
          Math.floor(
            Number.MAX_SAFE_INTEGER / multiplier
          )
        ) {
          return label;
        }

        weight *= multiplier;
      }

      const numberOfPoints = output.length + 1;

      bias = adaptPunycodeBias(
        i - oldI,
        numberOfPoints,
        oldI === 0
      );

      const codePointIncrease = Math.floor(
        i / numberOfPoints
      );

      if (
        codePointIncrease >
        Number.MAX_SAFE_INTEGER - n
      ) {
        return label;
      }

      n += codePointIncrease;
      i %= numberOfPoints;

      if (
        n > 0x10ffff ||
        (n >= 0xd800 && n <= 0xdfff)
      ) {
        return label;
      }

      output.splice(i, 0, n);
      i++;
    }

    return String.fromCodePoint(...output);
  } catch {
    return label;
  }
}

// ==========================================================
// UNICODE CONFUSABLE NORMALIZATION
// ==========================================================

/**
 * Maps commonly abused Cyrillic and Greek homoglyphs
 * to their visually similar Latin equivalents.
 *
 * This is a targeted heuristic, not a complete Unicode
 * confusables database.
 */
const UNICODE_CONFUSABLES = new Map<string, string>([
  // Cyrillic
  ["а", "a"],
  ["в", "b"],
  ["с", "c"],
  ["ԁ", "d"],
  ["е", "e"],
  ["һ", "h"],
  ["і", "i"],
  ["ј", "j"],
  ["к", "k"],
  ["м", "m"],
  ["о", "o"],
  ["р", "p"],
  ["ԛ", "q"],
  ["ѕ", "s"],
  ["т", "t"],
  ["у", "y"],
  ["х", "x"],
  ["ӏ", "l"],

  // Greek
  ["α", "a"],
  ["β", "b"],
  ["ϲ", "c"],
  ["ε", "e"],
  ["ι", "i"],
  ["κ", "k"],
  ["ο", "o"],
  ["ρ", "p"],
  ["τ", "t"],
  ["υ", "u"],
  ["χ", "x"],
]);

/**
 * Normalizes compatibility characters, Unicode homoglyphs
 * and common ASCII substitutions.
 */
function normalizeConfusables(value: string): string {
  const normalized = value
    .normalize("NFKC")
    .toLowerCase();

  const unicodeNormalized = Array.from(
    normalized,
    (character) =>
      UNICODE_CONFUSABLES.get(character) ?? character
  ).join("");

  return unicodeNormalized
    .replace(/0/g, "o")
    .replace(/1/g, "i")
    .replace(/3/g, "e")
    .replace(/5/g, "s")
    .replace(/@/g, "a");
}

// ==========================================================
// HOSTNAME ANALYSIS
// ==========================================================

function analyzeHostname(
  hostname: string
): HostAnalysis {
  const normalized = normalizeHostname(hostname);

  const labels = normalized
    .split(".")
    .filter(Boolean);

  const decodedLabels = labels.map(
    decodePunycodeLabel
  );

  const tokens = decodedLabels.flatMap((label) =>
    label
      .split(/[-_]/)
      .filter(Boolean)
      .map(normalizeConfusables)
  );

  return {
    hostname: normalized,
    labels,
    decodedLabels,
    tokens,
  };
}

// ==========================================================
// LEGITIMATE DOMAIN VALIDATION
// ==========================================================

/**
 * Only accepts an exact trusted domain or a genuine
 * subdomain of that domain.
 *
 * cloudflare.com                  -> trusted
 * challenges.cloudflare.com       -> trusted
 * cloudflare.com.attacker.net     -> rejected
 * attacker-cloudflare.com         -> rejected
 */
function isLegitimateBrandDomain(
  hostname: string,
  legitimateDomains: string[]
): boolean {
  return legitimateDomains.some((domain) => {
    const trustedDomain = domain
      .toLowerCase()
      .trim()
      .replace(/\.$/, "");

    return (
      hostname === trustedDomain ||
      hostname.endsWith(`.${trustedDomain}`)
    );
  });
}

// ==========================================================
// EDIT DISTANCE
// ==========================================================

/**
 * Calculates Levenshtein edit distance using two rows
 * rather than allocating a full two-dimensional matrix.
 */
function levenshteinDistance(
  first: string,
  second: string
): number {
  if (first === second) return 0;

  if (!first.length) return second.length;

  if (!second.length) return first.length;

  let previous = Array.from(
    { length: second.length + 1 },
    (_, index) => index
  );

  let current = new Array<number>(
    second.length + 1
  );

  for (let i = 1; i <= first.length; i++) {
    current[0] = i;

    for (let j = 1; j <= second.length; j++) {
      const cost =
        first[i - 1] === second[j - 1] ? 0 : 1;

      current[j] = Math.min(
        current[j - 1] + 1,
        previous[j] + 1,
        previous[j - 1] + cost
      );
    }

    [previous, current] = [current, previous];
  }

  return previous[second.length];
}

// ==========================================================
// BRAND HOSTNAME MATCHING
// ==========================================================

function getBrandToken(
  brand: BrandPattern
): string {
  return normalizeConfusables(
    brand.name.replace(/[^a-z0-9]/gi, "")
  );
}

/**
 * Detects an exact brand identifier in the decoded
 * hostname tokens.
 *
 * Examples:
 * microsoft-login.example
 * cloudflare-verify.example
 * xn--<unicode-lookalike>.example
 */
function hasExactBrandHostToken(
  analysis: HostAnalysis,
  brand: BrandPattern
): boolean {
  const aliases = [
    getBrandToken(brand),
    ...(brand.hostAliases || []).map(
      normalizeConfusables
    ),
  ];

  return analysis.tokens.some((token) =>
    aliases.includes(token)
  );
}

/**
 * Detects a misspelled brand identifier.
 *
 * A lookalike spelling requires additional suspicious
 * hostname context before it becomes a signal.
 */
function hasTyposquattedBrand(
  analysis: HostAnalysis,
  brand: BrandPattern
): boolean {
  const brandToken = getBrandToken(brand);

  return analysis.tokens.some((token) => {
    const candidate = normalizeConfusables(token);

    if (
      candidate.length < 5 ||
      candidate === brandToken
    ) {
      return false;
    }

    const distance = levenshteinDistance(
      candidate,
      brandToken
    );

    const maximumDistance =
      brandToken.length >= 8 ? 2 : 1;

    return (
      distance > 0 &&
      distance <= maximumDistance
    );
  });
}

// ==========================================================
// SUSPICIOUS HOSTNAME CONTEXT
// ==========================================================

function hasSuspiciousHostContext(
  analysis: HostAnalysis
): boolean {
  return analysis.tokens.some((token) =>
    SUSPICIOUS_HOST_TOKENS.has(token)
  );
}

// ==========================================================
// BRAND CLAIM ANALYSIS
// ==========================================================

function hasProminentBrandClaim(
  pageText: string,
  brand: BrandPattern
): boolean {
  // Compatibility normalization helps with full-width
  // characters, while the regex remains brand-specific.
  const normalizedText = pageText.normalize("NFKC");

  return brand.claimRegex.test(normalizedText);
}

// ==========================================================
// SIGNAL CREATION
// ==========================================================

function createBrandSignal(
  brand: BrandPattern,
  hostname: string,
  reason: string
): ThreatSignal {
  return {
    type: "DOMAIN_IMPERSONATION",
    reason:
      `Potential ${brand.name} impersonation detected on ` +
      `${hostname}: ${reason}`,
    snippet: `Claimed brand: ${brand.name}`,
  };
}

// ==========================================================
// MAIN DETECTOR
// ==========================================================

export function detectBrandImpersonation(
  pageText: string,
  hostname: string
): ThreatSignal[] {
  const signals: ThreatSignal[] = [];

  // --------------------------------------------------------
  // 1. Validate input
  // --------------------------------------------------------

  if (
    typeof pageText !== "string" ||
    typeof hostname !== "string"
  ) {
    return signals;
  }

  const analysis = analyzeHostname(hostname);
  const cleanHost = analysis.hostname;

  if (
    !cleanHost ||
    isLocalHostname(cleanHost)
  ) {
    return signals;
  }

  // Limit input size to prevent unnecessarily expensive
  // text processing.
  const normalizedPageText = pageText
    .slice(0, 20000);

  // --------------------------------------------------------
  // 2. Evaluate each monitored brand
  // --------------------------------------------------------

  for (const brand of MONITORED_BRANDS) {
    // ------------------------------------------------------
    // A. Exclude explicitly trusted brand domains
    // ------------------------------------------------------

    if (
      isLegitimateBrandDomain(
        cleanHost,
        brand.legitimateDomains
      )
    ) {
      continue;
    }

    // ------------------------------------------------------
    // B. Analyze prominent brand claims
    // ------------------------------------------------------

    const hasBrandClaim = hasProminentBrandClaim(
      normalizedPageText,
      brand
    );

    // ------------------------------------------------------
    // C. Analyze hostname indicators
    // ------------------------------------------------------

    const hasExactBrandToken =
      hasExactBrandHostToken(analysis, brand);

    const hasSuspiciousContext =
      hasSuspiciousHostContext(analysis);

    const hasTyposquat =
      hasTyposquattedBrand(analysis, brand);

    // ------------------------------------------------------
    // D. Determine impersonation
    // ------------------------------------------------------

    let reason: string | null = null;

    if (hasBrandClaim) {
      reason =
        "Page prominently claims brand-specific security, verification or service functionality on an unrelated hostname.";
    } else if (hasExactBrandToken) {
      reason =
        "Hostname contains a monitored brand identifier outside its trusted domains.";
    } else if (
      hasTyposquat &&
      hasSuspiciousContext
    ) {
      reason =
        "Hostname contains a Unicode or spelling-based lookalike of a monitored brand together with suspicious authentication or verification terminology.";
    }

    if (!reason) {
      continue;
    }

    signals.push(
      createBrandSignal(
        brand,
        cleanHost,
        reason
      )
    );
  }

  return signals;
}
