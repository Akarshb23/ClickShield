
import type { ThreatSignal } from "../../shared/types/signal";

import {
  SUSPICIOUS_TLDS,
  TRUSTED_DOMAINS,
} from "../rules/domain-rules";

import {
  LEGITIMATE_CAPTCHA_IFRAMES,
} from "../rules/captcha-rules";

// ==========================================================
// CONSTANTS
// ==========================================================

const DECEPTIVE_SUBDOMAIN_PATTERN =
  /^(?:turnstile|captcha|recaptcha|cf-verify|human-verify|cloudflare-check|anti-bot|security-check)(?:[.-]|$)/i;

const SUSPICIOUS_HOST_TOKENS = new Set([
  "login",
  "signin",
  "verify",
  "verification",
  "captcha",
  "security",
  "account",
  "auth",
  "update",
  "challenge",
  "human",
  "official",
]);

const NORMALIZED_SUSPICIOUS_TLDS = new Set(
  SUSPICIOUS_TLDS.map((tld) =>
    tld.toLowerCase().replace(/^\./, "")
  )
);

// ==========================================================
// TRUSTED DOMAIN CONFIGURATION
// ==========================================================

/**
 * Extract provider hostnames from CAPTCHA rules.
 *
 * Supports entries such as:
 * google.com/recaptcha
 * recaptcha.net
 * challenges.cloudflare.com
 */
function getCaptchaProviderDomains(): string[] {
  return LEGITIMATE_CAPTCHA_IFRAMES.map((entry) => {
    return entry
      .trim()
      .toLowerCase()
      .replace(/^https?:\/\//, "")
      .split("/")[0]
      .replace(/\.$/, "");
  }).filter(Boolean);
}

const TRUSTED_HOST_DOMAINS = [
  ...TRUSTED_DOMAINS,
  ...getCaptchaProviderDomains(),
].map((domain) => domain.toLowerCase());

// ==========================================================
// HOSTNAME NORMALIZATION
// ==========================================================

/**
 * Normalize a hostname.
 *
 * The detector normally receives window.location.hostname,
 * but also safely supports an absolute HTTP/HTTPS URL.
 */
function normalizeHostname(input: string): string {
  if (typeof input !== "string") return "";

  const candidate = input.trim().toLowerCase();

  if (!candidate) return "";

  try {
    const parsed = candidate.includes("://")
      ? new URL(candidate)
      : new URL(`http://${candidate}`);

    if (
      parsed.username ||
      parsed.password ||
      parsed.port ||
      parsed.pathname !== "/" ||
      parsed.search ||
      parsed.hash
    ) {
      // Hostname inputs must not contain URL components.
      if (!candidate.includes("://")) return "";
    }

    if (
      parsed.protocol !== "http:" &&
      parsed.protocol !== "https:"
    ) {
      return "";
    }

    return parsed.hostname
      .toLowerCase()
      .replace(/\.$/, "");
  } catch {
    return "";
  }
}

// ==========================================================
// LOCAL HOST VALIDATION
// ==========================================================

function isLocalHostname(hostname: string): boolean {
  return (
    hostname === "localhost" ||
    hostname === "127.0.0.1" ||
    hostname === "[::1]" ||
    hostname === "::1" ||
    hostname === "local-file"
  );
}

// ==========================================================
// TRUSTED HOST VALIDATION
// ==========================================================

/**
 * Only trust an exact configured hostname or its genuine
 * subdomains.
 *
 * Never use substring matching.
 */
function isTrustedHostname(hostname: string): boolean {
  return TRUSTED_HOST_DOMAINS.some((domain) => {
    return (
      hostname === domain ||
      hostname.endsWith(`.${domain}`)
    );
  });
}

// ==========================================================
// IPV4 VALIDATION
// ==========================================================

function parseIPv4(hostname: string): number[] | null {
  const match = hostname.match(
    /^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/
  );

  if (!match) return null;

  const octets = match.slice(1).map(Number);

  if (
    octets.some(
      (octet) =>
        !Number.isInteger(octet) ||
        octet < 0 ||
        octet > 255
    )
  ) {
    return null;
  }

  return octets;
}

function ipv4ToNumber(octets: number[]): number {
  return (
    octets[0] * 16777216 +
    octets[1] * 65536 +
    octets[2] * 256 +
    octets[3]
  );
}

/**
 * Determine whether an IPv4 address belongs to a
 * private, loopback, reserved or special-purpose range.
 *
 * Such addresses must not be treated as public IP threats
 * merely because they are accessed directly.
 */
function isNonPublicIPv4(
  octets: number[]
): boolean {
  const ip = ipv4ToNumber(octets);

  const ranges: Array<[number, number]> = [
    [0x00000000, 0x00ffffff], // 0.0.0.0/8
    [0x0a000000, 0x0affffff], // 10.0.0.0/8
    [0x64400000, 0x647fffff], // 100.64.0.0/10
    [0x7f000000, 0x7fffffff], // 127.0.0.0/8
    [0xa9fe0000, 0xa9feffff], // 169.254.0.0/16
    [0xac100000, 0xac1fffff], // 172.16.0.0/12
    [0xc0000000, 0xc00000ff], // 192.0.0.0/24
    [0xc0000200, 0xc00002ff], // 192.0.2.0/24
    [0xc0586300, 0xc05863ff], // 192.88.99.0/24
    [0xc0a80000, 0xc0a8ffff], // 192.168.0.0/16
    [0xc6120000, 0xc613ffff], // 198.18.0.0/15
    [0xc6336400, 0xc63364ff], // 198.51.100.0/24
    [0xcb007100, 0xcb0071ff], // 203.0.113.0/24
    [0xe0000000, 0xefffffff], // 224.0.0.0/4
    [0xf0000000, 0xffffffff], // Reserved / broadcast
  ];

  return ranges.some(
    ([start, end]) => ip >= start && ip <= end
  );
}

// ==========================================================
// IPV6 VALIDATION
// ==========================================================

function isNonPublicIPv6(hostname: string): boolean {
  const address = hostname
    .replace(/^\[|\]$/g, "")
    .toLowerCase();

  // Loopback and unspecified addresses.
  if (
    address === "::1" ||
    address === "::"
  ) {
    return true;
  }

  // Unique local addresses: fc00::/7.
  if (/^f[cd]/i.test(address)) {
    return true;
  }

  // Link-local addresses: fe80::/10.
  if (/^fe[89ab]/i.test(address)) {
    return true;
  }

  // Multicast addresses: ff00::/8.
  if (/^ff/i.test(address)) {
    return true;
  }

  // Documentation range: 2001:db8::/32.
  if (/^2001:0?db8:/i.test(address)) {
    return true;
  }

  // This detector only classifies global-unicast
  // candidates in the 2000::/3 range as public.
  return !/^[23]/i.test(address);
}

// ==========================================================
// PUBLIC IP DETECTION
// ==========================================================

function detectPublicIP(
  hostname: string
): ThreatSignal | null {
  const ipv4 = parseIPv4(hostname);

  if (ipv4) {
    if (isNonPublicIPv4(ipv4)) {
      return null;
    }

    return {
      type: "SUSPICIOUS_DOMAIN",
      reason:
        "Website accessed directly via raw public IP address without domain resolution.",
      snippet: `Public IP: ${hostname}`,
    };
  }

  if (
    hostname.startsWith("[") &&
    hostname.endsWith("]")
  ) {
    if (isNonPublicIPv6(hostname)) {
      return null;
    }

    return {
      type: "SUSPICIOUS_DOMAIN",
      reason:
        "Website accessed directly using a public IPv6 address instead of a domain name.",
      snippet: `Public IPv6: ${hostname}`,
    };
  }

  return null;
}

// ==========================================================
// SUSPICIOUS TLD DETECTION
// ==========================================================

function detectSuspiciousTLD(
  hostname: string
): ThreatSignal | null {
  const labels = hostname.split(".");

  const finalLabel = labels[labels.length - 1];

  if (!NORMALIZED_SUSPICIOUS_TLDS.has(finalLabel)) {
    return null;
  }

  return {
    type: "SUSPICIOUS_DOMAIN",
    reason:
      `Domain uses a TLD associated with elevated abuse (${finalLabel}).`,
    snippet: `TLD: .${finalLabel}`,
  };
}

// ==========================================================
// DECEPTIVE SUBDOMAIN DETECTION
// ==========================================================

function detectDeceptiveSubdomain(
  hostname: string
): ThreatSignal | null {
  const labels = hostname.split(".");

  const firstLabel = labels[0];

  if (
    !DECEPTIVE_SUBDOMAIN_PATTERN.test(firstLabel)
  ) {
    return null;
  }

  return {
    type: "SUSPICIOUS_DOMAIN",
    reason:
      "Domain uses a deceptive CAPTCHA or security-verification hostname outside recognized provider infrastructure.",
    snippet: hostname,
  };
}

// ==========================================================
// INTERNATIONALIZED DOMAIN ANALYSIS
// ==========================================================

/**
 * Punycode alone is not evidence of malicious behavior.
 *
 * Internationalized domains can be completely legitimate.
 * Brand-specific lookalike detection is handled separately
 * by the impersonation detector.
 */
function hasInternationalizedLabel(
  hostname: string
): boolean {
  return hostname
    .split(".")
    .some((label) => label.startsWith("xn--"));
}

// ==========================================================
// SUBDOMAIN STRUCTURE ANALYSIS
// ==========================================================

function detectExcessiveSubdomains(
  hostname: string
): ThreatSignal | null {
  const parts = hostname.split(".");

  if (parts.length < 5) {
    return null;
  }

  const hasSuspiciousTokens = parts
    .slice(0, -2)
    .some((label) => {
      const tokens = label.split(/[-_]/);

      return tokens.some((token) =>
        SUSPICIOUS_HOST_TOKENS.has(token)
      );
    });

  if (!hasSuspiciousTokens) {
    return null;
  }

  return {
    type: "SUSPICIOUS_DOMAIN",
    reason:
      "Deep hostname hierarchy combined with suspicious authentication or verification labels may conceal the actual domain origin.",
    snippet: `${parts.length} domain labels with suspicious hostname indicators.`,
  };
}

// ==========================================================
// MAIN DETECTOR
// ==========================================================

export function detectDomainAnomalies(
  hostname: string
): ThreatSignal[] {
  const signals: ThreatSignal[] = [];

  // --------------------------------------------------------
  // 1. Normalize input
  // --------------------------------------------------------

  const cleanHost = normalizeHostname(hostname || "");

  if (!cleanHost || isLocalHostname(cleanHost)) {
    return signals;
  }

  // --------------------------------------------------------
  // 2. Exclude explicitly trusted domains
  // --------------------------------------------------------

  if (isTrustedHostname(cleanHost)) {
    return signals;
  }

  // --------------------------------------------------------
  // 3. Direct public IP detection
  // --------------------------------------------------------

  const ipSignal = detectPublicIP(cleanHost);

  if (ipSignal) {
    signals.push(ipSignal);
  }

  // --------------------------------------------------------
  // 4. Suspicious TLD detection
  // --------------------------------------------------------

  const tldSignal = detectSuspiciousTLD(cleanHost);

  if (tldSignal) {
    signals.push(tldSignal);
  }

  // --------------------------------------------------------
  // 5. Deceptive verification subdomains
  // --------------------------------------------------------

  const subdomainSignal =
    detectDeceptiveSubdomain(cleanHost);

  if (subdomainSignal) {
    signals.push(subdomainSignal);
  }

  // --------------------------------------------------------
  // 6. Internationalized domain awareness
  // --------------------------------------------------------

  if (hasInternationalizedLabel(cleanHost)) {
    // Do not flag punycode by itself.
    // The impersonation detector handles known brand
    // lookalikes separately.
  }

  // --------------------------------------------------------
  // 7. Suspicious hostname hierarchy
  // --------------------------------------------------------

  const hierarchySignal =
    detectExcessiveSubdomains(cleanHost);

  if (hierarchySignal) {
    signals.push(hierarchySignal);
  }

  return signals;
}
