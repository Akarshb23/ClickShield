
import { logger } from "../shared/utils/logger";

// ==========================================================
// CONSTANTS
// ==========================================================

const ALLOWLIST_KEY = "clickshield_allowlist";

const MAX_DOMAIN_LENGTH = 253;

// Common public suffixes that must not be allowlisted
// as standalone entries.
const COMMON_PUBLIC_SUFFIXES = new Set([
  "co.uk",
  "org.uk",
  "gov.uk",
  "ac.uk",
  "com.au",
  "net.au",
  "org.au",
  "edu.au",
  "co.in",
  "firm.in",
  "net.in",
  "org.in",
  "gen.in",
  "ind.in",
  "co.nz",
  "org.nz",
  "net.nz",
  "ac.nz",
  "com.br",
  "com.mx",
  "co.jp",
  "ne.jp",
  "or.jp",
  "com.cn",
  "net.cn",
  "org.cn",
]);

// ==========================================================
// DOMAIN NORMALIZATION
// ==========================================================

function isIPv4(hostname: string): boolean {
  const parts = hostname.split(".");

  if (parts.length !== 4) return false;

  return parts.every((part) => {
    if (!/^\d{1,3}$/.test(part)) return false;

    const value = Number(part);

    return value >= 0 && value <= 255;
  });
}

function isIPv6(hostname: string): boolean {
  return (
    hostname.startsWith("[") &&
    hostname.endsWith("]")
  );
}

/**
 * Normalize a hostname into a canonical form.
 *
 * Accepted:
 * - example.com
 * - portal.example.com
 * - internal.corp
 * - localhost
 * - Valid IPv4 addresses
 * - Valid bracketed IPv6 addresses
 *
 * Rejected:
 * - Full URLs
 * - Wildcard domains
 * - Paths and query strings
 * - Credentials
 * - Ports
 * - Invalid DNS labels
 * - Common public suffixes
 */
function normalizeDomain(input: unknown): string | null {
  if (typeof input !== "string") return null;

  const candidate = input.trim();

  if (!candidate || candidate.length > MAX_DOMAIN_LENGTH) {
    return null;
  }

  // Reject URL components and wildcard entries.
  if (
    /[\s/?#@\\*]/.test(candidate) ||
    candidate.includes("://")
  ) {
    return null;
  }

  // IPv6 addresses require brackets.
  if (
    candidate.includes(":") &&
    !candidate.startsWith("[")
  ) {
    return null;
  }

  try {
    const parsed = new URL(`https://${candidate}`);

    if (
      parsed.protocol !== "https:" ||
      parsed.username ||
      parsed.password ||
      parsed.port ||
      parsed.pathname !== "/" ||
      parsed.search ||
      parsed.hash
    ) {
      return null;
    }

    const hostname = parsed.hostname
      .toLowerCase()
      .replace(/\.$/, "");

    if (!hostname || hostname.length > MAX_DOMAIN_LENGTH) {
      return null;
    }

    // Localhost is permitted as an exact host.
    if (hostname === "localhost") {
      return hostname;
    }

    // Validate IPv4 addresses.
    if (isIPv4(hostname)) {
      // Prevent non-canonical representations such as 127.1.
      if (
        candidate.replace(/\.$/, "") !== hostname
      ) {
        return null;
      }

      return hostname;
    }

    // Validate IPv6 addresses.
    if (isIPv6(hostname)) {
      return hostname;
    }

    // IPv4-like or malformed numeric hostnames are rejected.
    if (/^[\d.]+$/.test(hostname)) {
      return null;
    }

    const labels = hostname.split(".");

    // Require a fully qualified hostname.
    if (labels.length < 2) {
      return null;
    }

    for (const label of labels) {
      if (
        label.length === 0 ||
        label.length > 63 ||
        !/^[a-z0-9](?:[a-z0-9-]*[a-z0-9])?$/i.test(label)
      ) {
        return null;
      }
    }

    // Prevent allowing an entire common public suffix.
    if (COMMON_PUBLIC_SUFFIXES.has(hostname)) {
      return null;
    }

    return hostname;
  } catch {
    return null;
  }
}

// ==========================================================
// DOMAIN MATCHING
// ==========================================================

/**
 * Match exact domains and their genuine subdomains.
 *
 * example.com:
 *   example.com          -> true
 *   portal.example.com   -> true
 *   attacker-example.com -> false
 *   example.com.evil.net -> false
 *
 * IP addresses and localhost require exact matching.
 */
function domainMatches(
  hostname: string,
  allowedDomain: string
): boolean {
  if (
    isIPv4(allowedDomain) ||
    isIPv6(allowedDomain) ||
    allowedDomain === "localhost"
  ) {
    return hostname === allowedDomain;
  }

  return (
    hostname === allowedDomain ||
    hostname.endsWith(`.${allowedDomain}`)
  );
}

// ==========================================================
// REPOSITORY
// ==========================================================

export class AllowlistRepository {
  /**
   * Serialize modifications so concurrent additions,
   * removals and updates do not overwrite each other.
   */
  private static mutationQueue: Promise<void> =
    Promise.resolve();

  private static enqueueMutation<T>(
    operation: () => Promise<T>
  ): Promise<T> {
    const task = this.mutationQueue.then(operation);

    this.mutationQueue = task.then(
      () => undefined,
      () => undefined
    );

    return task;
  }

  // ========================================================
  // INTERNAL STORAGE ACCESS
  // ========================================================

  private static async readStoredDomains(): Promise<string[]> {
    const result = await chrome.storage.local.get(
      ALLOWLIST_KEY
    );

    const stored = result[ALLOWLIST_KEY];

    if (!Array.isArray(stored)) {
      return [];
    }

    // Normalize and deduplicate legacy entries.
    const normalized = new Set<string>();

    for (const entry of stored) {
      const domain = normalizeDomain(entry);

      if (domain) {
        normalized.add(domain);
      }
    }

    return Array.from(normalized);
  }

  private static async saveDomains(
    domains: string[]
  ): Promise<void> {
    await chrome.storage.local.set({
      [ALLOWLIST_KEY]: domains,
    });
  }

  // ========================================================
  // GET ALL
  // ========================================================

  static async getAll(): Promise<string[]> {
    try {
      return await this.readStoredDomains();
    } catch (error) {
      logger.error(
        "Failed to retrieve ClickShield allowlist:",
        error
      );

      // Fail closed: an unavailable allowlist must
      // never cause a website to be treated as trusted.
      return [];
    }
  }

  // ========================================================
  // CHECK ALLOWLIST
  // ========================================================

  static async isAllowed(
    hostname: string
  ): Promise<boolean> {
    const cleanHostname = normalizeDomain(hostname);

    if (!cleanHostname) return false;

    const list = await this.getAll();

    return list.some((allowedDomain) =>
      domainMatches(cleanHostname, allowedDomain)
    );
  }

  // ========================================================
  // ADD DOMAIN
  // ========================================================

  static async add(
    domain: string
  ): Promise<string[]> {
    const clean = normalizeDomain(domain);

    if (!clean) {
      throw new TypeError(
        "Invalid domain. Enter a valid hostname without a URL, path, port or wildcard."
      );
    }

    return this.enqueueMutation(async () => {
      const list = await this.readStoredDomains();

      if (list.includes(clean)) {
        return list;
      }

      const updated = [...list, clean];

      await this.saveDomains(updated);

      logger.info(
        "Domain added to ClickShield allowlist:",
        clean
      );

      return updated;
    });
  }

  // ========================================================
  // REMOVE DOMAIN
  // ========================================================

  static async remove(
    domain: string
  ): Promise<string[]> {
    const clean = normalizeDomain(domain);

    if (!clean) {
      throw new TypeError(
        "Invalid domain supplied for allowlist removal."
      );
    }

    return this.enqueueMutation(async () => {
      const list = await this.readStoredDomains();

      const updated = list.filter(
        (item) => item !== clean
      );

      if (updated.length === list.length) {
        return list;
      }

      await this.saveDomains(updated);

      logger.info(
        "Domain removed from ClickShield allowlist:",
        clean
      );

      return updated;
    });
  }
}
