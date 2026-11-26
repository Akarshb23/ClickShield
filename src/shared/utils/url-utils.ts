
/**
 * ClickShield URL Utilities
 *
 * Determines whether a browser URL is an eligible scanning target.
 *
 * Supported protocols:
 * - HTTP
 * - HTTPS
 * - FILE
 *
 * Restricted protocols:
 * - chrome://
 * - chrome-extension://
 * - edge://
 * - about:
 * - javascript:
 * - data:
 * - devtools:
 * - Other browser-internal schemes
 */

// ==========================================================
// CONSTANTS
// ==========================================================

const MAX_URL_LENGTH = 16384;

const SCANNABLE_PROTOCOLS = new Set([
  "http:",
  "https:",
  "file:",
]);

// ==========================================================
// URL VALIDATION
// ==========================================================

/**
 * Check whether a URL is eligible for ClickShield scanning.
 *
 * This validates URL protocol and structure.
 * Actual content-script injection also depends on Chrome
 * extension permissions and browser restrictions.
 */
export function isScannableUrl(
  url: string | undefined
): boolean {
  // 1. Validate input.
  if (
    typeof url !== "string" ||
    !url.trim() ||
    url.length > MAX_URL_LENGTH
  ) {
    return false;
  }

  try {
    // 2. Parse absolute URL.
    const parsed = new URL(url.trim());

    // 3. Reject unsupported browser and application schemes.
    if (!SCANNABLE_PROTOCOLS.has(parsed.protocol)) {
      return false;
    }

    // 4. HTTP and HTTPS require a valid hostname.
    if (
      parsed.protocol === "http:" ||
      parsed.protocol === "https:"
    ) {
      return parsed.hostname.length > 0;
    }

    // 5. File URLs are eligible, subject to Chrome's
    // user-controlled file URL access permission.
    if (parsed.protocol === "file:") {
      return parsed.pathname.length > 0;
    }

    return false;
  } catch {
    // Malformed URLs are never considered scannable.
    return false;
  }
}
