
/**
 * ClickShield Security Sanitizer
 *
 * Sanitizes untrusted webpage content before inserting it
 * into ClickShield's HTML-based interfaces.
 *
 * Security responsibilities:
 * - HTML entity escaping.
 * - Input type validation.
 * - Bounded text length.
 * - Safe hostname extraction.
 *
 * Note:
 * sanitizeText() is intended for HTML text contexts.
 * It is not a substitute for contextual sanitization
 * when inserting content into URLs, attributes or scripts.
 */

// ==========================================================
// CONSTANTS
// ==========================================================

const MAX_TEXT_LENGTH = 500;
const MAX_URL_LENGTH = 2048;

// ==========================================================
// HTML ESCAPING
// ==========================================================

const HTML_ESCAPE_MAP: Record<string, string> = {
  "&": "&amp;",
  "<": "&lt;",
  ">": "&gt;",
  '"': "&quot;",
  "'": "&#x27;",
};

/**
 * Escape HTML-sensitive characters.
 *
 * Replaces characters in a single pass so newly generated
 * HTML entities are not accidentally escaped again.
 */
function escapeHtml(text: string): string {
  return text.replace(
    /[&<>"']/g,
    (character) => HTML_ESCAPE_MAP[character]
  );
}

// ==========================================================
// TEXT SANITIZATION
// ==========================================================

/**
 * Sanitize untrusted strings extracted from webpage DOM.
 *
 * Supported input:
 * - Strings.
 * - Null and undefined.
 * - Other unexpected values, which return an empty string.
 *
 * The original input is bounded BEFORE HTML escaping.
 * This prevents truncation in the middle of an entity.
 */
export function sanitizeText(input: unknown): string {
  if (typeof input !== "string") {
    return "";
  }

  if (!input) {
    return "";
  }

  // Bound the original text before transformation.
  const boundedInput = input.slice(
    0,
    MAX_TEXT_LENGTH
  );

  // Escape all HTML-sensitive characters.
  return escapeHtml(boundedInput);
}

// ==========================================================
// HOSTNAME SANITIZATION
// ==========================================================

/**
 * Safely extract a hostname from an absolute HTTP or HTTPS URL.
 *
 * Examples:
 *
 * https://Portal.Internal.Corp:8080/path
 * -> portal.internal.corp
 *
 * http://localhost:3000
 * -> localhost
 *
 * https://example.com
 * -> example.com
 *
 * Invalid URLs and unsupported protocols return "unknown".
 */
export function sanitizeHostname(urlStr: string): string {
  try {
    // Runtime validation.
    if (
      typeof urlStr !== "string" ||
      !urlStr.trim() ||
      urlStr.length > MAX_URL_LENGTH
    ) {
      return "unknown";
    }

    const candidate = urlStr.trim();

    // Require an absolute URL.
    const parsed = new URL(candidate);

    // Only accept website protocols.
    if (
      parsed.protocol !== "http:" &&
      parsed.protocol !== "https:"
    ) {
      return "unknown";
    }

    // Reject URLs containing embedded credentials.
    if (
      parsed.username ||
      parsed.password
    ) {
      return "unknown";
    }

    // Extract normalized hostname.
    const hostname = parsed.hostname
      .toLowerCase()
      .replace(/\.$/, "");

    if (!hostname) {
      return "unknown";
    }

    return hostname;
  } catch {
    // Malformed URLs must never break the caller.
    return "unknown";
  }
}
