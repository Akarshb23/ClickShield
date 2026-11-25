/**
 * Sanitizes untrusted strings and text extracted from the webpage DOM
 * to prevent XSS or injection vulnerabilities when rendering into UI.
 */
export function sanitizeText(input: unknown): string {
  if (typeof input !== "string") return "";
  return input
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#x27;")
    .slice(0, 500); // Bound text length
}

export function sanitizeHostname(urlStr: string): string {
  try {
    const parsed = new URL(urlStr);
    return parsed.hostname.toLowerCase();
  } catch {
    return "unknown";
  }
}

