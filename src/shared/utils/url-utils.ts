/**
 * Checks if a URL is a browser-restricted or scannable target.
 * Extensions cannot scan chrome://, edge://, about:, chrome-extension://, etc.
 */
export function isScannableUrl(url: string | undefined): boolean {
  if (!url) return false;
  try {
    const parsed = new URL(url);
    return parsed.protocol === "http:" || parsed.protocol === "https:";
  } catch {
    return false;
  }
}

