export class SafeNavigation {
  /**
   * Safely redirects the browser away from an active attack page
   */
  static leavePage(): void {
    try {
      window.stop(); // Immediately halt ongoing network requests or script downloads
      window.location.replace("about:blank");
    } catch {
      window.location.href = "about:blank";
    }
  }

  /**
   * Provides direct navigation to the authentic official provider
   * if brand impersonation was detected.
   */
  static getAuthenticDestination(brandName?: string): string | null {
    if (!brandName) return null;
    const lower = brandName.toLowerCase();

    if (lower.includes("cloudflare")) {
      return "https://www.cloudflare.com";
    }
    if (lower.includes("microsoft")) {
      return "https://www.microsoft.com";
    }
    if (lower.includes("google")) {
      return "https://www.google.com";
    }
    if (lower.includes("apple")) {
      return "https://www.apple.com";
    }

    return null;
  }
}

