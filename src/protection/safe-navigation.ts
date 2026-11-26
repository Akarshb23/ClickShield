
export class SafeNavigation {
  // ==========================================================
  // TRUSTED DESTINATIONS
  // ==========================================================

  private static readonly OFFICIAL_DESTINATIONS: Record<
    string,
    string
  > = {
    cloudflare: "https://www.cloudflare.com",
    microsoft: "https://www.microsoft.com",
    google: "https://www.google.com",
    apple: "https://www.apple.com",
  };

  /**
   * Resolve an explicitly recognized brand name.
   *
   * Never accept arbitrary URLs or partial brand matches.
   */
  private static normalizeBrandName(
    brandName?: string
  ): string | null {
    if (
      typeof brandName !== "string" ||
      !brandName.trim()
    ) {
      return null;
    }

    const normalized = brandName
      .trim()
      .toLowerCase()
      .replace(/\s+/g, " ");

    // Preserve the existing Microsoft Support API behavior.
    const aliases: Record<string, string> = {
      "microsoft support": "microsoft",
    };

    if (aliases[normalized]) {
      return aliases[normalized];
    }

    if (
      Object.prototype.hasOwnProperty.call(
        this.OFFICIAL_DESTINATIONS,
        normalized
      )
    ) {
      return normalized;
    }

    return null;
  }

  // ==========================================================
  // LEAVE CURRENT PAGE
  // ==========================================================

  /**
   * Safely redirects the browser away from a potentially
   * malicious webpage.
   *
   * Stops ongoing page activity before navigating away.
   */
  static leavePage(): void {
    try {
      window.stop();
    } catch {
      // Continue attempting navigation.
    }

    try {
      window.location.replace("about:blank");
    } catch {
      try {
        window.location.href = "about:blank";
      } catch {
        // Navigation may be restricted by the browser.
      }
    }
  }

  // ==========================================================
  // OFFICIAL DESTINATION
  // ==========================================================

  /**
   * Provides a fixed official destination for supported brands.
   *
   * Destinations are statically defined and cannot be supplied
   * or overridden by the webpage being scanned.
   */
  static getAuthenticDestination(
    brandName?: string
  ): string | null {
    const brand = this.normalizeBrandName(brandName);

    if (!brand) return null;

    return this.OFFICIAL_DESTINATIONS[brand] || null;
  }
}
