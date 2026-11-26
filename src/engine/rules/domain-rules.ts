
/**
 * Domains belonging to recognized services.
 *
 * Domain matching must use hostname boundaries:
 *   google.com                  -> trusted
 *   accounts.google.com         -> trusted
 *   google.com.attacker.net     -> NOT trusted
 *
 * Keep this list aligned with the legitimateDomains
 * entries in the impersonation detector.
 */
export const TRUSTED_DOMAINS: string[] = [
  // Cloudflare
  "cloudflare.com",
  "cloudflare-ipfs.com",
  "challenges.cloudflare.com",

  // Google
  "google.com",
  "gstatic.com",
  "recaptcha.net",

  // Microsoft
  "microsoft.com",
  "live.com",
  "office.com",
  "azure.com",

  // Apple
  "apple.com",
  "icloud.com",

  // Discord
  "discord.com",
  "discordapp.com",
  "discord.gg",

  // Other monitored services
  "zoom.us",
  "metamask.io",
  "steampowered.com",
  "steamcommunity.com",

  // Developer and community platforms
  "github.com",
  "stackoverflow.com",
];

/**
 * TLDs monitored for potentially elevated abuse.
 *
 * IMPORTANT:
 * A monitored TLD is not inherently malicious.
 * TLD matching should be treated as a weak risk signal
 * and correlated with other suspicious indicators.
 *
 * Keep the leading dot for readability. The domain
 * detector normalizes entries before matching.
 */
export const SUSPICIOUS_TLDS: string[] = [
  ".zip",
  ".mov",
  ".top",
  ".work",
  ".click",
  ".xyz",
  ".country",
  ".stream",
  ".buzz",
  ".rest",
  ".icu",
  ".monster",
  ".cfd",
  ".sbs",
  ".quest",
  ".live",
  ".surf",
  ".download",
  ".racing",
  ".bid",
  ".loan",
  ".trade",
  ".party",
  ".science",
  ".space",
  ".site",
  ".online",
  ".fun",
  ".uno",
  ".cam",
  ".fit",
  ".gq",
  ".cf",
  ".tk",
  ".ml",
  ".ga",
];
