import type { ThreatSignal } from "../../shared/types/signal";

interface BrandPattern {
  name: string;
  claimRegex: RegExp;
  legitimateDomains: string[];
}

const MONITORED_BRANDS: BrandPattern[] = [
  {
    name: "Cloudflare",
    claimRegex: /\b(cloudflare\s+(turnstile|ddos|protection|ray\s*id)|checking\s+your\s+browser\s+before\s+accessing|ddos-guard)\b/i,
    legitimateDomains: ["cloudflare.com", "cloudflare-ipfs.com", "challenges.cloudflare.com"],
  },
  {
    name: "Microsoft",
    claimRegex: /\b(microsoft\s+(support|security|windows\s+defender|account\s+verification)|windows\s+security\s+center|windows\s+update\s+required)\b/i,
    legitimateDomains: ["microsoft.com", "live.com", "office.com", "azure.com"],
  },
  {
    name: "Google",
    claimRegex: /\b(google\s+(recaptcha|security\s+alert|workspace\s+verification|meet\s+audio\s+error))\b/i,
    legitimateDomains: ["google.com", "recaptcha.net", "gstatic.com"],
  },
  {
    name: "Apple",
    claimRegex: /\b(apple\s+id\s+verification|icloud\s+security\s+checkpoint)\b/i,
    legitimateDomains: ["apple.com", "icloud.com"],
  },
  {
    name: "Discord",
    claimRegex: /\b(discord\s+(verification|security\s+bot|human\s+check))\b/i,
    legitimateDomains: ["discord.com", "discordapp.com", "discord.gg"],
  },
  {
    name: "Zoom",
    claimRegex: /\b(zoom\s+(audio\s+fix|connection\s+issue|meeting\s+verification))\b/i,
    legitimateDomains: ["zoom.us"],
  },
  {
    name: "MetaMask",
    claimRegex: /\b(metamask\s+(security\s+update|wallet\s+verification))\b/i,
    legitimateDomains: ["metamask.io"],
  },
  {
    name: "Steam",
    claimRegex: /\b(steam\s+(guard\s+verification|account\s+security\s+alert))\b/i,
    legitimateDomains: ["steampowered.com", "steamcommunity.com"],
  },
];

export function detectBrandImpersonation(pageText: string, hostname: string): ThreatSignal[] {
  const signals: ThreatSignal[] = [];
  const cleanHost = (hostname || "").toLowerCase().trim();

  // Whitelist safe contexts
  if (!cleanHost || cleanHost === "localhost" || cleanHost === "127.0.0.1" || cleanHost === "local-file") {
    return [];
  }

  for (const brand of MONITORED_BRANDS) {
    // Check if hostname legitimately belongs to the brand
    const isLegitimateHost = brand.legitimateDomains.some(
      (domain) => cleanHost === domain || cleanHost.endsWith("." + domain)
    );

    if (isLegitimateHost) continue;

    // To prevent false positives from benign mentions in footers, articles, or third-party integrations:
    // Only flag brand impersonation if the page prominently claims to BE the official service in its title,
    // primary headline, or if the untrusted hostname actively typosquats the brand name.
    const lowerText = pageText.toLowerCase();
    const hasBrandInHost = cleanHost.includes(brand.name.toLowerCase());
    const hasProminentClaim = brand.claimRegex.test(pageText);

    if (hasBrandInHost || hasProminentClaim) {
      signals.push({
        type: "DOMAIN_IMPERSONATION",
        reason: `Page claims ${brand.name} branding or verification, but hostname (${cleanHost}) is unrelated.`,
        snippet: `Claimed brand: ${brand.name}`,
      });
    }
  }

  return signals;
}

