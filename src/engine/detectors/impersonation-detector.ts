import type { ThreatSignal } from "../../shared/types/signal";

interface BrandPattern {
  name: string;
  claimRegex: RegExp;
  legitimateDomains: string[];
}

const MONITORED_BRANDS: BrandPattern[] = [
  {
    name: "Cloudflare",
    claimRegex: /\b(cloudflare\s+(turnstile|ddos|protection|ray\s*id)|checking\s+your\s+browser\s+before\s+accessing)\b/i,
    legitimateDomains: ["cloudflare.com", "cloudflare-ipfs.com", "challenges.cloudflare.com"],
  },
  {
    name: "Microsoft",
    claimRegex: /\b(microsoft\s+(support|security|windows\s+defender|account\s+verification))\b/i,
    legitimateDomains: ["microsoft.com", "live.com", "office.com", "azure.com"],
  },
  {
    name: "Google",
    claimRegex: /\b(google\s+(recaptcha|security\s+alert|workspace\s+verification))\b/i,
    legitimateDomains: ["google.com", "recaptcha.net", "gstatic.com"],
  },
  {
    name: "Apple",
    claimRegex: /\b(apple\s+id\s+verification|icloud\s+security\s+checkpoint)\b/i,
    legitimateDomains: ["apple.com", "icloud.com"],
  },
];

export function detectBrandImpersonation(pageText: string, hostname: string): ThreatSignal[] {
  const signals: ThreatSignal[] = [];
  const cleanHost = (hostname || "").toLowerCase().trim();

  if (!cleanHost || cleanHost === "localhost" || cleanHost === "127.0.0.1") {
    return [];
  }

  for (const brand of MONITORED_BRANDS) {
    if (brand.claimRegex.test(pageText)) {
      // Check if hostname legitimately matches the claimed brand
      const isLegitimate = brand.legitimateDomains.some(
        (domain) => cleanHost === domain || cleanHost.endsWith("." + domain)
      );

      if (!isLegitimate) {
        signals.push({
          type: "DOMAIN_IMPERSONATION",
          reason: `Page claims ${brand.name} branding or verification, but hostname (${cleanHost}) is unrelated.`,
          snippet: `Claimed brand: ${brand.name}`,
        });
      }
    }
  }

  return signals;
}
