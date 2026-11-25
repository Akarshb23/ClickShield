import type { ThreatSignal } from "../../shared/types/signal";
import { SUSPICIOUS_TLDS } from "../rules/domain-rules";

export function detectDomainAnomalies(hostname: string): ThreatSignal[] {
  const signals: ThreatSignal[] = [];
  const cleanHost = (hostname || "").toLowerCase().trim();

  if (!cleanHost || cleanHost === "localhost" || cleanHost === "127.0.0.1") {
    return [];
  }

  // 1. Suspicious high-abuse TLDs
  const matchedTld = SUSPICIOUS_TLDS.find((tld) => cleanHost.endsWith(tld));
  if (matchedTld) {
    signals.push({
      type: "SUSPICIOUS_DOMAIN",
      reason: `Domain uses high-abuse top-level domain (${matchedTld}).`,
      snippet: `TLD: ${matchedTld}`,
    });
  }

  // 2. Punycode / IDN spoofing check
  if (cleanHost.includes("xn--")) {
    signals.push({
      type: "SUSPICIOUS_DOMAIN",
      reason: "Internationalized Domain Name (Punycode xn--) detected, possible homoglyph spoofing.",
      snippet: cleanHost,
    });
  }

  // 3. Excessive subdomain count (e.g. login.verification.microsoft.com.attacker.xyz)
  const parts = cleanHost.split(".");
  if (parts.length >= 5) {
    signals.push({
      type: "SUSPICIOUS_DOMAIN",
      reason: "Excessive subdomain hierarchy detected, often used to conceal actual domain origin.",
      snippet: `${parts.length} domain labels detected.`,
    });
  }

  return signals;
}

