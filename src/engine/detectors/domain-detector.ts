import type { ThreatSignal } from "../../shared/types/signal";
import { SUSPICIOUS_TLDS } from "../rules/domain-rules";

export function detectDomainAnomalies(hostname: string): ThreatSignal[] {
  const signals: ThreatSignal[] = [];
  const cleanHost = (hostname || "").toLowerCase().trim();

  if (!cleanHost || cleanHost === "localhost" || cleanHost === "127.0.0.1" || cleanHost === "local-file") {
    return [];
  }

  // 1. Direct Public IP address hostname detection (e.g. http://185.220.101.5/)
  const isIpv4 = /^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/.test(cleanHost);
  if (isIpv4) {
    const isPrivate =
      cleanHost.startsWith("10.") ||
      cleanHost.startsWith("192.168.") ||
      /^172\.(1[6-9]|2\d|3[01])\./.test(cleanHost) ||
      cleanHost.startsWith("127.");

    if (!isPrivate) {
      signals.push({
        type: "SUSPICIOUS_DOMAIN",
        reason: "Website accessed directly via raw public IP address without domain resolution.",
        snippet: `Public IP: ${cleanHost}`,
      });
    }
  }

  // 2. Suspicious high-abuse TLDs
  const matchedTld = SUSPICIOUS_TLDS.find((tld) => cleanHost.endsWith(tld));
  if (matchedTld) {
    signals.push({
      type: "SUSPICIOUS_DOMAIN",
      reason: `Domain uses high-abuse top-level domain (${matchedTld}).`,
      snippet: `TLD: ${matchedTld}`,
    });
  }

  // 3. Deceptive verification subdomain mimicking security infrastructure
  const deceptiveSubdomains = /^(turnstile|captcha|recaptcha|cf-verify|human-verify|cloudflare-check|anti-bot|security-check)\./i;
  if (deceptiveSubdomains.test(cleanHost) && !cleanHost.includes("cloudflare.com") && !cleanHost.includes("google.com")) {
    signals.push({
      type: "SUSPICIOUS_DOMAIN",
      reason: "Domain utilizes deceptive security verification subdomains to simulate official checks.",
      snippet: cleanHost,
    });
  }

  // 4. Punycode / IDN spoofing check
  if (cleanHost.includes("xn--")) {
    signals.push({
      type: "SUSPICIOUS_DOMAIN",
      reason: "Internationalized Domain Name (Punycode xn--) detected, possible homoglyph spoofing.",
      snippet: cleanHost,
    });
  }

  // 5. Excessive subdomain count (e.g. login.verification.microsoft.com.attacker.xyz)
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

