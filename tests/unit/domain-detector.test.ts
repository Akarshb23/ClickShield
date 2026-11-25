import { describe, it, expect } from "vitest";
import { detectDomainAnomalies } from "../../src/engine/detectors/domain-detector";
import { detectBrandImpersonation } from "../../src/engine/detectors/impersonation-detector";

describe("Domain and Impersonation Detectors", () => {
  it("flags high-abuse TLDs such as .xyz and .top", () => {
    const signals = detectDomainAnomalies("captcha-verify.xyz");
    expect(signals.length).toBeGreaterThan(0);
    expect(signals[0].type).toBe("SUSPICIOUS_DOMAIN");
  });

  it("flags brand impersonation when claiming Cloudflare DDoS protection on third-party domain", () => {
    const pageText = "Cloudflare Turnstile DDoS protection is verifying your browser.";
    const signals = detectBrandImpersonation(pageText, "unrelated-site.com");

    expect(signals.length).toBeGreaterThan(0);
    expect(signals[0].type).toBe("DOMAIN_IMPERSONATION");
  });

  it("flags websites accessed directly via raw public IP address", () => {
    const signals = detectDomainAnomalies("185.220.101.5");

    expect(signals.length).toBeGreaterThan(0);
    expect(signals[0].type).toBe("SUSPICIOUS_DOMAIN");
    expect(signals[0].reason).toContain("public IP address");
  });

  it("does not flag legitimate brand domains", () => {
    const pageText = "Cloudflare Turnstile DDoS protection is verifying your browser.";
    const signals = detectBrandImpersonation(pageText, "challenges.cloudflare.com");

    expect(signals).toHaveLength(0);
  });
});

