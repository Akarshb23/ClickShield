import { describe, it, expect } from "vitest";
import { calculateRisk } from "../../src/engine/risk-engine";
import { isScannableUrl } from "../../src/shared/utils/url-utils";
import { sanitizeText, sanitizeHostname } from "../../src/shared/utils/sanitizer";

describe("Message Validation & Security Sanitization", () => {
  it("rejects non-scannable and internal browser schemes", () => {
    expect(isScannableUrl("chrome://extensions")).toBe(false);
    expect(isScannableUrl("chrome://settings")).toBe(false);
    expect(isScannableUrl("edge://settings")).toBe(false);
    expect(isScannableUrl("about:blank")).toBe(false);
    expect(isScannableUrl("chrome-extension://abcdefg/index.html")).toBe(false);
    expect(isScannableUrl("javascript:alert(1)")).toBe(false);

    expect(isScannableUrl("https://example.com")).toBe(true);
    expect(isScannableUrl("http://localhost:3000")).toBe(true);
  });

  it("sanitizes untrusted text extracted from webpage DOM", () => {
    const maliciousInput = '<script>alert("xss")</script><img src="x" onerror="alert(1)">';
    const sanitized = sanitizeText(maliciousInput);

    expect(sanitized).not.toContain("<script>");
    expect(sanitized).toContain("&lt;script&gt;");
  });

  it("extracts clean hostnames safely from malformed URLs", () => {
    expect(sanitizeHostname("https://Portal.Internal.Corp:8080/path?query=1")).toBe("portal.internal.corp");
    expect(sanitizeHostname("not-a-valid-url")).toBe("unknown");
  });

  it("safely handles null, undefined, or empty signal sets in risk engine", () => {
    const res = calculateRisk([]);
    expect(res.score).toBe(0);
    expect(res.level).toBe("LOW");
  });
});

