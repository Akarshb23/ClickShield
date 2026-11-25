import { describe, it, expect } from "vitest";
import { SafeNavigation } from "../../src/protection/safe-navigation";

describe("Safe Navigation", () => {
  it("resolves authentic official destinations for monitored brands", () => {
    expect(SafeNavigation.getAuthenticDestination("Cloudflare")).toBe("https://www.cloudflare.com");
    expect(SafeNavigation.getAuthenticDestination("Microsoft Support")).toBe("https://www.microsoft.com");
    expect(SafeNavigation.getAuthenticDestination("Google")).toBe("https://www.google.com");
  });

  it("returns null for unknown brand names", () => {
    expect(SafeNavigation.getAuthenticDestination("RandomUnknownSite")).toBeNull();
  });
});

