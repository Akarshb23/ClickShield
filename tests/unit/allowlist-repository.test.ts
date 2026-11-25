import { describe, it, expect, beforeEach } from "vitest";
import { AllowlistRepository } from "../../src/storage/allowlist-repository";

describe("Allowlist Repository", () => {
  let mockStorage: Record<string, any> = {};

  beforeEach(() => {
    mockStorage = {};
    (globalThis as any).chrome = {
      storage: {
        local: {
          get: async (key: string) => ({ [key]: mockStorage[key] }),
          set: async (items: Record<string, any>) => {
            Object.assign(mockStorage, items);
          },
        },
      },
    };
  });

  it("adds and detects allowed domains including subdomains", async () => {
    await AllowlistRepository.add("internal.corp");

    const isDirectMatch = await AllowlistRepository.isAllowed("internal.corp");
    const isSubdomainMatch = await AllowlistRepository.isAllowed("portal.internal.corp");
    const isUnrelated = await AllowlistRepository.isAllowed("attacker.com");

    expect(isDirectMatch).toBe(true);
    expect(isSubdomainMatch).toBe(true);
    expect(isUnrelated).toBe(false);
  });

  it("removes domains accurately from the list", async () => {
    await AllowlistRepository.add("test.example");
    expect(await AllowlistRepository.isAllowed("test.example")).toBe(true);

    await AllowlistRepository.remove("test.example");
    expect(await AllowlistRepository.isAllowed("test.example")).toBe(false);
  });
});

