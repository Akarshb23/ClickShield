import { describe, it, expect, beforeEach } from "vitest";
import { ThreatRepository } from "../../src/storage/threat-repository";
import type { ThreatRecord } from "../../src/shared/types/threat";

describe("Threat Repository & Retention", () => {
  let mockStorage: Record<string, any> = {};

  beforeEach(() => {
    mockStorage = {};
    (globalThis as any).chrome = {
      storage: {
        local: {
          get: async (key: string | string[]) => {
            if (Array.isArray(key)) {
              const res: Record<string, any> = {};
              key.forEach((k) => (res[k] = mockStorage[k]));
              return res;
            }
            return { [key]: mockStorage[key] };
          },
          set: async (items: Record<string, any>) => {
            Object.assign(mockStorage, items);
          },
        },
      },
    };
  });

  it("stores and retrieves recorded threats", async () => {
    const record: ThreatRecord = {
      id: "threat-1",
      hostname: "malicious.test",
      url: "https://malicious.test",
      timestamp: Date.now(),
      riskScore: 85,
      riskLevel: "CRITICAL",
      signals: ["FAKE_CAPTCHA", "EXECUTION_INSTRUCTION"],
      action: "WARNING_DISPLAYED",
    };

    await ThreatRepository.addRecord(record);
    const stored = await ThreatRepository.getAll();

    expect(stored.length).toBe(1);
    expect(stored[0].hostname).toBe("malicious.test");
  });

  it("deduplicates repeated identical threats within 30 seconds", async () => {
    const record: ThreatRecord = {
      id: "threat-1",
      hostname: "dup.test",
      url: "https://dup.test",
      timestamp: Date.now(),
      riskScore: 85,
      riskLevel: "CRITICAL",
      signals: ["FAKE_CAPTCHA"],
      action: "WARNING_DISPLAYED",
    };

    await ThreatRepository.addRecord(record);
    await ThreatRepository.addRecord({ ...record, id: "threat-2" });

    const stored = await ThreatRepository.getAll();
    expect(stored.length).toBe(1);
  });

  it("clears all records when requested", async () => {
    await ThreatRepository.addRecord({
      id: "threat-clear",
      hostname: "clear.test",
      url: "https://clear.test",
      timestamp: Date.now(),
      riskScore: 40,
      riskLevel: "SUSPICIOUS",
      signals: ["SUSPICIOUS_INSTRUCTION"],
      action: "CAUTION_SHOWN",
    });

    expect((await ThreatRepository.getAll()).length).toBe(1);
    await ThreatRepository.clearAll();
    expect((await ThreatRepository.getAll()).length).toBe(0);
  });
});

