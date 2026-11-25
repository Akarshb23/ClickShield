const ALLOWLIST_KEY = "clickshield_allowlist";

export class AllowlistRepository {
  static async getAll(): Promise<string[]> {
    try {
      const result = await chrome.storage.local.get(ALLOWLIST_KEY);
      return (result[ALLOWLIST_KEY] as string[]) || [];
    } catch {
      return [];
    }
  }

  static async isAllowed(hostname: string): Promise<boolean> {
    const clean = (hostname || "").toLowerCase().trim();
    if (!clean) return false;

    const list = await this.getAll();
    return list.some(
      (item) => clean === item.toLowerCase() || clean.endsWith("." + item.toLowerCase())
    );
  }

  static async add(domain: string): Promise<string[]> {
    const clean = (domain || "").toLowerCase().trim();
    if (!clean) return await this.getAll();

    const list = await this.getAll();
    if (!list.includes(clean)) {
      list.push(clean);
      await chrome.storage.local.set({ [ALLOWLIST_KEY]: list });
    }
    return list;
  }

  static async remove(domain: string): Promise<string[]> {
    const clean = (domain || "").toLowerCase().trim();
    const list = await this.getAll();
    const updated = list.filter((item) => item.toLowerCase() !== clean);
    await chrome.storage.local.set({ [ALLOWLIST_KEY]: updated });
    return updated;
  }
}

