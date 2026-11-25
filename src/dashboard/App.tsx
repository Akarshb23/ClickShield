import React, { useEffect, useState } from "react";
import {
  Shield,
  ShieldAlert,
  ShieldCheck,
  Activity,
  History,
  Settings,
  Trash2,
  ExternalLink,
  Plus,
  X,
  FileCheck2,
} from "lucide-react";
import type { ThreatRecord, SecurityStatistics } from "../shared/types/threat";
import type { ClickShieldSettings } from "../shared/types/settings";

export default function DashboardApp() {
  const [activeTab, setActiveTab] = useState<"overview" | "history" | "allowlist">("overview");
  const [stats, setStats] = useState<SecurityStatistics>({
    pagesScanned: 0,
    threatsDetected: 0,
    interventions: 0,
  });
  const [threats, setThreats] = useState<ThreatRecord[]>([]);
  const [allowlist, setAllowlist] = useState<string[]>([]);
  const [newDomain, setNewDomain] = useState("");
  const [settings, setSettings] = useState<ClickShieldSettings | null>(null);

  useEffect(() => {
    fetchData();
  }, []);

  const fetchData = async () => {
    try {
      const statsRes = await chrome.runtime.sendMessage({ type: "GET_STATISTICS" });
      if (statsRes?.stats) setStats(statsRes.stats);

      const historyRes = await chrome.runtime.sendMessage({ type: "GET_THREAT_HISTORY" });
      if (historyRes?.history) setThreats(historyRes.history);

      const allowRes = await chrome.runtime.sendMessage({ type: "GET_ALLOWLIST" });
      if (allowRes?.allowlist) setAllowlist(allowRes.allowlist);

      const settingsRes = await chrome.runtime.sendMessage({ type: "GET_SETTINGS" });
      if (settingsRes?.settings) setSettings(settingsRes.settings);
    } catch (e) {
      console.warn("Error fetching dashboard data:", e);
    }
  };

  const handleClearHistory = async () => {
    if (confirm("Clear all recorded threat history?")) {
      await chrome.runtime.sendMessage({ type: "CLEAR_HISTORY" });
      setThreats([]);
    }
  };

  const handleAddAllowlist = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!newDomain.trim()) return;
    const res = await chrome.runtime.sendMessage({
      type: "ALLOWLIST_ADD",
      payload: { hostname: newDomain.trim() },
    });
    if (res?.allowlist) {
      setAllowlist(res.allowlist);
      setNewDomain("");
    }
  };

  const handleRemoveAllowlist = async (host: string) => {
    const res = await chrome.runtime.sendMessage({
      type: "ALLOWLIST_REMOVE",
      payload: { hostname: host },
    });
    if (res?.allowlist) setAllowlist(res.allowlist);
  };

  return (
    <div className="flex min-h-screen bg-[#080808] text-[#F5F5F5] font-sans">
      {/* Sidebar */}
      <aside className="w-64 border-r border-[#222222] bg-[#0E0E0E] flex flex-col justify-between p-5">
        <div>
          <div className="flex items-center gap-3 mb-8">
            <div className="w-9 h-9 rounded bg-[#171717] border border-[#E5B83B]/50 flex items-center justify-center">
              <Shield className="w-5 h-5 text-[#E5B83B]" />
            </div>
            <div>
              <div className="text-sm font-black tracking-widest text-[#E5B83B] uppercase">
                ClickShield
              </div>
              <div className="text-[10px] text-neutral-400 font-mono">
                SECURITY COMMAND
              </div>
            </div>
          </div>

          <nav className="space-y-1.5 font-mono text-xs">
            <button
              onClick={() => setActiveTab("overview")}
              className={`w-full flex items-center gap-2.5 px-3 py-2.5 rounded transition-colors text-left cursor-pointer ${
                activeTab === "overview"
                  ? "bg-[#1E1E1E] text-[#E5B83B] border-l-2 border-[#E5B83B]"
                  : "text-neutral-400 hover:bg-[#161616] hover:text-neutral-200"
              }`}
            >
              <Activity className="w-4 h-4" />
              Overview
            </button>

            <button
              onClick={() => setActiveTab("history")}
              className={`w-full flex items-center gap-2.5 px-3 py-2.5 rounded transition-colors text-left cursor-pointer ${
                activeTab === "history"
                  ? "bg-[#1E1E1E] text-[#E5B83B] border-l-2 border-[#E5B83B]"
                  : "text-neutral-400 hover:bg-[#161616] hover:text-neutral-200"
              }`}
            >
              <History className="w-4 h-4" />
              Threat History ({threats.length})
            </button>

            <button
              onClick={() => setActiveTab("allowlist")}
              className={`w-full flex items-center gap-2.5 px-3 py-2.5 rounded transition-colors text-left cursor-pointer ${
                activeTab === "allowlist"
                  ? "bg-[#1E1E1E] text-[#E5B83B] border-l-2 border-[#E5B83B]"
                  : "text-neutral-400 hover:bg-[#161616] hover:text-neutral-200"
              }`}
            >
              <FileCheck2 className="w-4 h-4" />
              Allowlist ({allowlist.length})
            </button>
          </nav>
        </div>

        <div className="border-t border-[#222222] pt-4 font-mono text-[11px] text-neutral-500">
          <div className="flex items-center gap-2 mb-1">
            <span className="w-2 h-2 rounded-full bg-[#16A34A] animate-pulse" />
            <span className="text-neutral-300">Local-First Engine</span>
          </div>
          <div>Manifest V3 · v0.1.0</div>
        </div>
      </aside>

      {/* Main Content Area */}
      <main className="flex-1 p-8 overflow-y-auto">
        <header className="flex items-center justify-between pb-6 border-b border-[#222222] mb-8">
          <div>
            <h1 className="text-2xl font-black font-mono tracking-tight text-neutral-100">
              Security Analytics & Control
            </h1>
            <p className="text-xs font-mono text-neutral-400 mt-1">
              Active behavioral monitoring for deceptive verification and ClickFix command attacks.
            </p>
          </div>

          <div className="flex items-center gap-3">
            <button
              onClick={() => chrome.runtime.openOptionsPage()}
              className="flex items-center gap-1.5 px-3 py-1.5 rounded bg-[#161616] hover:bg-[#202020] border border-[#2D2D2D] text-xs font-mono text-neutral-300 transition-colors cursor-pointer"
            >
              <Settings className="w-3.5 h-3.5 text-[#E5B83B]" /> Settings
            </button>
          </div>
        </header>

        {activeTab === "overview" && (
          <div className="space-y-8">
            {/* KPI Cards */}
            <div className="grid grid-cols-4 gap-4">
              <div className="p-5 rounded bg-[#111111] border border-[#222222]">
                <div className="text-[11px] font-mono text-neutral-400 uppercase tracking-wider">
                  Pages Scanned
                </div>
                <div className="text-3xl font-black font-mono text-neutral-100 mt-2">
                  {stats.pagesScanned.toLocaleString()}
                </div>
                <div className="text-[10px] text-neutral-500 font-mono mt-1">
                  Active DOM inspections
                </div>
              </div>

              <div className="p-5 rounded bg-[#111111] border border-[#222222]">
                <div className="text-[11px] font-mono text-neutral-400 uppercase tracking-wider">
                  Threats Detected
                </div>
                <div className="text-3xl font-black font-mono text-[#E5B83B] mt-2">
                  {stats.threatsDetected}
                </div>
                <div className="text-[10px] text-neutral-500 font-mono mt-1">
                  Deceptive verification patterns
                </div>
              </div>

              <div className="p-5 rounded bg-[#111111] border border-[#222222]">
                <div className="text-[11px] font-mono text-neutral-400 uppercase tracking-wider">
                  Interventions
                </div>
                <div className="text-3xl font-black font-mono text-[#4ADE80] mt-2">
                  {stats.interventions}
                </div>
                <div className="text-[10px] text-neutral-500 font-mono mt-1">
                  Alerts & clipboard actions
                </div>
              </div>

              <div className="p-5 rounded bg-[#111111] border border-[#222222]">
                <div className="text-[11px] font-mono text-neutral-400 uppercase tracking-wider">
                  Protection Engine
                </div>
                <div className="text-xl font-bold font-mono text-[#4ADE80] mt-2 flex items-center gap-2">
                  <span className="w-2.5 h-2.5 rounded-full bg-[#16A34A] animate-pulse" />
                  {settings?.protectionEnabled ? "OPERATIONAL" : "PAUSED"}
                </div>
                <div className="text-[10px] text-neutral-500 font-mono mt-1">
                  Zero cloud telemetry
                </div>
              </div>
            </div>

            {/* Recent threats quick view */}
            <div className="rounded bg-[#111111] border border-[#222222] p-5">
              <div className="flex items-center justify-between mb-4">
                <h2 className="text-sm font-bold font-mono text-neutral-200 uppercase tracking-wider">
                  Recent Threat Detections
                </h2>
                <button
                  onClick={() => setActiveTab("history")}
                  className="text-xs font-mono text-[#E5B83B] hover:underline cursor-pointer"
                >
                  View All ({threats.length})
                </button>
              </div>

              {threats.length === 0 ? (
                <div className="text-center py-10 font-mono text-xs text-neutral-500">
                  No threats recorded yet. Safe browsing in progress.
                </div>
              ) : (
                <div className="overflow-x-auto">
                  <table className="w-full text-left font-mono text-xs">
                    <thead>
                      <tr className="border-b border-[#222222] text-neutral-500 text-[11px]">
                        <th className="pb-3">HOSTNAME</th>
                        <th className="pb-3">RISK SCORE</th>
                        <th className="pb-3">LEVEL</th>
                        <th className="pb-3">DETECTED SIGNALS</th>
                        <th className="pb-3">TIMESTAMP</th>
                      </tr>
                    </thead>
                    <tbody className="divide-y divide-[#1C1C1C]">
                      {threats.slice(0, 5).map((threat) => (
                        <tr key={threat.id} className="hover:bg-[#171717]">
                          <td className="py-3 text-neutral-200 font-semibold">{threat.hostname}</td>
                          <td className="py-3 text-[#E5B83B]">{threat.riskScore}/100</td>
                          <td className="py-3">
                            <span
                              className={`px-2 py-0.5 rounded text-[10px] font-bold ${
                                threat.riskLevel === "CRITICAL"
                                  ? "bg-[#DC2626]/20 text-[#F87171]"
                                  : threat.riskLevel === "HIGH"
                                  ? "bg-[#EA580C]/20 text-[#FB923C]"
                                  : "bg-[#D4A32C]/20 text-[#FDE047]"
                              }`}
                            >
                              {threat.riskLevel}
                            </span>
                          </td>
                          <td className="py-3 text-neutral-400">
                            {threat.signals.map((s) => s.replace(/_/g, " ")).join(", ")}
                          </td>
                          <td className="py-3 text-neutral-500 text-[11px]">
                            {new Date(threat.timestamp).toLocaleTimeString()}
                          </td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              )}
            </div>
          </div>
        )}

        {activeTab === "history" && (
          <div className="rounded bg-[#111111] border border-[#222222] p-6">
            <div className="flex items-center justify-between mb-6">
              <div>
                <h2 className="text-lg font-bold font-mono text-neutral-200">
                  Full Threat Log
                </h2>
                <p className="text-xs font-mono text-neutral-400">
                  Stored securely in local extension storage. Never transmitted off-device.
                </p>
              </div>

              {threats.length > 0 && (
                <button
                  onClick={handleClearHistory}
                  className="flex items-center gap-1.5 px-3 py-1.5 rounded bg-[#2B1111] hover:bg-[#3D1414] border border-[#DC2626]/40 text-xs font-mono text-[#F87171] transition-colors cursor-pointer"
                >
                  <Trash2 className="w-3.5 h-3.5" /> Clear History
                </button>
              )}
            </div>

            {threats.length === 0 ? (
              <div className="text-center py-16 font-mono text-xs text-neutral-500">
                Threat log is currently empty.
              </div>
            ) : (
              <div className="overflow-x-auto">
                <table className="w-full text-left font-mono text-xs">
                  <thead>
                    <tr className="border-b border-[#222222] text-neutral-500 text-[11px]">
                      <th className="pb-3">TIMESTAMP</th>
                      <th className="pb-3">HOSTNAME</th>
                      <th className="pb-3">RISK SCORE</th>
                      <th className="pb-3">LEVEL</th>
                      <th className="pb-3">SIGNALS</th>
                      <th className="pb-3">INTERVENTION</th>
                    </tr>
                  </thead>
                  <tbody className="divide-y divide-[#1C1C1C]">
                    {threats.map((threat) => (
                      <tr key={threat.id} className="hover:bg-[#171717]">
                        <td className="py-3 text-neutral-400 text-[11px]">
                          {new Date(threat.timestamp).toLocaleString()}
                        </td>
                        <td className="py-3 text-neutral-200 font-semibold">{threat.hostname}</td>
                        <td className="py-3 text-[#E5B83B] font-bold">{threat.riskScore}</td>
                        <td className="py-3">
                          <span
                            className={`px-2 py-0.5 rounded text-[10px] font-bold ${
                              threat.riskLevel === "CRITICAL"
                                ? "bg-[#DC2626]/20 text-[#F87171]"
                                : threat.riskLevel === "HIGH"
                                ? "bg-[#EA580C]/20 text-[#FB923C]"
                                : "bg-[#D4A32C]/20 text-[#FDE047]"
                            }`}
                          >
                            {threat.riskLevel}
                          </span>
                        </td>
                        <td className="py-3 text-neutral-400 max-w-xs truncate">
                          {threat.signals.map((s) => s.replace(/_/g, " ")).join(", ")}
                        </td>
                        <td className="py-3 text-neutral-300">{threat.action}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            )}
          </div>
        )}

        {activeTab === "allowlist" && (
          <div className="rounded bg-[#111111] border border-[#222222] p-6 max-w-2xl">
            <h2 className="text-lg font-bold font-mono text-neutral-200 mb-1">
              Trusted Domain Allowlist
            </h2>
            <p className="text-xs font-mono text-neutral-400 mb-6">
              Domains added here will be exempted from heuristic warnings and interventions.
            </p>

            <form onSubmit={handleAddAllowlist} className="flex gap-3 mb-6">
              <input
                type="text"
                placeholder="e.g. portal.company.internal"
                value={newDomain}
                onChange={(e) => setNewDomain(e.target.value)}
                className="flex-1 bg-[#1A1A1A] border border-[#2E2E2E] rounded px-3 py-2 text-xs font-mono text-neutral-200 focus:outline-none focus:border-[#E5B83B]"
              />
              <button
                type="submit"
                className="flex items-center gap-1.5 px-4 py-2 bg-[#E5B83B] hover:bg-[#F5CB5C] text-black font-mono font-bold text-xs rounded transition-colors cursor-pointer"
              >
                <Plus className="w-4 h-4" /> Add Domain
              </button>
            </form>

            <div className="space-y-2">
              {allowlist.length === 0 ? (
                <div className="text-center py-8 font-mono text-xs text-neutral-500">
                  No custom allowed domains configured.
                </div>
              ) : (
                allowlist.map((domain) => (
                  <div
                    key={domain}
                    className="flex items-center justify-between p-3 rounded bg-[#171717] border border-[#262626] font-mono text-xs"
                  >
                    <span className="text-neutral-200 font-semibold">{domain}</span>
                    <button
                      onClick={() => handleRemoveAllowlist(domain)}
                      className="text-neutral-500 hover:text-[#DC2626] transition-colors cursor-pointer p-1"
                      title="Remove domain"
                    >
                      <X className="w-4 h-4" />
                    </button>
                  </div>
                ))
              )}
            </div>
          </div>
        )}
      </main>
    </div>
  );
}

