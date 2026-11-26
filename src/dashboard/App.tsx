import React, { useCallback, useEffect, useMemo, useState } from "react";

import {

  Activity,

  BarChart2,

  Download,

  FileCheck2,

  Filter,

  History,

  Plus,

  Search,

  Settings,

  Shield,

  ShieldCheck,

  Trash2,

  X,

} from "lucide-react";



import { ThreatChart } from "./components/ThreatChart";

import { ThreatDetailsModal } from "./components/ThreatDetailsModal";

import type {

  SecurityStatistics,

  ThreatRecord,

} from "../shared/types/threat";

import type { ClickShieldSettings } from "../shared/types/settings";



type DashboardTab = "overview" | "history" | "analytics" | "allowlist";

type Feedback = { type: "success" | "error"; message: string } | null;



const EMPTY_STATISTICS: SecurityStatistics = {

  pagesScanned: 0,

  threatsDetected: 0,

  interventions: 0,

};



function normalizeStatistics(value: unknown): SecurityStatistics | null {
  if (typeof value !== "object" || value === null) {
    return null;
  }

  const candidate = value as Record<string, unknown>;
  const keys: (keyof SecurityStatistics)[] = [
    "pagesScanned",
    "threatsDetected",
    "interventions",
  ];

  const normalized = {} as SecurityStatistics;

  for (const key of keys) {
    const count = candidate[key];

    if (
      typeof count !== "number" ||
      !Number.isSafeInteger(count) ||
      count < 0
    ) {
      return null;
    }

    normalized[key] = count;
  }

  return normalized;
}

function getResponseError(response: unknown): string | null {

  if (

    typeof response === "object" &&

    response !== null &&

    "error" in response &&

    typeof response.error === "string" &&

    response.error.trim()

  ) {

    return response.error;

  }



  return null;

}



function normalizeHostname(value: string): string | null {

  const candidate = value.trim();



  if (

    !candidate ||

    candidate.length > 253 ||

    /[\s/?#@\\\\]/.test(candidate) ||

    candidate.includes("://")

  ) {

    return null;

  }



  try {

    const parsed = new URL(`https://${candidate}`);



    if (

      parsed.username ||

      parsed.password ||

      parsed.port ||

      parsed.pathname !== "/" ||

      parsed.search ||

      parsed.hash

    ) {

      return null;

    }



    const hostname = parsed.hostname.toLowerCase().replace(/\.$/, "");



    if (!hostname || hostname.length > 253) {

      return null;

    }



    // URL parsing also normalizes internationalized hostnames to ASCII.

    return hostname;

  } catch {

    return null;

  }

}



function getRiskBadgeClass(riskLevel: ThreatRecord["riskLevel"]): string {

  switch (riskLevel) {

    case "CRITICAL":

      return "bg-[#DC2626]/20 text-[#F87171]";

    case "HIGH":

      return "bg-[#EA580C]/20 text-[#FB923C]";

    case "SUSPICIOUS":

      return "bg-[#D4A32C]/20 text-[#FDE047]";

    default:

      return "bg-[#525252]/30 text-neutral-300";

  }

}



function formatTimestamp(timestamp: ThreatRecord["timestamp"]): string {

  const date = new Date(timestamp);

  return Number.isNaN(date.getTime()) ? "Unknown time" : date.toLocaleString();

}



export default function DashboardApp() {

  const [activeTab, setActiveTab] = useState<DashboardTab>("overview");

  const [stats, setStats] = useState<SecurityStatistics>(EMPTY_STATISTICS);

  const [threats, setThreats] = useState<ThreatRecord[]>([]);

  const [allowlist, setAllowlist] = useState<string[]>([]);

  const [newDomain, setNewDomain] = useState("");

  const [settings, setSettings] = useState<ClickShieldSettings | null>(null);



  const [searchQuery, setSearchQuery] = useState("");

  const [levelFilter, setLevelFilter] = useState("ALL");

  const [selectedThreat, setSelectedThreat] = useState<ThreatRecord | null>(null);



  const [isLoading, setIsLoading] = useState(true);

  const [pendingAction, setPendingAction] = useState<string | null>(null);

  const [feedback, setFeedback] = useState<Feedback>(null);



  const fetchData = useCallback(async () => {

    setIsLoading(true);

    setFeedback(null);



    const requests = await Promise.allSettled([

      chrome.runtime.sendMessage({ type: "GET_STATISTICS" }),

      chrome.runtime.sendMessage({ type: "GET_THREAT_HISTORY" }),

      chrome.runtime.sendMessage({ type: "GET_ALLOWLIST" }),

      chrome.runtime.sendMessage({ type: "GET_SETTINGS" }),

    ]);



    const errors: string[] = [];



    const [statsResult, historyResult, allowlistResult, settingsResult] = requests;



    if (statsResult.status === "fulfilled") {

      const response = statsResult.value;

      const responseError = getResponseError(response);



      if (responseError) {

        errors.push(`Statistics: ${responseError}`);

      } else {
        const normalizedStats = normalizeStatistics(response?.stats);

        if (normalizedStats) {
          setStats(normalizedStats);
        } else {
          errors.push("Statistics were not returned in the expected format.");
        }
      }

    } else {

      errors.push("Could not load statistics.");

    }



    if (historyResult.status === "fulfilled") {

      const response = historyResult.value;

      const responseError = getResponseError(response);



      if (responseError) {

        errors.push(`Threat history: ${responseError}`);

      } else if (Array.isArray(response?.history)) {

        setThreats(response.history as ThreatRecord[]);

      } else {

        errors.push("Threat history was not returned in the expected format.");

      }

    } else {

      errors.push("Could not load threat history.");

    }



    if (allowlistResult.status === "fulfilled") {

      const response = allowlistResult.value;

      const responseError = getResponseError(response);



      if (responseError) {

        errors.push(`Allowlist: ${responseError}`);

      } else if (Array.isArray(response?.allowlist)) {

        setAllowlist(response.allowlist as string[]);

      } else {

        errors.push("The allowlist was not returned in the expected format.");

      }

    } else {

      errors.push("Could not load the allowlist.");

    }



    if (settingsResult.status === "fulfilled") {

      const response = settingsResult.value;

      const responseError = getResponseError(response);



      if (responseError) {

        errors.push(`Settings: ${responseError}`);

      } else if (response?.settings) {

        setSettings(response.settings as ClickShieldSettings);

      } else {

        errors.push("Settings were not returned by the background service.");

      }

    } else {

      errors.push("Could not load settings.");

    }



    if (errors.length > 0) {

      setFeedback({

        type: "error",

        message: errors.join(" "),

      });

    }



    setIsLoading(false);

  }, []);



  useEffect(() => {

    void fetchData();

  }, [fetchData]);



  const handleClearHistory = async () => {

    if (pendingAction) return;



    const confirmed = window.confirm("Clear all recorded threat history?");

    if (!confirmed) return;



    setPendingAction("clear-history");

    setFeedback(null);



    try {

      const response = await chrome.runtime.sendMessage({

        type: "CLEAR_HISTORY",

      });

      const responseError = getResponseError(response);



      if (responseError) {

        throw new Error(responseError);

      }



      if (response?.success !== true) {

        throw new Error("The background service did not confirm the history clear.");

      }



      setThreats([]);

      setFeedback({

        type: "success",

        message: "Threat history cleared. Cumulative statistics were not reset.",

      });

    } catch (error) {

      console.error("Could not clear threat history:", error);

      setFeedback({

        type: "error",

        message:

          error instanceof Error ? error.message : "Could not clear threat history.",

      });

    } finally {

      setPendingAction(null);

    }

  };



  const handleExportData = () => {

    try {

      const exportPayload = {

        exportDate: new Date().toISOString(),

        statistics: stats,

        allowlist,

        threatHistory: threats,

      };



      const blob = new Blob([JSON.stringify(exportPayload, null, 2)], {

        type: "application/json",

      });

      const url = URL.createObjectURL(blob);

      const anchor = document.createElement("a");



      anchor.href = url;

      anchor.download = `clickshield-security-audit-${Date.now()}.json`;

      anchor.style.display = "none";

      document.body.appendChild(anchor);

      anchor.click();

      anchor.remove();



      // Allow the browser to start the download before releasing the object URL.

      window.setTimeout(() => URL.revokeObjectURL(url), 1000);



      setFeedback({ type: "success", message: "Audit log export started." });

    } catch (error) {

      console.error("Could not export dashboard data:", error);

      setFeedback({ type: "error", message: "Could not export the audit log." });

    }

  };



  const handleAddAllowlist = async (domainToAdd: string) => {

    if (pendingAction) return;



    const hostname = normalizeHostname(domainToAdd);



    if (!hostname) {

      setFeedback({

        type: "error",

        message: "Enter a valid hostname only, without a URL path or port.",

      });

      return;

    }



    setPendingAction("allowlist-add");

    setFeedback(null);



    try {

      const response = await chrome.runtime.sendMessage({

        type: "ALLOWLIST_ADD",

        payload: { hostname },

      });

      const responseError = getResponseError(response);



      if (responseError) {

        throw new Error(responseError);

      }



      if (!Array.isArray(response?.allowlist)) {

        throw new Error("The background service did not return the updated allowlist.");

      }



      setAllowlist(response.allowlist as string[]);

      setNewDomain("");

      setFeedback({

        type: "success",

        message: `${hostname} added to the allowlist.`,

      });

    } catch (error) {

      console.error("Could not add allowlist hostname:", error);

      setFeedback({

        type: "error",

        message: error instanceof Error ? error.message : "Could not add the hostname.",

      });

    } finally {

      setPendingAction(null);

    }

  };



  const handleRemoveAllowlist = async (host: string) => {

    if (pendingAction) return;



    setPendingAction(`allowlist-remove:${host}`);

    setFeedback(null);



    try {

      const response = await chrome.runtime.sendMessage({

        type: "ALLOWLIST_REMOVE",

        payload: { hostname: host },

      });

      const responseError = getResponseError(response);



      if (responseError) {

        throw new Error(responseError);

      }



      if (!Array.isArray(response?.allowlist)) {

        throw new Error("The background service did not return the updated allowlist.");

      }



      setAllowlist(response.allowlist as string[]);

      setFeedback({

        type: "success",

        message: `${host} removed from the allowlist.`,

      });

    } catch (error) {

      console.error("Could not remove allowlist hostname:", error);

      setFeedback({

        type: "error",

        message: error instanceof Error ? error.message : "Could not remove the hostname.",

      });

    } finally {

      setPendingAction(null);

    }

  };



  const filteredThreats = useMemo(() => {

    const query = searchQuery.trim().toLowerCase();



    return threats.filter((threat) => {

      const matchesSearch =

        !query ||

        threat.hostname.toLowerCase().includes(query) ||

        threat.signals.some((signal) => signal.toLowerCase().includes(query));

      const matchesLevel = levelFilter === "ALL" || threat.riskLevel === levelFilter;



      return matchesSearch && matchesLevel;

    });

  }, [threats, searchQuery, levelFilter]);



  const isBusy = pendingAction !== null;



  return (

    <div className="flex min-h-screen bg-[#080808] text-[#F5F5F5] font-sans">

      <ThreatDetailsModal

        threat={selectedThreat}

        onClose={() => setSelectedThreat(null)}

        onAllowlist={(hostname) => {

          void handleAddAllowlist(hostname);

        }}

      />



      {/* Sidebar */}

      <aside className="w-64 shrink-0 border-r border-[#222222] bg-[#0E0E0E] flex flex-col justify-between p-5">

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



          <nav className="space-y-1.5 font-mono text-xs" aria-label="Dashboard sections">

            <button

              type="button"

              onClick={() => setActiveTab("overview")}

              aria-current={activeTab === "overview" ? "page" : undefined}

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

              type="button"

              onClick={() => setActiveTab("analytics")}

              aria-current={activeTab === "analytics" ? "page" : undefined}

              className={`w-full flex items-center gap-2.5 px-3 py-2.5 rounded transition-colors text-left cursor-pointer ${

                activeTab === "analytics"

                  ? "bg-[#1E1E1E] text-[#E5B83B] border-l-2 border-[#E5B83B]"

                  : "text-neutral-400 hover:bg-[#161616] hover:text-neutral-200"

              }`}

            >

              <BarChart2 className="w-4 h-4" />

              Threat Analytics

            </button>



            <button

              type="button"

              onClick={() => setActiveTab("history")}

              aria-current={activeTab === "history" ? "page" : undefined}

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

              type="button"

              onClick={() => setActiveTab("allowlist")}

              aria-current={activeTab === "allowlist" ? "page" : undefined}

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

            <span className="text-neutral-300">Local-First Defense</span>

          </div>

          <div>Manifest V3 · v0.1.0</div>

        </div>

      </aside>



      {/* Main Content Area */}

      <main className="min-w-0 flex-1 p-8 overflow-y-auto">

        <header className="flex items-center justify-between gap-4 pb-6 border-b border-[#222222] mb-8">

          <div>

            <h1 className="text-2xl font-black font-mono tracking-tight text-neutral-100">

              Security Analytics & Control

            </h1>

            <p className="text-xs font-mono text-neutral-400 mt-1">

              Active behavioral monitoring for deceptive verification and ClickFix command attacks.

            </p>

          </div>



          <div className="flex items-center gap-3 shrink-0">

            <button

              type="button"

              onClick={handleExportData}

              className="flex items-center gap-1.5 px-3 py-1.5 rounded bg-[#161616] hover:bg-[#202020] border border-[#2D2D2D] text-xs font-mono text-neutral-300 transition-colors cursor-pointer"

            >

              <Download className="w-3.5 h-3.5 text-[#E5B83B]" />

              Export Audit Log

            </button>



            <button

              type="button"

              onClick={() => void chrome.runtime.openOptionsPage()}

              className="flex items-center gap-1.5 px-3 py-1.5 rounded bg-[#161616] hover:bg-[#202020] border border-[#2D2D2D] text-xs font-mono text-neutral-300 transition-colors cursor-pointer"

            >

              <Settings className="w-3.5 h-3.5 text-[#E5B83B]" />

              Settings

            </button>

          </div>

        </header>



        {feedback && (

          <div

            role={feedback.type === "error" ? "alert" : "status"}

            className={`mb-6 rounded border px-4 py-3 text-xs font-mono ${

              feedback.type === "error"

                ? "border-red-500/30 bg-red-500/10 text-red-300"

                : "border-[#16A34A]/30 bg-[#16A34A]/10 text-green-300"

            }`}

          >

            {feedback.message}

          </div>

        )}



        {isLoading ? (

          <div className="py-16 text-center font-mono text-xs text-neutral-500">

            Loading dashboard data...

          </div>

        ) : (

          <>

            {activeTab === "overview" && (

              <div className="space-y-8">

                {/* KPI Cards */}

                <div className="grid grid-cols-1 sm:grid-cols-2 xl:grid-cols-4 gap-4">

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

                      Confirmed protection actions

                    </div>

                  </div>



                  <div className="p-5 rounded bg-[#111111] border border-[#222222]">

                    <div className="text-[11px] font-mono text-neutral-400 uppercase tracking-wider">

                      Protection Engine

                    </div>

                    <div

                      className={`text-xl font-bold font-mono mt-2 flex items-center gap-2 ${

                        settings?.protectionEnabled

                          ? "text-[#4ADE80]"

                          : "text-[#F87171]"

                      }`}

                    >

                      <span

                        className={`w-2.5 h-2.5 rounded-full ${

                          settings?.protectionEnabled

                            ? "bg-[#16A34A] animate-pulse"

                            : "bg-[#DC2626]"

                        }`}

                      />

                      {settings === null
                        ? "STATUS UNAVAILABLE"
                        : settings.protectionEnabled
                          ? "OPERATIONAL"
                          : "PAUSED"}

                    </div>

                    <div className="text-[10px] text-neutral-500 font-mono mt-1">

                      {settings?.clipboardProtection

                        ? "Page and clipboard guards enabled"

                        : "Clipboard guard disabled"}

                    </div>

                  </div>

                </div>



                {/* Quick Threat Chart preview */}

                <div className="p-5 rounded bg-[#111111] border border-[#222222]">

                  <h2 className="text-sm font-bold font-mono text-neutral-200 uppercase tracking-wider mb-4">

                    Threat Signal Distribution

                  </h2>

                  <ThreatChart threats={threats} />

                </div>



                {/* Recent threats table */}

                <div className="rounded bg-[#111111] border border-[#222222] p-5">

                  <div className="flex items-center justify-between mb-4">

                    <h2 className="text-sm font-bold font-mono text-neutral-200 uppercase tracking-wider">

                      Recent Threat Detections

                    </h2>

                    <button

                      type="button"

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

                            <th className="pb-3">DETAILS</th>

                          </tr>

                        </thead>

                        <tbody className="divide-y divide-[#1C1C1C]">

                          {threats.slice(0, 5).map((threat) => (

                            <tr key={threat.id} className="hover:bg-[#171717]">

                              <td className="py-3 text-neutral-200 font-semibold">

                                {threat.hostname}

                              </td>

                              <td className="py-3 text-[#E5B83B]">

                                {threat.riskScore}/100

                              </td>

                              <td className="py-3">

                                <span

                                  className={`px-2 py-0.5 rounded text-[10px] font-bold ${getRiskBadgeClass(

                                    threat.riskLevel

                                  )}`}

                                >

                                  {threat.riskLevel}

                                </span>

                              </td>

                              <td className="py-3 text-neutral-400">

                                {threat.signals

                                  .map((signal) => signal.replace(/\_/g, " "))

                                  .join(", ")}

                              </td>

                              <td className="py-3">

                                <button

                                  type="button"

                                  onClick={() => setSelectedThreat(threat)}

                                  className="text-neutral-400 hover:text-[#E5B83B] cursor-pointer"

                                >

                                  Inspect →

                                </button>

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



            {activeTab === "analytics" && (

              <div className="space-y-6">

                <div className="p-6 rounded bg-[#111111] border border-[#222222]">

                  <h2 className="text-base font-bold font-mono text-neutral-200 mb-1">

                    Threat Vector Frequencies

                  </h2>

                  <p className="text-xs font-mono text-neutral-400 mb-6">

                    Relative prevalence of deceptive verification mechanisms,

                    clipboard hooks, and LOLBin command cradles.

                  </p>

                  <ThreatChart threats={threats} />

                </div>



                <div className="grid grid-cols-1 xl:grid-cols-2 gap-4">

                  <div className="p-5 rounded bg-[#111111] border border-[#222222]">

                    <h3 className="text-xs font-mono font-bold text-neutral-300 uppercase mb-3">

                      Behavioral Guard Efficacy

                    </h3>

                    <div className="space-y-3 font-mono text-xs">

                      <div className="flex justify-between gap-4 py-1.5 border-b border-[#1C1C1C]">

                        <span className="text-neutral-400">Total Scans Performed:</span>

                        <span className="font-bold text-neutral-200">

                          {stats.pagesScanned.toLocaleString()}

                        </span>

                      </div>

                      <div className="flex justify-between gap-4 py-1.5 border-b border-[#1C1C1C]">

                        <span className="text-neutral-400">Suspicious Pages Caught:</span>

                        <span className="font-bold text-[#E5B83B]">

                          {stats.threatsDetected.toLocaleString()}

                        </span>

                      </div>

                      <div className="flex justify-between gap-4 py-1.5">

                        <span className="text-neutral-400">Confirmed Interventions:</span>

                        <span className="font-bold text-[#4ADE80]">

                          {stats.interventions.toLocaleString()}

                        </span>

                      </div>

                    </div>

                  </div>



                  <div className="p-5 rounded bg-[#111111] border border-[#222222]">

                    <h3 className="text-xs font-mono font-bold text-neutral-300 uppercase mb-3">

                      Privacy & Telemetry Verification

                    </h3>

                    <div className="space-y-2 text-xs font-mono text-neutral-400">

                      <p className="flex items-center gap-2 text-[#4ADE80]">

                        <ShieldCheck className="w-4 h-4" />

                        Local heuristic processing

                      </p>

                      <p className="flex items-center gap-2 text-[#4ADE80]">

                        <ShieldCheck className="w-4 h-4" />

                        No external cloud telemetry configured

                      </p>

                      <p className="flex items-center gap-2 text-[#4ADE80]">

                        <ShieldCheck className="w-4 h-4" />

                        Raw clipboard contents are not stored in threat history

                      </p>

                    </div>

                  </div>

                </div>

              </div>

            )}



            {activeTab === "history" && (

              <div className="rounded bg-[#111111] border border-[#222222] p-6">

                <div className="flex items-center justify-between gap-4 mb-6">

                  <div>

                    <h2 className="text-lg font-bold font-mono text-neutral-200">

                      Full Threat Log

                    </h2>

                    <p className="text-xs font-mono text-neutral-400">

                      Inspect recorded attack vectors or export historical detections.

                    </p>

                  </div>



                  <div className="flex items-center gap-2 shrink-0">

                    <button

                      type="button"

                      onClick={handleExportData}

                      className="flex items-center gap-1.5 px-3 py-1.5 rounded bg-[#1C1C1C] hover:bg-[#252525] border border-[#333333] text-xs font-mono text-neutral-200 transition-colors cursor-pointer"

                    >

                      <Download className="w-3.5 h-3.5 text-[#E5B83B]" />

                      Export JSON

                    </button>



                    {threats.length > 0 && (

                      <button

                        type="button"

                        onClick={() => void handleClearHistory()}

                        disabled={isBusy}

                        className="flex items-center gap-1.5 px-3 py-1.5 rounded bg-[#2B1111] hover:bg-[#3D1414] border border-[#DC2626]/40 text-xs font-mono text-[#F87171] transition-colors cursor-pointer disabled:opacity-40 disabled:cursor-not-allowed"

                      >

                        <Trash2 className="w-3.5 h-3.5" />

                        {pendingAction === "clear-history" ? "Clearing..." : "Clear History"}

                      </button>

                    )}

                  </div>

                </div>



                {/* Search & Filter toolbar */}

                <div className="flex flex-col sm:flex-row items-stretch sm:items-center gap-3 mb-6">

                  <div className="flex-1 relative">

                    <Search className="w-4 h-4 text-neutral-500 absolute left-3 top-2.5" />

                    <input

                      type="text"

                      placeholder="Filter by hostname or signal type..."

                      value={searchQuery}

                      onChange={(event) => setSearchQuery(event.target.value)}

                      className="w-full bg-[#161616] border border-[#2A2A2A] rounded pl-9 pr-3 py-2 text-xs font-mono text-neutral-200 focus:outline-none focus:border-[#E5B83B]"

                    />

                  </div>



                  <div className="flex items-center gap-1.5 font-mono text-xs">

                    <Filter className="w-3.5 h-3.5 text-neutral-400" />

                    <select

                      value={levelFilter}

                      onChange={(event) => setLevelFilter(event.target.value)}

                      className="bg-[#161616] border border-[#2A2A2A] rounded px-2.5 py-2 text-xs font-mono text-neutral-200 focus:outline-none cursor-pointer"

                    >

                      <option value="ALL">All Levels</option>

                      <option value="CRITICAL">Critical Only</option>

                      <option value="HIGH">High Risk</option>

                      <option value="SUSPICIOUS">Suspicious</option>

                      <option value="LOW">Low Risk</option>

                    </select>

                  </div>

                </div>



                {filteredThreats.length === 0 ? (

                  <div className="text-center py-16 font-mono text-xs text-neutral-500">

                    No matching threat records found.

                  </div>

                ) : (

                  <div className="overflow-x-auto">

                    <table className="w-full text-left font-mono text-xs">

                      <thead>

                        <tr className="border-b border-[#222222] text-neutral-500 text-[11px]">

                          <th className="pb-3 pr-4">TIMESTAMP</th>

                          <th className="pb-3 pr-4">HOSTNAME</th>

                          <th className="pb-3 pr-4">RISK SCORE</th>

                          <th className="pb-3 pr-4">LEVEL</th>

                          <th className="pb-3 pr-4">SIGNALS</th>

                          <th className="pb-3 pr-4">ACTION</th>

                          <th className="pb-3">DETAILS</th>

                        </tr>

                      </thead>

                      <tbody className="divide-y divide-[#1C1C1C]">

                        {filteredThreats.map((threat) => (

                          <tr key={threat.id} className="hover:bg-[#171717]">

                            <td className="py-3 pr-4 text-neutral-400 text-[11px] whitespace-nowrap">

                              {formatTimestamp(threat.timestamp)}

                            </td>

                            <td className="py-3 pr-4 text-neutral-200 font-semibold">

                              {threat.hostname}

                            </td>

                            <td className="py-3 pr-4 text-[#E5B83B] font-bold">

                              {threat.riskScore}

                            </td>

                            <td className="py-3 pr-4">

                              <span

                                className={`px-2 py-0.5 rounded text-[10px] font-bold ${getRiskBadgeClass(

                                  threat.riskLevel

                                )}`}

                              >

                                {threat.riskLevel}

                              </span>

                            </td>

                            <td className="py-3 pr-4 text-neutral-400 max-w-xs truncate">

                              {threat.signals

                                .map((signal) => signal.replace(/\_/g, " "))

                                .join(", ")}

                            </td>

                            <td className="py-3 pr-4 text-neutral-300">

                              {threat.action}

                            </td>

                            <td className="py-3">

                              <button

                                type="button"

                                onClick={() => setSelectedThreat(threat)}

                                className="text-neutral-400 hover:text-[#E5B83B] cursor-pointer"

                              >

                                Inspect →

                              </button>

                            </td>

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



                <form

                  onSubmit={(event) => {

                    event.preventDefault();

                    void handleAddAllowlist(newDomain);

                  }}

                  className="flex flex-col sm:flex-row gap-3 mb-6"

                >

                  <input

                    type="text"

                    value={newDomain}

                    onChange={(event) => setNewDomain(event.target.value)}

                    placeholder="e.g. portal.company.internal"

                    autoComplete="off"

                    spellCheck={false}

                    aria-label="Hostname to add to allowlist"

                    className="flex-1 min-w-0 bg-[#1A1A1A] border border-[#2E2E2E] rounded px-3 py-2 text-xs font-mono text-neutral-200 focus:outline-none focus:border-[#E5B83B]"

                  />

                  <button

                    type="submit"

                    disabled={isBusy || !newDomain.trim()}

                    className="flex items-center justify-center gap-1.5 px-4 py-2 bg-[#E5B83B] hover:bg-[#F5CB5C] text-black font-mono font-bold text-xs rounded transition-colors cursor-pointer disabled:opacity-40 disabled:cursor-not-allowed"

                  >

                    <Plus className="w-4 h-4" />

                    {pendingAction === "allowlist-add" ? "Adding..." : "Add Domain"}

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

                        className="flex items-center justify-between gap-3 p-3 rounded bg-[#171717] border border-[#262626] font-mono text-xs"

                      >

                        <span className="text-neutral-200 font-semibold break-all">

                          {domain}

                        </span>

                        <button

                          type="button"

                          onClick={() => void handleRemoveAllowlist(domain)}

                          disabled={isBusy}

                          className="shrink-0 text-neutral-500 hover:text-[#DC2626] transition-colors cursor-pointer p-1 disabled:opacity-40 disabled:cursor-not-allowed"

                          title={`Remove ${domain} from allowlist`}

                          aria-label={`Remove ${domain} from allowlist`}

                        >

                          <X className="w-4 h-4" />

                        </button>

                      </div>

                    ))

                  )}

                </div>

              </div>

            )}

          </>

        )}

      </main>

    </div>

  );

}
