import React, { useEffect, useRef, useState } from "react";

import { AlertTriangle } from "lucide-react";

import { Header } from "./components/Header";

import { RiskGauge } from "./components/RiskGauge";

import { WebsiteInfo } from "./components/WebsiteInfo";

import { ThreatList } from "./components/ThreatList";

import { QuickActions } from "./components/QuickActions";

import { Footer } from "./components/Footer";

import type { RiskLevel, SignalType, ThreatSignal } from "../shared/types/signal";

import { isScannableUrl } from "../shared/utils/url-utils";

type RuntimeResponse = Record<string, unknown>;

const VALID_SIGNAL_TYPES: readonly SignalType[] = [

  "FAKE_CAPTCHA",

  "SUSPICIOUS_INSTRUCTION",

  "CLIPBOARD_MANIPULATION",

  "EXECUTION_INSTRUCTION",

  "SUSPICIOUS_DOMAIN",

  "DOMAIN_IMPERSONATION",

];

function isRecord(value: unknown): value is Record<string, unknown> {

  return typeof value === "object" && value !== null && !Array.isArray(value);

}

function getResponseError(response: unknown): string | null {

  if (

    isRecord(response) &&

    typeof response.error === "string" &&

    response.error.trim()

  ) {

    return response.error;

  }

  return null;

}

async function sendRuntimeMessage(message: {

  type: string;

  payload?: unknown;

}): Promise<RuntimeResponse> {

  let response: unknown;

  try {
    response = await chrome.runtime.sendMessage(message);
  } catch (error) {
    const messageText = error instanceof Error ? error.message : "";

    if (/receiving end does not exist|could not establish connection|message port closed/i.test(messageText)) {
      throw new Error(
        "ClickShield's background service is unavailable. Reload the extension from chrome://extensions, then reopen the popup."
      );
    }

    throw error;
  }

  const responseError = getResponseError(response);

  if (responseError) {

    throw new Error(responseError);

  }

  if (!isRecord(response)) {

    throw new Error("The background service returned an invalid response.");

  }

  return response;

}

function normalizeRiskScore(value: unknown): number {

  if (typeof value !== "number" || !Number.isFinite(value)) {

    return 0;

  }

  return Math.max(0, Math.min(100, Math.round(value)));

}

function normalizeRiskLevel(_value: unknown, score: number): RiskLevel {
  // Derive the displayed level from the score so stale or malformed stored
  // state cannot show a risk label that contradicts its numeric score.
  if (score >= 80) return "CRITICAL";
  if (score >= 60) return "HIGH";
  if (score >= 30) return "SUSPICIOUS";
  return "LOW";
}

function normalizeSignals(value: unknown): ThreatSignal[] {

  if (!Array.isArray(value)) {

    return [];

  }

  return value

    .filter((item): item is Record<string, unknown> => isRecord(item))

    .filter((item) =>

      typeof item.type === "string" &&

      VALID_SIGNAL_TYPES.includes(item.type as SignalType)

    )

    .map((item) => ({

      type: item.type as SignalType,

      reason:

        typeof item.reason === "string"

          ? item.reason.slice(0, 500)

          : "Suspicious page behavior detected.",

      ...(typeof item.weight === "number" && Number.isFinite(item.weight)

        ? { weight: Math.max(0, Math.min(100, item.weight)) }

        : {}),

      ...(typeof item.snippet === "string"

        ? { snippet: item.snippet.slice(0, 200) }

        : {}),

    }));

}

function getHostname(url: string, scannable: boolean): string {

  if (!url) return "No active webpage";

  try {

    const parsed = new URL(url);

    if (parsed.protocol === "file:") {

      return "Local file";

    }

    if (parsed.hostname) {

      return parsed.hostname.toLowerCase();

    }

    return scannable

      ? "Unknown host"

      : `${parsed.protocol.replace(":", "")} page`;

  } catch {

    return scannable ? "Unknown host" : "Restricted browser page";

  }

}

function isAllowlistableHostname(hostname: string): boolean {

  if (!hostname || hostname === "Local file" || hostname.length > 253) {

    return false;

  }

  try {

    const parsed = new URL(`https\\://${hostname}`);

    return (

      parsed.hostname.length > 0 &&

      !parsed.username &&

      !parsed.password &&

      !parsed.port &&

      parsed.pathname === "/" &&

      !parsed.search &&

      !parsed.hash

    );

  } catch {

    return false;

  }

}

function tabStateMatchesUrl(state: unknown, currentUrl: string): boolean {

  if (!isRecord(state) || typeof state.url !== "string" || !currentUrl) {

    return false;

  }

  // Ignore hash-only differences, but do not display a scan from another route.

  try {

    const storedUrl = new URL(state.url);

    const activeUrl = new URL(currentUrl);

    return (

      storedUrl.origin === activeUrl.origin &&

      storedUrl.pathname === activeUrl.pathname &&

      storedUrl.search === activeUrl.search

    );

  } catch {

    return state.url === currentUrl;

  }

}

function applyRiskState(

  source: Record<string, unknown>,

  setRiskScore: React.Dispatch<React.SetStateAction<number>>,

  setRiskLevel: React.Dispatch<React.SetStateAction<RiskLevel>>,

  setSignals: React.Dispatch<React.SetStateAction<ThreatSignal[]>>

): void {

  const score = normalizeRiskScore(source.score);

  setRiskScore(score);

  setRiskLevel(normalizeRiskLevel(source.level, score));

  setSignals(normalizeSignals(source.signals));

}

export default function App() {

  const [loading, setLoading] = useState(true);

  const [isScanning, setIsScanning] = useState(false);

  const [isUpdatingProtection, setIsUpdatingProtection] = useState(false);

  const [isUpdatingAllowlist, setIsUpdatingAllowlist] = useState(false);

  const [tabId, setTabId] = useState<number | null>(null);

  const [hostname, setHostname] = useState("");

  const [isScannable, setIsScannable] = useState(false);

  const [protectionActive, setProtectionActive] = useState(false);

  const [isAllowlisted, setIsAllowlisted] = useState(false);

  const [riskScore, setRiskScore] = useState(0);

  const [riskLevel, setRiskLevel] = useState<RiskLevel>("LOW");

  const [signals, setSignals] = useState<ThreatSignal[]>([]);

  const [feedback, setFeedback] = useState("");

  const loadSequenceRef = useRef(0);

  const scanningRef = useRef(false);

  const protectionUpdateRef = useRef(false);

  const allowlistUpdateRef = useRef(false);

  useEffect(() => {

    void loadTabInfo();

    return () => {

      // Prevent an older asynchronous load from overwriting a newer popup state.

      loadSequenceRef.current += 1;

    };

    // The popup loads its active-tab snapshot once when it opens.

    // eslint-disable-next-line react-hooks/exhaustive-deps

  }, []);

  const loadTabInfo = async () => {

    const requestId = ++loadSequenceRef.current;

    setFeedback("");

    try {

      const [activeTab] = await chrome.tabs.query({

        active: true,

        currentWindow: true,

      });

      if (requestId !== loadSequenceRef.current) return;

      // Settings are global and must be read even when the current tab is restricted.

      const settingsResponse = await sendRuntimeMessage({ type: "GET_SETTINGS" });

      const settings = settingsResponse.settings;

      if (!isRecord(settings) || typeof settings.protectionEnabled !== "boolean") {

        throw new Error("Protection settings were not returned in the expected format.");

      }

      if (requestId !== loadSequenceRef.current) return;

      setProtectionActive(settings.protectionEnabled);

      if (!activeTab || activeTab.id === undefined) {

        setTabId(null);

        setHostname("No active webpage");

        setIsScannable(false);

        setIsAllowlisted(false);

        setRiskScore(0);

        setRiskLevel("LOW");

        setSignals([]);

        setFeedback("No active browser tab is available.");

        return;

      }

      const activeTabId = activeTab.id;

      const activeUrl = activeTab.url || "";

      const scannable = isScannableUrl(activeUrl);

      const currentHostname = getHostname(activeUrl, scannable);

      setTabId(activeTabId);

      setHostname(currentHostname);

      setIsScannable(scannable);

      //  Read the tab snapshot and allowlist independently so one failure does not

      // prevent the other information from appearing in the popup.

      const [stateResult, allowlistResult] = await Promise.allSettled([

        sendRuntimeMessage({

          type: "GET_TAB_STATE",

          payload: { tabId: activeTabId },

        }),

        sendRuntimeMessage({ type: "GET_ALLOWLIST" }),

      ]);

      if (requestId !== loadSequenceRef.current) return;

      let storedState: unknown = null;

      if (stateResult.status === "fulfilled") {

        storedState = stateResult.value.state;

      } else {

        console.debug("Could not retrieve stored tab state:", stateResult.reason);

      }

      if (allowlistResult.status === "fulfilled") {

        const values = allowlistResult.value.allowlist;

        if (Array.isArray(values)) {

          setIsAllowlisted(

            typeof currentHostname === "string" &&

              values.some(

                (entry) =>

                  typeof entry === "string" &&

                  entry.toLowerCase() === currentHostname.toLowerCase()

              )

          );

        } else {

          setIsAllowlisted(

            isRecord(storedState) && storedState.isAllowlisted === true

          );

        }

      } else {

        console.debug("Could not retrieve the allowlist:", allowlistResult.reason);

        setIsAllowlisted(

          isRecord(storedState) && storedState.isAllowlisted === true

        );

      }

      if (!settings.protectionEnabled) {

        // Stored detections are historical once the global protection switch is off.

        setRiskScore(0);

        setRiskLevel("LOW");

        setSignals([]);

        return;

      }

      const hasMatchingStoredState = tabStateMatchesUrl(storedState, activeUrl);

      if (hasMatchingStoredState && isRecord(storedState)) {

        applyRiskState(

          storedState,

          setRiskScore,

          setRiskLevel,

          setSignals

        );

        return;

      }

      // A stale tab snapshot must not be shown for a different URL/route.

      setRiskScore(0);

      setRiskLevel("LOW");

      setSignals([]);

      if (scannable && settings.protectionEnabled) {

        try {

          const tabResponse: unknown = await chrome.tabs.sendMessage(activeTabId, {

            type: "GET_LIVE_SCAN",

          });

          if (requestId !== loadSequenceRef.current) return;

          if (isRecord(tabResponse) && isRecord(tabResponse.result)) {

            applyRiskState(

              tabResponse.result,

              setRiskScore,

              setRiskLevel,

              setSignals

            );

          }

        } catch (error) {

          console.debug("Live scan is not available for this tab yet:", error);

          setFeedback(

            "ClickShield could not read this page yet. Try rescanning after the page finishes loading."

          );

        }

      }

    } catch (error) {

      console.error("Failed to retrieve ClickShield tab information:", error);

      setFeedback(

        error instanceof Error

          ? error.message

          : "Could not retrieve the current tab information."

      );

    } finally {

      if (requestId === loadSequenceRef.current) {

        setLoading(false);

      }

    }

  };

  const handleToggleProtection = async () => {

    if (protectionUpdateRef.current) return;

    protectionUpdateRef.current = true;

    setIsUpdatingProtection(true);

    setFeedback("");

    const nextState = !protectionActive;

    try {

      const response = await sendRuntimeMessage({

        type: "UPDATE_SETTINGS",

        payload: { protectionEnabled: nextState },

      });

      if (

        !isRecord(response.settings) ||

        response.settings.protectionEnabled !== nextState

      ) {

        throw new Error("The background service did not confirm the protection setting.");

      }

      // Reflect the new state only after the background service confirms the save.

      setProtectionActive(nextState);

      if (!nextState) {

        // Avoid presenting old scan results as current protection activity.

        setRiskScore(0);

        setRiskLevel("LOW");

        setSignals([]);

      } else if (tabId !== null && isScannable) {

        await runRescan();

      }

    } catch (error) {

      console.error("Failed to update protection:", error);

      setFeedback(

        error instanceof Error

          ? error.message

          : "Could not update the protection setting."

      );

    } finally {

      protectionUpdateRef.current = false;

      setIsUpdatingProtection(false);

    }

  };

  const runRescan = async () => {

    if (tabId === null || !isScannable) {

      setFeedback("This browser page cannot be scanned by ClickShield.");

      return;

    }

    if (!protectionActive && !protectionUpdateRef.current) {

      setFeedback("Protection is disabled. Enable protection before rescanning.");

      return;

    }

    if (scanningRef.current) return;

    scanningRef.current = true;

    setIsScanning(true);

    setFeedback("");

    try {

      const response: unknown = await chrome.tabs.sendMessage(tabId, {

        type: "TRIGGER_RESCAN",

      });

      if (!isRecord(response) || response.status !== "OK" || !isRecord(response.result)) {

        throw new Error("The page did not return a valid scan result. It may still be loading.");

      }

      applyRiskState(response.result, setRiskScore, setRiskLevel, setSignals);

    } catch (error) {

      console.error("Page rescan failed:", error);

      const errorMessage = error instanceof Error ? error.message : "";

      setFeedback(
        /receiving end does not exist|could not establish connection|message port closed/i.test(errorMessage)
          ? "ClickShield's page scanner is not connected to this tab. Reload the webpage, then try rescanning."
          : errorMessage || "Could not rescan this page. Try again after it finishes loading."
      );

    } finally {

      scanningRef.current = false;

      setIsScanning(false);

    }

  };

  const handleRescan = async () => {

    await runRescan();

  };

  const handleToggleAllowlist = async () => {

    if (allowlistUpdateRef.current || !isAllowlistableHostname(hostname)) {

      return;

    }

    allowlistUpdateRef.current = true;

    setIsUpdatingAllowlist(true);

    setFeedback("");

    try {

      const response = await sendRuntimeMessage({

        type: isAllowlisted ? "ALLOWLIST_REMOVE" : "ALLOWLIST_ADD",

        payload: { hostname },

      });

      if (!Array.isArray(response.allowlist)) {

        throw new Error("The background service did not return the updated allowlist.");

      }

      const nextAllowlist = response.allowlist.filter(

        (entry): entry is string => typeof entry === "string"

      );

      const nextIsAllowlisted = nextAllowlist.some(

        (entry) => entry.toLowerCase() === hostname.toLowerCase()

      );

      setIsAllowlisted(nextIsAllowlisted);

      if (protectionActive) {

        await runRescan();

      } else {

        setRiskScore(0);

        setRiskLevel("LOW");

        setSignals([]);

      }

    } catch (error) {

      console.error("Failed to update allowlist:", error);

      setFeedback(

        error instanceof Error

          ? error.message

          : "Could not update the allowlist."

      );

    } finally {

      allowlistUpdateRef.current = false;

      setIsUpdatingAllowlist(false);

    }

  };

  const handleOpenDashboard = async () => {

    setFeedback("");

    try {

      await chrome.tabs.create({

        url: chrome.runtime.getURL("src/dashboard/index.html"),

      });

    } catch (error) {

      console.error("Could not open the dashboard:", error);

      setFeedback("Could not open the dashboard.");

    }

  };

  const handleOpenSettings = async () => {

    setFeedback("");

    try {

      await chrome.runtime.openOptionsPage();

    } catch (error) {

      console.error("Could not open settings:", error);

      setFeedback("Could not open ClickShield settings.");

    }

  };

  if (loading) {

    return (

      <div className="w-95 h-100 flex items-center justify-center bg-[#080808] text-neutral-400 font-mono text-xs">

        <div className="flex items-center gap-2">

          <span className="w-2 h-2 rounded-full bg-[#E5B83B] animate-pulse" />

          Initializing ClickShield...

        </div>

      </div>

    );

  }

  return (

    <div className="w-95 min-h-120 flex flex-col justify-between bg-[#080808] border border-[#222222]">

      <div>

        <div className={isUpdatingProtection ? "pointer-events-none opacity-70" : ""}>

          <Header

            protectionActive={protectionActive}

            onToggleProtection={handleToggleProtection}

          />

        </div>

        <RiskGauge score={riskScore} level={riskLevel} />

        <WebsiteInfo

          hostname={hostname}

          isScannable={isScannable}

          isAllowlisted={isAllowlisted}

          signalCount={signals.length}

        />

        <ThreatList signals={signals} />

        {feedback && (

          <div

            role="alert"

            className="mx-3 my-2 flex items-start gap-2 rounded border border-[#DC2626]/40 bg-[#DC2626]/10 p-2.5 text-[10px] font-mono text-[#FCA5A5]"

          >

            <AlertTriangle className="mt-0.5 h-3.5 w-3.5 shrink-0" />

            <span className="min-w-0 wrap-break-word">{feedback}</span>

          </div>

        )}

      </div>

      <div

        className={

          isUpdatingAllowlist || isUpdatingProtection

            ? "pointer-events-none opacity-70"

            : ""

        }

      >

        <QuickActions

          onRescan={handleRescan}

          onOpenDashboard={handleOpenDashboard}

          onToggleAllowlist={handleToggleAllowlist}

          isAllowlisted={isAllowlisted}

          isScanning={isScanning || isUpdatingAllowlist}

          canAllowlist={isScannable && isAllowlistableHostname(hostname)}

        />

        <Footer onOpenSettings={handleOpenSettings} />

      </div>

    </div>

  );

}
