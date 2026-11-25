import React, { useEffect, useState } from "react";
import { Header } from "./components/Header";
import { RiskGauge } from "./components/RiskGauge";
import { WebsiteInfo } from "./components/WebsiteInfo";
import { ThreatList } from "./components/ThreatList";
import { QuickActions } from "./components/QuickActions";
import { Footer } from "./components/Footer";
import type { RiskLevel, ThreatSignal } from "../shared/types/signal";
import type { TabState } from "../shared/types/messages";
import { isScannableUrl } from "../shared/utils/url-utils";

export default function App() {
  const [loading, setLoading] = useState(true);
  const [isScanning, setIsScanning] = useState(false);
  const [tabId, setTabId] = useState<number | null>(null);
  const [hostname, setHostname] = useState<string>("");
  const [url, setUrl] = useState<string>("");
  const [isScannable, setIsScannable] = useState<boolean>(true);
  const [protectionActive, setProtectionActive] = useState<boolean>(true);
  const [isAllowlisted, setIsAllowlisted] = useState<boolean>(false);
  const [riskScore, setRiskScore] = useState<number>(0);
  const [riskLevel, setRiskLevel] = useState<RiskLevel>("LOW");
  const [signals, setSignals] = useState<ThreatSignal[]>([]);

  useEffect(() => {
    loadTabInfo();
  }, []);

  const loadTabInfo = async () => {
    try {
      const [activeTab] = await chrome.tabs.query({ active: true, currentWindow: true });
      if (!activeTab || activeTab.id === undefined) {
        setLoading(false);
        return;
      }

      setTabId(activeTab.id);
      const tabUrl = activeTab.url || "";
      setUrl(tabUrl);

      const scannable = isScannableUrl(tabUrl);
      setIsScannable(scannable);

      if (scannable) {
        try {
          const parsed = new URL(tabUrl);
          setHostname(parsed.hostname);
        } catch {
          setHostname("");
        }
      } else {
        setHostname(tabUrl.split("/")[0] || "restricted");
      }

      // Query service worker for stored state
      const response = await chrome.runtime.sendMessage({
        type: "GET_TAB_STATE",
        payload: { tabId: activeTab.id },
      });

      if (response && response.state) {
        const state: TabState = response.state;
        setRiskScore(state.score || 0);
        setRiskLevel((state.level as RiskLevel) || "LOW");
        setSignals(state.signals || []);
        setIsAllowlisted(Boolean(state.isAllowlisted));
        setProtectionActive(state.protectionEnabled !== false);
      } else {
        // Query global settings
        const settingsRes = await chrome.runtime.sendMessage({ type: "GET_SETTINGS" });
        if (settingsRes?.settings) {
          setProtectionActive(settingsRes.settings.protectionEnabled);
        }
      }
    } catch (err) {
      console.warn("Failed to retrieve tab state:", err);
    } finally {
      setLoading(false);
    }
  };

  const handleToggleProtection = async () => {
    const nextState = !protectionActive;
    setProtectionActive(nextState);
    await chrome.runtime.sendMessage({
      type: "UPDATE_SETTINGS",
      payload: { protectionEnabled: nextState },
    });
    // Trigger rescan
    handleRescan();
  };

  const handleRescan = async () => {
    if (!tabId || !isScannable) return;
    setIsScanning(true);
    try {
      await chrome.tabs.sendMessage(tabId, { type: "TRIGGER_RESCAN" });
      // Give the content script a moment to complete and report
      setTimeout(async () => {
        await loadTabInfo();
        setIsScanning(false);
      }, 700);
    } catch {
      setIsScanning(false);
    }
  };

  const handleToggleAllowlist = async () => {
    if (!hostname) return;
    try {
      if (isAllowlisted) {
        await chrome.runtime.sendMessage({
          type: "ALLOWLIST_REMOVE",
          payload: { hostname },
        });
        setIsAllowlisted(false);
      } else {
        await chrome.runtime.sendMessage({
          type: "ALLOWLIST_ADD",
          payload: { hostname },
        });
        setIsAllowlisted(true);
      }
      handleRescan();
    } catch (err) {
      console.error("Failed to update allowlist:", err);
    }
  };

  const handleOpenDashboard = () => {
    chrome.tabs.create({ url: chrome.runtime.getURL("src/dashboard/index.html") });
  };

  const handleOpenSettings = () => {
    chrome.runtime.openOptionsPage();
  };

  if (loading) {
    return (
      <div className="w-[380px] h-[400px] flex items-center justify-center bg-[#080808] text-neutral-400 font-mono text-xs">
        <div className="flex items-center gap-2">
          <span className="w-2 h-2 rounded-full bg-[#E5B83B] animate-pulse" />
          Initializing ClickShield...
        </div>
      </div>
    );
  }

  return (
    <div className="w-[380px] min-h-[480px] flex flex-col justify-between bg-[#080808] border border-[#222222]">
      <div>
        <Header
          protectionActive={protectionActive}
          onToggleProtection={handleToggleProtection}
        />
        <RiskGauge score={riskScore} level={riskLevel} />
        <WebsiteInfo
          hostname={hostname}
          isScannable={isScannable}
          isAllowlisted={isAllowlisted}
          signalCount={signals.length}
        />
        <ThreatList signals={signals} />
      </div>

      <div>
        <QuickActions
          onRescan={handleRescan}
          onOpenDashboard={handleOpenDashboard}
          onToggleAllowlist={handleToggleAllowlist}
          isAllowlisted={isAllowlisted}
          isScanning={isScanning}
          canAllowlist={isScannable && Boolean(hostname)}
        />
        <Footer onOpenSettings={handleOpenSettings} />
      </div>
    </div>
  );
}

