import { calculateRisk } from "../engine/risk-engine";
import { StorageManager } from "../storage/storage-manager";
import { BADGE_COLORS } from "../shared/constants/risk-levels";
import { logger } from "../shared/utils/logger";
import type { ScanResult, RiskLevel, ThreatSignal } from "../shared/types/signal";
import type { TabState } from "../shared/types/messages";

chrome.runtime.onInstalled.addListener(async (details) => {
  logger.info("ClickShield extension installed/updated:", details.reason);
  await StorageManager.initializeDefaults();
});

chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
  // Guard against foreign messages
  if (sender.id !== chrome.runtime.id) {
    return false;
  }

  handleIncomingMessage(message, sender)
    .then((res) => sendResponse(res))
    .catch((err) => {
      logger.error("Message handling failed:", err);
      sendResponse({ error: err.message });
    });

  return true; // Keep message channel open for async response
});

async function handleIncomingMessage(
  message: { type: string; payload?: any },
  sender: chrome.runtime.MessageSender
) {
  const { type, payload } = message;

  switch (type) {
    case "SCAN_RESULT": {
      const tabId = sender.tab?.id;
      if (tabId === undefined) return { success: false };

      // In Chrome MV3 with all_frames: true, only the top frame (frameId === 0)
      // defines the tab's page scan result and badge. Subframes must never overwrite the tab state.
      if (sender.frameId !== 0) {
        return { success: false, ignored: "subframe" };
      }

      const scan: ScanResult = payload;
      if (typeof scan.score !== "number" || scan.score < 0 || scan.score > 100) {
        return { success: false, error: "Invalid score" };
      }

      const settings = await StorageManager.getSettings();
      const hostname = scan.hostname || "unknown";
      const isAllowed = await StorageManager.isAllowlisted(hostname);

      let effectiveScore = scan.score;
      let effectiveLevel = scan.level;

      if (!settings.protectionEnabled || isAllowed) {
        effectiveScore = 0;
        effectiveLevel = "LOW";
      }

      // Update badge
      const badgeText = effectiveScore > 0 ? String(effectiveScore) : "";
      const color = BADGE_COLORS[effectiveLevel as RiskLevel] || BADGE_COLORS.LOW;

      try {
        await chrome.action.setBadgeText({ tabId, text: badgeText });
        await chrome.action.setBadgeBackgroundColor({ tabId, color });
      } catch (e) {
        // Tab might be closing
      }

      const tabState: TabState = {
        score: effectiveScore,
        level: effectiveLevel,
        signals: scan.signals || [],
        hostname,
        url: scan.url || "",
        timestamp: scan.timestamp || Date.now(),
        protectionEnabled: settings.protectionEnabled,
        isAllowlisted: isAllowed,
      };

      await StorageManager.setTabState(tabId, tabState);
      await StorageManager.incrementStats("pagesScanned");

      // Record threat if suspicious or higher
      if (effectiveScore >= 30 && !isAllowed) {
        await StorageManager.addThreatRecord({
          id: `threat-${Date.now()}-${Math.random().toString(36).substring(2, 7)}`,
          hostname,
          url: scan.url || "",
          timestamp: Date.now(),
          riskScore: effectiveScore,
          riskLevel: effectiveLevel,
          signals: (scan.signals || []).map((s) => s.type),
          details: (scan.signals || []).map((s) => s.reason),
          action: effectiveScore >= 80 ? "WARNING_DISPLAYED" : "CAUTION_SHOWN",
        });

        // Show Chrome notification if critical threat and enabled
        if (effectiveScore >= 80 && settings.notificationsEnabled) {
          chrome.notifications.create({
            type: "basic",
            iconUrl: chrome.runtime.getURL("icons/icon128.png"),
            title: "ClickShield: High Risk Detected",
            message: `Suspicious ClickFix instructions detected on ${hostname}. Do not copy or run any commands!`,
            priority: 2,
          });
        }
      }

      return {
        success: true,
        effectiveScore,
        effectiveLevel,
        protectionEnabled: settings.protectionEnabled,
        isAllowlisted: isAllowed,
      };
    }

    case "SUBFRAME_THREAT": {
      const tabId = sender.tab?.id;
      if (tabId === undefined) return { success: false };

      const signal: ThreatSignal = payload;
      if (!signal || !signal.type) return { success: false };

      const settings = await StorageManager.getSettings();
      const currentState = await StorageManager.getTabState(tabId);
      const hostname = currentState?.hostname || sender.tab?.url || "unknown";
      const isAllowed = await StorageManager.isAllowlisted(hostname);

      if (!settings.protectionEnabled || isAllowed) {
        return { success: false };
      }

      const result = calculateRisk([...(currentState?.signals ?? []), signal]);
      if (currentState) {
        currentState.score = result.score;
        currentState.level = result.level;
        currentState.signals = result.signals;
        await StorageManager.setTabState(tabId, currentState);
      }

      const badgeText = result.score > 0 ? String(result.score) : "";
      try {
        await chrome.action.setBadgeText({ tabId, text: badgeText });
        await chrome.action.setBadgeBackgroundColor({
          tabId,
          color: BADGE_COLORS[result.level as RiskLevel] || BADGE_COLORS.LOW,
        });
      } catch {}

      await StorageManager.addThreatRecord({
        id: `threat-${Date.now()}-${Math.random().toString(36).substring(2, 7)}`,
        hostname,
        url: sender.tab?.url || "",
        timestamp: Date.now(),
        riskScore: result.score,
        riskLevel: result.level,
        signals: result.signals.map((s) => s.type),
        details: result.signals.map((s) => s.reason),
        action: "CLIPBOARD_INTERCEPTED",
      });

      return { success: true, score: result.score, level: result.level };
    }

    case "GET_TAB_STATE": {
      const tabId = payload?.tabId;
      if (typeof tabId !== "number") {
        return { state: null };
      }
      const state = await StorageManager.getTabState(tabId);
      return { state };
    }

    case "GET_SETTINGS": {
      const settings = await StorageManager.getSettings();
      return { settings };
    }

    case "UPDATE_SETTINGS": {
      const updated = await StorageManager.updateSettings(payload);
      return { settings: updated };
    }

    case "GET_STATISTICS": {
      const stats = await StorageManager.getStatistics();
      return { stats };
    }

    case "GET_THREAT_HISTORY": {
      const history = await StorageManager.getThreatHistory();
      return { history };
    }

    case "CLEAR_HISTORY": {
      await StorageManager.clearThreatHistory();
      return { success: true };
    }

    case "GET_ALLOWLIST": {
      const allowlist = await StorageManager.getAllowlist();
      return { allowlist };
    }

    case "ALLOWLIST_ADD": {
      const list = await StorageManager.addToAllowlist(payload?.hostname);
      return { allowlist: list };
    }

    case "ALLOWLIST_REMOVE": {
      const list = await StorageManager.removeFromAllowlist(payload?.hostname);
      return { allowlist: list };
    }

    default:
      return { error: "Unknown message type" };
  }
}

// Clean up tab state on tab close
chrome.tabs.onRemoved.addListener((tabId) => {
  StorageManager.clearTabState(tabId);
});

// Reset badge on navigation
chrome.webNavigation?.onCommitted?.addListener((details) => {
  if (details.frameId === 0) {
    chrome.action.setBadgeText({ tabId: details.tabId, text: "" }).catch(() => {});
  }
});

