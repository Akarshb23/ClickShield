import { scanPage } from "./page-scanner";
import { calculateRisk } from "../engine/risk-engine";
import { ClipboardGuard } from "./clipboard-guard";
import { DynamicDomObserver } from "./dom-observer";
import { InteractionMonitor } from "./event-monitor";
import { InterventionManager } from "../protection/intervention-manager";
import { logger } from "../shared/utils/logger";
import type { ThreatSignal, ScanResult } from "../shared/types/signal";

let dynamicSignals: ThreatSignal[] = [];
let lastScore = -1;

function executeScan(forceNotify = false): ScanResult | null {
  try {
    const pageSignals = scanPage();
    const combinedSignals = [...pageSignals, ...dynamicSignals];

    const result: ScanResult = calculateRisk(combinedSignals, {
      hostname: window.location.hostname || "local-file",
      url: window.location.href,
    });

    // Check if intervention overlay should be displayed
    InterventionManager.evaluateAndIntervene(result);

    if (forceNotify || result.score !== lastScore || dynamicSignals.length > 0) {
      lastScore = result.score;
      chrome.runtime
        .sendMessage({
          type: "SCAN_RESULT",
          payload: result,
        })
        .catch(() => {});
    }

    return result;
  } catch (err) {
    logger.debug("Scan error or context invalidated:", err);
    return null;
  }
}

function handleDynamicThreat(signal: ThreatSignal) {
  const exists = dynamicSignals.some(
    (s) => s.type === signal.type && s.reason === signal.reason
  );
  if (!exists) {
    dynamicSignals.push(signal);
    executeScan(true);
  }
}

function initContentScript() {
  logger.info("Content script initialized on", window.location.hostname || window.location.href);

  // Initialize intervention system
  InterventionManager.initialize();

  // 1. Initial page scan
  executeScan(true);

  // 2. Initialize DOM Mutation Observer
  const domObserver = new DynamicDomObserver({
    onMutation: () => executeScan(false),
    debounceMs: 500,
  });

  const targetNode = document.body || document.documentElement;
  if (targetNode) {
    domObserver.start(targetNode);
  }

  if (document.readyState === "loading") {
    document.addEventListener("DOMContentLoaded", () => {
      executeScan(true);
      if (document.body) domObserver.start(document.body);
    });
  }

  // 3. Initialize Clipboard Guard
  ClipboardGuard.initialize({
    onThreatDetected: handleDynamicThreat,
  });

  // 4. Initialize User Interaction Monitor
  InteractionMonitor.initialize({
    onInteractionThreat: handleDynamicThreat,
  });

  // 5. Listen for manual rescan or live query triggers from popup
  chrome.runtime.onMessage.addListener((message, _sender, sendResponse) => {
    if (message.type === "TRIGGER_RESCAN" || message.type === "GET_LIVE_SCAN") {
      InterventionManager.resetSession();
      const result = executeScan(true);
      sendResponse({ status: "OK", result });
      return true;
    }
    return true;
  });
}

if (document.readyState === "loading") {
  document.addEventListener("DOMContentLoaded", initContentScript, { once: true });
} else {
  initContentScript();
}
