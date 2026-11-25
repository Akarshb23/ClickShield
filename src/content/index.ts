import { scanPage } from "./page-scanner";
import { calculateRisk } from "../engine/risk-engine";
import { ClipboardGuard } from "./clipboard-guard";
import { DynamicDomObserver } from "./dom-observer";
import { InteractionMonitor } from "./event-monitor";
import { logger } from "../shared/utils/logger";
import type { ThreatSignal, ScanResult } from "../shared/types/signal";

let dynamicSignals: ThreatSignal[] = [];
let lastScore = -1;

function executeScan() {
  try {
    const pageSignals = scanPage();
    const combinedSignals = [...pageSignals, ...dynamicSignals];

    const result: ScanResult = calculateRisk(combinedSignals, {
      hostname: window.location.hostname,
      url: window.location.href,
    });

    if (result.score !== lastScore) {
      lastScore = result.score;
      chrome.runtime
        .sendMessage({
          type: "SCAN_RESULT",
          payload: result,
        })
        .catch(() => {});
    }
  } catch (err) {
    logger.debug("Scan error or context invalidated:", err);
  }
}

function handleDynamicThreat(signal: ThreatSignal) {
  // Add to dynamic signals if not already present
  const exists = dynamicSignals.some(
    (s) => s.type === signal.type && s.reason === signal.reason
  );
  if (!exists) {
    dynamicSignals.push(signal);
    executeScan();
  }
}

function initContentScript() {
  logger.info("Content script with behavioral guard initialized on", window.location.hostname);

  // 1. Initial page scan
  executeScan();

  // 2. Initialize DOM Mutation Observer
  const domObserver = new DynamicDomObserver({
    onMutation: executeScan,
    debounceMs: 500,
  });

  if (document.body) {
    domObserver.start(document.body);
  } else {
    document.addEventListener("DOMContentLoaded", () => {
      executeScan();
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

  // 5. Listen for manual rescan triggers from popup
  chrome.runtime.onMessage.addListener((message, _sender, sendResponse) => {
    if (message.type === "TRIGGER_RESCAN") {
      executeScan();
      sendResponse({ status: "SCANNING" });
    }
    return true;
  });
}

if (document.readyState === "loading") {
  document.addEventListener("DOMContentLoaded", initContentScript, { once: true });
} else {
  initContentScript();
}
