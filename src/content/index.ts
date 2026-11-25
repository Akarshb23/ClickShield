import { scanPage } from "./page-scanner";
import { calculateRisk } from "../engine/risk-engine";
import { logger } from "../shared/utils/logger";
import type { ScanResult } from "../shared/types/signal";

let debounceTimer: ReturnType<typeof setTimeout> | null = null;
let lastScore = -1;

function executeScan() {
  try {
    const signals = scanPage();
    const result: ScanResult = calculateRisk(signals, {
      hostname: window.location.hostname,
      url: window.location.href,
    });

    // Only broadcast if the score changed or this is the initial scan
    if (result.score !== lastScore) {
      lastScore = result.score;
      chrome.runtime
        .sendMessage({
          type: "SCAN_RESULT",
          payload: result,
        })
        .catch(() => {
          // Extension context might be invalidated during updates/reloads
        });
    }
  } catch (err) {
    logger.debug("Scan error or context invalidated:", err);
  }
}

function initContentScript() {
  logger.info("Content script initialized on", window.location.hostname);
  executeScan();

  // Observe dynamic DOM changes (ClickFix attacks frequently inject prompts after user clicks)
  const observer = new MutationObserver((mutations) => {
    // Ignore changes within ClickShield elements
    const isInternal = mutations.some((m) =>
      Array.from(m.addedNodes).some(
        (n) => n instanceof HTMLElement && n.hasAttribute("data-clickshield-ignore")
      )
    );
    if (isInternal) return;

    if (debounceTimer) clearTimeout(debounceTimer);
    debounceTimer = setTimeout(executeScan, 600);
  });

  if (document.body) {
    observer.observe(document.body, {
      childList: true,
      subtree: true,
      characterData: true,
    });
  } else {
    document.addEventListener("DOMContentLoaded", () => {
      executeScan();
      if (document.body) {
        observer.observe(document.body, {
          childList: true,
          subtree: true,
          characterData: true,
        });
      }
    });
  }

  // Listen for manual rescan or status queries from popup
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

