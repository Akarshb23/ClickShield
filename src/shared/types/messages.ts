import type { ScanResult, ThreatSignal } from "./signal";
import type { ClickShieldSettings } from "./settings";
import type { ThreatRecord, SecurityStatistics } from "./threat";

export type MessageType =
  | "SCAN_RESULT"
  | "SUBFRAME_THREAT"
  | "INTERVENTION_SHOWN"
  | "GET_TAB_STATE"
  | "TAB_STATE_RESPONSE"
  | "GET_SETTINGS"
  | "SETTINGS_RESPONSE"
  | "UPDATE_SETTINGS"
  | "TRIGGER_RESCAN"
  | "GET_STATISTICS"
  | "GET_THREAT_HISTORY"
  | "CLEAR_HISTORY"
  | "ALLOWLIST_ADD"
  | "ALLOWLIST_REMOVE"
  | "GET_ALLOWLIST";

export interface ExtensionMessage<T = unknown> {
  type: MessageType;
  payload?: T;
}

export interface ScanResultMessage {
  type: "SCAN_RESULT";
  payload: ScanResult;
}

/** A signal reported by a genuine child frame to the background service worker. */
export interface SubframeThreatMessage {
  type: "SUBFRAME_THREAT";
  payload: ThreatSignal;
}

/** Confirms that the top-frame warning overlay was actually displayed. */
export interface InterventionShownMessage {
  type: "INTERVENTION_SHOWN";
  payload: {
    interventionId: string;
  };
}

export interface TabState {
  score: number;
  level: string;
  signals: ThreatSignal[];
  hostname: string;
  url: string;
  timestamp: number;
  protectionEnabled: boolean;
  isAllowlisted: boolean;
}
