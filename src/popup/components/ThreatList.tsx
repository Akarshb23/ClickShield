import React from "react";
import type { ThreatSignal, SignalType } from "../../shared/types/signal";
import {
  AlertCircle,
  CheckCircle2,
  Terminal,
  Copy,
  ShieldAlert,
} from "lucide-react";

interface ThreatListProps {
  signals: ThreatSignal[];
}

const VALID_SIGNAL_TYPES: readonly SignalType[] = [
  "FAKE_CAPTCHA",
  "SUSPICIOUS_INSTRUCTION",
  "CLIPBOARD_MANIPULATION",
  "EXECUTION_INSTRUCTION",
  "SUSPICIOUS_DOMAIN",
  "DOMAIN_IMPERSONATION",
];

function isThreatSignal(value: unknown): value is ThreatSignal {
  if (typeof value !== "object" || value === null || Array.isArray(value)) {
    return false;
  }

  const candidate = value as Record<string, unknown>;
  return (
    typeof candidate.type === "string" &&
    VALID_SIGNAL_TYPES.includes(candidate.type as SignalType)
  );
}

function getSignalIcon(type: SignalType) {
  const iconClass = "h-3.5 w-3.5 shrink-0";

  switch (type) {
    case "FAKE_CAPTCHA":
      return <ShieldAlert className={`${iconClass} text-[#DC2626]`} aria-hidden="true" />;
    case "EXECUTION_INSTRUCTION":
      return <Terminal className={`${iconClass} text-[#EA580C]`} aria-hidden="true" />;
    case "CLIPBOARD_MANIPULATION":
      return <Copy className={`${iconClass} text-[#D4A32C]`} aria-hidden="true" />;
    default:
      return <AlertCircle className={`${iconClass} text-[#E5B83B]`} aria-hidden="true" />;
  }
}

export const ThreatList: React.FC<ThreatListProps> = ({ signals }) => {
  const validSignals = Array.isArray(signals) ? signals.filter(isThreatSignal) : [];

  if (validSignals.length === 0) {
    return (
      <div
        className="border-b border-[#222222] bg-[#0A0A0A] p-4 text-center"
        role="status"
        aria-live="polite"
      >
        <CheckCircle2
          className="mx-auto mb-1.5 h-6 w-6 text-[#16A34A] opacity-80"
          aria-hidden="true"
        />
        <p className="font-mono text-xs text-neutral-300">
          No ClickFix patterns detected
        </p>
        <p className="mt-0.5 text-[10px] text-neutral-500">
          Webpage content appears typical. Passive behavioral monitoring active.
        </p>
      </div>
    );
  }

  return (
    <section
      className="max-h-48 overflow-y-auto border-b border-[#222222] bg-[#0A0A0A] p-3"
      aria-labelledby="threat-list-heading"
    >
      <h2
        id="threat-list-heading"
        className="mb-2 font-mono text-[10px] uppercase tracking-wider text-neutral-500"
      >
        Detection Breakdown
      </h2>

      <ul className="space-y-2">
        {validSignals.map((signal, index) => {
          const weight =
            typeof signal.weight === "number" && Number.isFinite(signal.weight)
              ? Math.max(0, Math.min(100, signal.weight))
              : null;
          const reason =
            typeof signal.reason === "string" && signal.reason.trim().length > 0
              ? signal.reason.slice(0, 500)
              : "No additional details available.";

          return (
            <li
              key={`${signal.type}-${index}`}
              className="flex items-start gap-2 rounded border border-[#222222] bg-[#141414] p-2"
            >
              {getSignalIcon(signal.type)}

              <div className="min-w-0 flex-1">
                <div className="flex items-start justify-between gap-2">
                  <span className="break-words font-mono text-[11px] font-semibold text-neutral-200">
                    {signal.type.replace(/_/g, " ")}
                  </span>

                  {weight !== null && (
                    <span className="shrink-0 font-mono text-[10px] text-[#E5B83B]">
                      +{weight}
                    </span>
                  )}
                </div>

                <p className="mt-0.5 break-words text-[10px] leading-snug text-neutral-400">
                  {reason}
                </p>
              </div>
            </li>
          );
        })}
      </ul>
    </section>
  );
};
