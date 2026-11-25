import React from "react";
import type { ThreatSignal } from "../../shared/types/signal";
import { AlertCircle, CheckCircle2, Terminal, Copy, ShieldAlert } from "lucide-react";

interface ThreatListProps {
  signals: ThreatSignal[];
}

export const ThreatList: React.FC<ThreatListProps> = ({ signals }) => {
  if (signals.length === 0) {
    return (
      <div className="p-4 text-center border-b border-[#222222] bg-[#0A0A0A]">
        <CheckCircle2 className="w-6 h-6 text-[#16A34A] mx-auto mb-1.5 opacity-80" />
        <p className="text-xs font-mono text-neutral-300">No ClickFix patterns detected</p>
        <p className="text-[10px] text-neutral-500 mt-0.5">
          Webpage content appears typical. Passive behavioral monitoring active.
        </p>
      </div>
    );
  }

  const getSignalIcon = (type: string) => {
    switch (type) {
      case "FAKE_CAPTCHA":
        return <ShieldAlert className="w-3.5 h-3.5 text-[#DC2626] shrink-0" />;
      case "EXECUTION_INSTRUCTION":
        return <Terminal className="w-3.5 h-3.5 text-[#EA580C] shrink-0" />;
      case "CLIPBOARD_MANIPULATION":
        return <Copy className="w-3.5 h-3.5 text-[#D4A32C] shrink-0" />;
      default:
        return <AlertCircle className="w-3.5 h-3.5 text-[#E5B83B] shrink-0" />;
    }
  };

  return (
    <div className="p-3 border-b border-[#222222] bg-[#0A0A0A] max-h-48 overflow-y-auto">
      <div className="text-[10px] font-mono tracking-wider uppercase text-neutral-500 mb-2">
        Detection Breakdown
      </div>
      <div className="space-y-2">
        {signals.map((signal, idx) => (
          <div
            key={idx}
            className="flex items-start gap-2 p-2 rounded bg-[#141414] border border-[#222222]"
          >
            {getSignalIcon(signal.type)}
            <div className="flex-1 min-w-0">
              <div className="flex items-center justify-between">
                <span className="text-[11px] font-mono font-semibold text-neutral-200">
                  {signal.type.replace(/_/g, " ")}
                </span>
                {signal.weight && (
                  <span className="text-[10px] font-mono text-[#E5B83B]">
                    +{signal.weight}
                  </span>
                )}
              </div>
              <p className="text-[10px] text-neutral-400 mt-0.5 leading-snug">
                {signal.reason}
              </p>
            </div>
          </div>
        ))}
      </div>
    </div>
  );
};

