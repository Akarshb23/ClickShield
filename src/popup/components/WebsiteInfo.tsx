import React from "react";
import { Globe, Lock, AlertTriangle, ShieldCheck } from "lucide-react";

interface WebsiteInfoProps {
  hostname: string;
  isScannable: boolean;
  isAllowlisted: boolean;
  signalCount: number;
}

export const WebsiteInfo: React.FC<WebsiteInfoProps> = ({
  hostname,
  isScannable,
  isAllowlisted,
  signalCount,
}) => {
  return (
    <div className="px-4 py-3 border-b border-[#222222] bg-[#0E0E0E]">
      <div className="flex items-center justify-between text-xs text-neutral-400 mb-1">
        <span className="font-mono text-[10px] tracking-wider uppercase text-neutral-500">
          Target Domain
        </span>
        {isAllowlisted && (
          <span className="flex items-center gap-1 text-[10px] text-[#E5B83B] font-mono">
            <ShieldCheck className="w-3 h-3" /> ALLOWLISTED
          </span>
        )}
      </div>

      <div className="flex items-center gap-2">
        <Globe className="w-4 h-4 text-neutral-400 shrink-0" />
        <span
          className="text-xs font-mono font-medium text-neutral-200 truncate"
          title={hostname}
        >
          {hostname || "No active webpage"}
        </span>
      </div>

      {!isScannable && (
        <div className="mt-2 text-[10px] font-mono text-neutral-500 bg-[#161616] p-1.5 rounded border border-[#262626]">
          Protected browser page. ClickShield monitoring is restricted by Chrome.
        </div>
      )}

      {isScannable && (
        <div className="mt-2 flex items-center justify-between text-[11px] font-mono">
          <span className="text-neutral-400">Indicators detected:</span>
          <span
            className={`font-bold ${
              signalCount > 0 ? "text-[#E5B83B]" : "text-[#16A34A]"
            }`}
          >
            {signalCount} {signalCount === 1 ? "signal" : "signals"}
          </span>
        </div>
      )}
    </div>
  );
};

