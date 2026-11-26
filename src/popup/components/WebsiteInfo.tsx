import React from "react";
import { Globe, ShieldCheck } from "lucide-react";

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
  // Keep the popup resilient if values arrive from runtime messaging in an
  // unexpected shape despite the TypeScript interface.
  const displayedHostname =
    typeof hostname === "string" && hostname.trim().length > 0
      ? hostname.trim()
      : "No active webpage";

  const safeSignalCount =
    typeof signalCount === "number" && Number.isFinite(signalCount)
      ? Math.max(0, Math.floor(signalCount))
      : 0;

  const scannable = isScannable === true;
  const allowlisted = isAllowlisted === true;

  return (
    <div className="border-b border-[#222222] bg-[#0E0E0E] px-4 py-3">
      <div className="mb-1 flex items-center justify-between gap-2 text-xs text-neutral-400">
        <span className="font-mono text-[10px] uppercase tracking-wider text-neutral-500">
          Target Domain
        </span>

        {allowlisted && (
          <span
            className="flex shrink-0 items-center gap-1 font-mono text-[10px] text-[#E5B83B]"
            role="status"
          >
            <ShieldCheck className="h-3 w-3" aria-hidden="true" />
            ALLOWLISTED
          </span>
        )}
      </div>

      <div className="flex min-w-0 items-center gap-2">
        <Globe
          className="h-4 w-4 shrink-0 text-neutral-400"
          aria-hidden="true"
        />
        <span
          className="min-w-0 truncate font-mono text-xs font-medium text-neutral-200"
          title={displayedHostname}
        >
          {displayedHostname}
        </span>
      </div>

      {!scannable && (
        <div
          className="mt-2 rounded border border-[#262626] bg-[#161616] p-1.5 font-mono text-[10px] text-neutral-500"
          role="status"
        >
          Protected browser page. ClickShield monitoring is restricted by Chrome.
        </div>
      )}

      {scannable && (
        <div
          className="mt-2 flex items-center justify-between font-mono text-[11px]"
          aria-live="polite"
          aria-atomic="true"
        >
          <span className="text-neutral-400">Indicators detected:</span>
          <span
            className={`font-bold ${
              safeSignalCount > 0 ? "text-[#E5B83B]" : "text-[#16A34A]"
            }`}
          >
            {safeSignalCount} {safeSignalCount === 1 ? "signal" : "signals"}
          </span>
        </div>
      )}
    </div>
  );
};
