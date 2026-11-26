import React from "react";
import {
  RefreshCw,
  LayoutDashboard,
  ShieldCheck,
  ShieldBan,
} from "lucide-react";

interface QuickActionsProps {
  onRescan: () => void;
  onOpenDashboard: () => void;
  onToggleAllowlist: () => void;
  isAllowlisted: boolean;
  isScanning: boolean;
  canAllowlist: boolean;
}

export const QuickActions: React.FC<QuickActionsProps> = ({
  onRescan,
  onOpenDashboard,
  onToggleAllowlist,
  isAllowlisted,
  isScanning,
  canAllowlist,
}) => {
  return (
    <div className="space-y-2 border-b border-[#222222] bg-[#0D0D0D] p-3">
      <div className="grid grid-cols-2 gap-2">
        <button
          type="button"
          onClick={onRescan}
          disabled={isScanning}
          aria-busy={isScanning}
          className="flex cursor-pointer items-center justify-center gap-1.5 rounded border border-[#2D2D2D] bg-[#1C1C1C] px-3 py-2 text-xs font-mono font-medium text-neutral-200 transition-colors hover:bg-[#252525] focus-visible:ring-2 focus-visible:ring-[#E5B83B] focus-visible:ring-offset-2 focus-visible:ring-offset-[#0D0D0D] disabled:cursor-not-allowed disabled:opacity-50"
        >
          <RefreshCw
            aria-hidden="true"
            className={`h-3.5 w-3.5 shrink-0 ${
              isScanning ? "animate-spin text-[#E5B83B]" : ""
            }`}
          />
          <span aria-live="polite" aria-atomic="true">
            {isScanning ? "Scanning..." : "Rescan Page"}
          </span>
        </button>

        <button
          type="button"
          onClick={onOpenDashboard}
          className="flex cursor-pointer items-center justify-center gap-1.5 rounded border border-[#2D2D2D] bg-[#1C1C1C] px-3 py-2 text-xs font-mono font-medium text-neutral-200 transition-colors hover:bg-[#252525] focus-visible:ring-2 focus-visible:ring-[#E5B83B] focus-visible:ring-offset-2 focus-visible:ring-offset-[#0D0D0D]"
        >
          <LayoutDashboard
            aria-hidden="true"
            className="h-3.5 w-3.5 shrink-0 text-[#E5B83B]"
          />
          <span>Dashboard</span>
        </button>
      </div>

      {canAllowlist && (
        <button
          type="button"
          onClick={onToggleAllowlist}
          aria-pressed={isAllowlisted}
          aria-label={
            isAllowlisted
              ? "Remove this domain from the allowlist"
              : "Add this domain to the allowlist"
          }
          className="flex w-full cursor-pointer items-center justify-center gap-1.5 rounded border border-[#262626] bg-[#141414] px-3 py-1.5 text-[11px] font-mono text-neutral-400 transition-colors hover:bg-[#1C1C1C] hover:text-neutral-200 focus-visible:ring-2 focus-visible:ring-[#E5B83B] focus-visible:ring-offset-2 focus-visible:ring-offset-[#0D0D0D]"
        >
          {isAllowlisted ? (
            <>
              <ShieldBan
                aria-hidden="true"
                className="h-3.5 w-3.5 shrink-0 text-[#DC2626]"
              />
              <span>Remove from Allowlist</span>
            </>
          ) : (
            <>
              <ShieldCheck
                aria-hidden="true"
                className="h-3.5 w-3.5 shrink-0 text-[#E5B83B]"
              />
              <span>Allowlist this Domain</span>
            </>
          )}
        </button>
      )}
    </div>
  );
};
