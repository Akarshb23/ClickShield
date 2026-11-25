import React from "react";
import { RefreshCw, LayoutDashboard, ShieldCheck, ShieldBan } from "lucide-react";

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
    <div className="p-3 bg-[#0D0D0D] border-b border-[#222222] space-y-2">
      <div className="grid grid-cols-2 gap-2">
        <button
          onClick={onRescan}
          disabled={isScanning}
          className="flex items-center justify-center gap-1.5 py-2 px-3 rounded bg-[#1C1C1C] hover:bg-[#252525] border border-[#2D2D2D] text-xs font-mono font-medium text-neutral-200 transition-colors cursor-pointer disabled:opacity-50"
        >
          <RefreshCw className={`w-3.5 h-3.5 ${isScanning ? "animate-spin text-[#E5B83B]" : ""}`} />
          {isScanning ? "Scanning..." : "Rescan Page"}
        </button>

        <button
          onClick={onOpenDashboard}
          className="flex items-center justify-center gap-1.5 py-2 px-3 rounded bg-[#1C1C1C] hover:bg-[#252525] border border-[#2D2D2D] text-xs font-mono font-medium text-neutral-200 transition-colors cursor-pointer"
        >
          <LayoutDashboard className="w-3.5 h-3.5 text-[#E5B83B]" />
          Dashboard
        </button>
      </div>

      {canAllowlist && (
        <button
          onClick={onToggleAllowlist}
          className="w-full flex items-center justify-center gap-1.5 py-1.5 px-3 rounded bg-[#141414] hover:bg-[#1C1C1C] border border-[#262626] text-[11px] font-mono text-neutral-400 hover:text-neutral-200 transition-colors cursor-pointer"
        >
          {isAllowlisted ? (
            <>
              <ShieldBan className="w-3.5 h-3.5 text-[#DC2626]" /> Remove from Allowlist
            </>
          ) : (
            <>
              <ShieldCheck className="w-3.5 h-3.5 text-[#E5B83B]" /> Allowlist this Domain
            </>
          )}
        </button>
      )}
    </div>
  );
};

