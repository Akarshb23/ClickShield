import React from "react";
import { Shield } from "lucide-react";

interface HeaderProps {
  protectionActive: boolean;
  onToggleProtection: () => void;
}

export const Header: React.FC<HeaderProps> = ({
  protectionActive,
  onToggleProtection,
}) => {
  const nextAction = protectionActive ? "off" : "on";

  return (
    <header className="flex items-center justify-between border-b border-[#222222] bg-[#0D0D0D] px-4 py-3">
      <div className="flex items-center gap-2.5">
        <div
          aria-hidden="true"
          className="relative flex h-8 w-8 items-center justify-center rounded border border-[#E5B83B]/40 bg-[#171717]"
        >
          <Shield className="h-4 w-4 text-[#E5B83B]" />
        </div>

        <div>
          <div className="text-xs font-bold uppercase tracking-widest text-[#E5B83B]">
            ClickShield
          </div>
          <div className="font-mono text-[10px] tracking-tight text-neutral-400">
            BEHAVIORAL DEFENSE
          </div>
        </div>
      </div>

      <button
        type="button"
        onClick={onToggleProtection}
        aria-pressed={protectionActive}
        aria-label={`Turn real-time behavioral protection ${nextAction}`}
        title={`Turn real-time behavioral protection ${nextAction}`}
        className={`flex cursor-pointer items-center gap-1.5 rounded border px-2.5 py-1 font-mono text-[11px] transition-colors focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-[#E5B83B] focus-visible:ring-offset-2 focus-visible:ring-offset-[#0D0D0D] ${
          protectionActive
            ? "border-[#16A34A]/50 bg-[#16A34A]/10 text-[#4ADE80]"
            : "border-[#DC2626]/50 bg-[#DC2626]/10 text-[#F87171]"
        }`}
      >
        <span
          aria-hidden="true"
          className={`h-1.5 w-1.5 rounded-full ${
            protectionActive ? "animate-pulse bg-[#4ADE80]" : "bg-[#F87171]"
          }`}
        />
        <span aria-live="polite" aria-atomic="true">
          {protectionActive ? "ACTIVE" : "DISABLED"}
        </span>
      </button>
    </header>
  );
};
