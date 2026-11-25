import React from "react";
import { Shield, ShieldAlert, ShieldCheck } from "lucide-react";

interface HeaderProps {
  protectionActive: boolean;
  onToggleProtection: () => void;
}

export const Header: React.FC<HeaderProps> = ({ protectionActive, onToggleProtection }) => {
  return (
    <div className="flex items-center justify-between border-b border-[#222222] px-4 py-3 bg-[#0D0D0D]">
      <div className="flex items-center gap-2.5">
        <div className="relative flex items-center justify-center w-8 h-8 rounded border border-[#E5B83B]/40 bg-[#171717]">
          <Shield className="w-4 h-4 text-[#E5B83B]" />
        </div>
        <div>
          <div className="text-xs font-bold tracking-widest text-[#E5B83B] uppercase">
            ClickShield
          </div>
          <div className="text-[10px] text-neutral-400 font-mono tracking-tight">
            BEHAVIORAL DEFENSE
          </div>
        </div>
      </div>

      <button
        onClick={onToggleProtection}
        className={`flex items-center gap-1.5 px-2.5 py-1 rounded text-[11px] font-mono border transition-all cursor-pointer ${
          protectionActive
            ? "border-[#16A34A]/50 bg-[#16A34A]/10 text-[#4ADE80]"
            : "border-[#DC2626]/50 bg-[#DC2626]/10 text-[#F87171]"
        }`}
        title="Toggle Real-Time Behavioral Guard"
      >
        <span
          className={`w-1.5 h-1.5 rounded-full ${
            protectionActive ? "bg-[#4ADE80] animate-pulse" : "bg-[#F87171]"
          }`}
        />
        {protectionActive ? "ACTIVE" : "DISABLED"}
      </button>
    </div>
  );
};

