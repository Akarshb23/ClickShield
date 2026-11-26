import React from "react";
import { Settings } from "lucide-react";

interface FooterProps {
  onOpenSettings: () => void;
}

export const Footer: React.FC<FooterProps> = ({ onOpenSettings }) => {
  return (
    <footer className="flex items-center justify-between px-4 py-2.5 bg-[#080808] text-[10px] font-mono text-neutral-500">
      <div className="flex items-center gap-1.5">
        <span
          aria-hidden="true"
          className="h-1.5 w-1.5 rounded-full bg-[#16A34A]"
        />
        <span>LOCAL-FIRST v0.1.0</span>
      </div>

      <button
        type="button"
        onClick={onOpenSettings}
        aria-label="Open ClickShield settings"
        className="flex items-center gap-1 rounded-sm text-neutral-400 transition-colors hover:text-[#E5B83B] focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-[#E5B83B] focus-visible:ring-offset-2 focus-visible:ring-offset-[#080808]"
      >
        <Settings aria-hidden="true" className="h-3 w-3" />
        <span>Settings</span>
      </button>
    </footer>
  );
};
