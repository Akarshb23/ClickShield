import React from "react";
import { Settings, ExternalLink } from "lucide-react";

interface FooterProps {
  onOpenSettings: () => void;
}

export const Footer: React.FC<FooterProps> = ({ onOpenSettings }) => {
  return (
    <div className="flex items-center justify-between px-4 py-2.5 bg-[#080808] text-[10px] font-mono text-neutral-500">
      <div className="flex items-center gap-1.5">
        <span className="w-1.5 h-1.5 rounded-full bg-[#16A34A]" />
        <span>LOCAL-FIRST v0.1.0</span>
      </div>

      <button
        onClick={onOpenSettings}
        className="flex items-center gap-1 text-neutral-400 hover:text-[#E5B83B] transition-colors cursor-pointer"
      >
        <Settings className="w-3 h-3" />
        Settings
      </button>
    </div>
  );
};

