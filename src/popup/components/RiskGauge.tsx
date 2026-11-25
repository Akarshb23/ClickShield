import React from "react";
import type { RiskLevel } from "../../shared/types/signal";

interface RiskGaugeProps {
  score: number;
  level: RiskLevel;
}

export const RiskGauge: React.FC<RiskGaugeProps> = ({ score, level }) => {
  const getColor = () => {
    switch (level) {
      case "CRITICAL":
        return { text: "text-[#DC2626]", bg: "bg-[#DC2626]", border: "border-[#DC2626]", label: "CRITICAL THREAT" };
      case "HIGH":
        return { text: "text-[#EA580C]", bg: "bg-[#EA580C]", border: "border-[#EA580C]", label: "HIGH RISK" };
      case "SUSPICIOUS":
        return { text: "text-[#D4A32C]", bg: "bg-[#D4A32C]", border: "border-[#D4A32C]", label: "SUSPICIOUS" };
      default:
        return { text: "text-[#16A34A]", bg: "bg-[#16A34A]", border: "border-[#16A34A]", label: "SECURE" };
    }
  };

  const config = getColor();

  return (
    <div className="flex flex-col items-center justify-center py-4 px-4 bg-[#121212] border-b border-[#222222]">
      <div className="relative flex items-center justify-center w-28 h-28 rounded-full border-4 border-[#1E1E1E]">
        {/* Dynamic score ring indicator */}
        <div
          className={`absolute inset-0 rounded-full border-4 ${config.border} transition-all duration-700 opacity-90`}
          style={{
            clipPath: `polygon(50% 50%, -50% -50%, ${score * 2}% -50%, ${score * 2}% 150%, -50% 150%)`,
          }}
        />
        <div className="flex flex-col items-center justify-center">
          <span className={`text-3xl font-black font-mono tracking-tighter ${config.text}`}>
            {score}
          </span>
          <span className="text-[10px] text-neutral-400 font-mono tracking-widest uppercase">
            / 100
          </span>
        </div>
      </div>

      <div className="mt-3 flex items-center gap-1.5">
        <span className={`w-2 h-2 rounded-full ${config.bg}`} />
        <span className={`text-xs font-bold tracking-wider font-mono ${config.text}`}>
          {config.label}
        </span>
      </div>
    </div>
  );
};

