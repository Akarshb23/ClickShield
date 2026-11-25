import React, { useEffect, useRef, useState } from "react";
import gsap from "gsap";
import type { RiskLevel } from "../../shared/types/signal";

interface RiskGaugeProps {
  score: number;
  level: RiskLevel;
}

export const RiskGauge: React.FC<RiskGaugeProps> = ({ score, level }) => {
  const [displayScore, setDisplayScore] = useState(0);
  const scoreRef = useRef<HTMLSpanElement>(null);
  const circleRef = useRef<SVGCircleElement>(null);

  const getColor = () => {
    switch (level) {
      case "CRITICAL":
        return { text: "#DC2626", bg: "bg-[#DC2626]", stroke: "#DC2626", label: "CRITICAL THREAT" };
      case "HIGH":
        return { text: "#EA580C", bg: "bg-[#EA580C]", stroke: "#EA580C", label: "HIGH RISK" };
      case "SUSPICIOUS":
        return { text: "#D4A32C", bg: "bg-[#D4A32C]", stroke: "#D4A32C", label: "SUSPICIOUS" };
      default:
        return { text: "#16A34A", bg: "bg-[#16A34A]", stroke: "#16A34A", label: "PROTECTED" };
    }
  };

  const config = getColor();
  const radius = 46;
  const circumference = 2 * Math.PI * radius;
  // Offset mapping: 0 score = full offset, 100 score = 0 offset
  const strokeDashoffset = circumference - (score / 100) * circumference;

  useEffect(() => {
    // Animate score counter smoothly using GSAP
    const counterObj = { val: displayScore };
    gsap.to(counterObj, {
      val: score,
      duration: 0.9,
      ease: "power2.out",
      onUpdate: () => {
        setDisplayScore(Math.round(counterObj.val));
      },
    });

    // Animate radial stroke offset
    if (circleRef.current) {
      gsap.to(circleRef.current, {
        strokeDashoffset: strokeDashoffset,
        duration: 0.9,
        ease: "power2.out",
      });
    }
  }, [score, strokeDashoffset]);

  return (
    <div className="flex flex-col items-center justify-center py-4 px-4 bg-[#0E0E0E] border-b border-[#222222]">
      <div className="relative flex items-center justify-center w-28 h-28">
        <svg className="w-full h-full -rotate-90 transform" viewBox="0 0 108 108">
          {/* Background track */}
          <circle
            cx="54"
            cy="54"
            r={radius}
            stroke="#1C1C1C"
            strokeWidth="7"
            fill="transparent"
          />
          {/* Animated active stroke */}
          <circle
            ref={circleRef}
            cx="54"
            cy="54"
            r={radius}
            stroke={config.stroke}
            strokeWidth="7"
            strokeDasharray={circumference}
            strokeDashoffset={circumference}
            strokeLinecap="round"
            fill="transparent"
          />
        </svg>

        <div className="absolute inset-0 flex flex-col items-center justify-center">
          <span
            ref={scoreRef}
            className="text-3xl font-black font-mono tracking-tighter"
            style={{ color: config.text }}
          >
            {displayScore}
          </span>
          <span className="text-[10px] text-neutral-400 font-mono tracking-widest uppercase">
            / 100
          </span>
        </div>
      </div>

      <div className="mt-3 flex items-center gap-1.5">
        <span className={`w-2 h-2 rounded-full ${config.bg}`} />
        <span
          className="text-xs font-bold tracking-wider font-mono"
          style={{ color: config.text }}
        >
          {config.label}
        </span>
      </div>
    </div>
  );
};
