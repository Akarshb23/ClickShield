import React, { useEffect, useRef, useState } from "react";
import gsap from "gsap";
import type { RiskLevel } from "../../shared/types/signal";

interface RiskGaugeProps {
  score: number;
  level: RiskLevel;
}

interface RiskGaugeStyle {
  text: string;
  background: string;
  stroke: string;
  label: string;
}

function getRiskStyle(level: RiskLevel): RiskGaugeStyle {
  switch (level) {
    case "CRITICAL":
      return {
        text: "#DC2626",
        background: "bg-[#DC2626]",
        stroke: "#DC2626",
        label: "CRITICAL THREAT",
      };
    case "HIGH":
      return {
        text: "#EA580C",
        background: "bg-[#EA580C]",
        stroke: "#EA580C",
        label: "HIGH RISK",
      };
    case "SUSPICIOUS":
      return {
        text: "#D4A32C",
        background: "bg-[#D4A32C]",
        stroke: "#D4A32C",
        label: "SUSPICIOUS",
      };
    case "LOW":
    default:
      return {
        text: "#16A34A",
        background: "bg-[#16A34A]",
        stroke: "#16A34A",
        label: "PROTECTED",
      };
  }
}

export const RiskGauge: React.FC<RiskGaugeProps> = ({ score, level }) => {
  const [displayScore, setDisplayScore] = useState(0);
  const displayScoreRef = useRef(0);
  const circleRef = useRef<SVGCircleElement>(null);

  const safeScore = Number.isFinite(score)
    ? Math.round(Math.min(100, Math.max(0, score)))
    : 0;

  const config = getRiskStyle(level);
  const radius = 46;
  const circumference = 2 * Math.PI * radius;
  const strokeDashoffset = circumference - (safeScore / 100) * circumference;

  useEffect(() => {
    const counter = { value: displayScoreRef.current };
    const prefersReducedMotion = window.matchMedia(
      "(prefers-reduced-motion: reduce)"
    ).matches;

    if (prefersReducedMotion) {
      counter.value = safeScore;
      displayScoreRef.current = safeScore;
      setDisplayScore(safeScore);

      if (circleRef.current) {
        gsap.set(circleRef.current, { strokeDashoffset });
      }

      return;
    }

    const counterTween = gsap.to(counter, {
      value: safeScore,
      duration: 0.9,
      ease: "power2.out",
      overwrite: "auto",
      onUpdate: () => {
        displayScoreRef.current = counter.value;
        setDisplayScore(Math.round(counter.value));
      },
      onComplete: () => {
        displayScoreRef.current = safeScore;
        setDisplayScore(safeScore);
      },
    });

    const circleTween = circleRef.current
      ? gsap.to(circleRef.current, {
          strokeDashoffset,
          duration: 0.9,
          ease: "power2.out",
          overwrite: "auto",
        })
      : null;

    return () => {
      counterTween.kill();
      circleTween?.kill();
    };
  }, [safeScore, strokeDashoffset]);

  return (
    <div className="flex flex-col items-center justify-center border-b border-[#222222] bg-[#0E0E0E] px-4 py-4">
      <div
        className="relative flex h-28 w-28 items-center justify-center"
        role="progressbar"
        aria-label="Current page risk score"
        aria-valuemin={0}
        aria-valuemax={100}
        aria-valuenow={safeScore}
        aria-valuetext={`${safeScore} out of 100, ${config.label.toLowerCase()}`}
      >
        <svg
          className="h-full w-full -rotate-90 transform"
          viewBox="0 0 108 108"
          aria-hidden="true"
        >
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

        <div className="absolute inset-0 flex flex-col items-center justify-center" aria-hidden="true">
          <span
            className="font-mono text-3xl font-black tracking-tighter"
            style={{ color: config.text }}
          >
            {displayScore}
          </span>
          <span className="font-mono text-[10px] uppercase tracking-widest text-neutral-400">
            / 100
          </span>
        </div>
      </div>

      <div className="mt-3 flex items-center gap-1.5" aria-live="polite">
        <span
          className={`h-2 w-2 rounded-full ${config.background}`}
          aria-hidden="true"
        />
        <span
          className="font-mono text-xs font-bold tracking-wider"
          style={{ color: config.text }}
        >
          {config.label}
        </span>
      </div>
    </div>
  );
};
