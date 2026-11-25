import React from "react";
import {
  BarChart,
  Bar,
  XAxis,
  YAxis,
  Tooltip,
  ResponsiveContainer,
  Cell,
} from "recharts";
import type { ThreatRecord } from "../../shared/types/threat";

interface ThreatChartProps {
  threats: ThreatRecord[];
}

export const ThreatChart: React.FC<ThreatChartProps> = ({ threats }) => {
  // Aggregate signal frequencies
  const counts: Record<string, number> = {
    "Fake CAPTCHA": 0,
    "Execution Cmd": 0,
    "Suspicious Inst": 0,
    "Clipboard": 0,
    "Impersonation": 0,
    "Bad Domain": 0,
  };

  threats.forEach((t) => {
    t.signals.forEach((sig) => {
      if (sig === "FAKE_CAPTCHA") counts["Fake CAPTCHA"]++;
      else if (sig === "EXECUTION_INSTRUCTION") counts["Execution Cmd"]++;
      else if (sig === "SUSPICIOUS_INSTRUCTION") counts["Suspicious Inst"]++;
      else if (sig === "CLIPBOARD_MANIPULATION") counts["Clipboard"]++;
      else if (sig === "DOMAIN_IMPERSONATION") counts["Impersonation"]++;
      else if (sig === "SUSPICIOUS_DOMAIN") counts["Bad Domain"]++;
    });
  });

  const data = Object.entries(counts).map(([name, count]) => ({
    name,
    count,
  }));

  const COLORS = ["#DC2626", "#EA580C", "#D4A32C", "#E5B83B", "#3B82F6", "#8B5CF6"];

  return (
    <div className="w-full h-64 font-mono text-xs">
      <ResponsiveContainer width="100%" height="100%">
        <BarChart data={data} margin={{ top: 10, right: 10, left: -20, bottom: 20 }}>
          <XAxis
            dataKey="name"
            stroke="#666"
            tick={{ fill: "#888", fontSize: 11 }}
            angle={-15}
            textAnchor="end"
          />
          <YAxis stroke="#666" tick={{ fill: "#888", fontSize: 11 }} allowDecimals={false} />
          <Tooltip
            contentStyle={{
              backgroundColor: "#171717",
              borderColor: "#333",
              color: "#F5F5F5",
              borderRadius: "4px",
              fontFamily: "monospace",
            }}
          />
          <Bar dataKey="count" radius={[4, 4, 0, 0]}>
            {data.map((_, index) => (
              <Cell key={`cell-${index}`} fill={COLORS[index % COLORS.length]} />
            ))}
          </Bar>
        </BarChart>
      </ResponsiveContainer>
    </div>
  );
};

