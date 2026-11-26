import React, { useMemo } from "react";
import {
  BarChart,
  Bar,
  XAxis,
  YAxis,
  Tooltip,
  ResponsiveContainer,
  CartesianGrid,
  Cell,
} from "recharts";
import type { ThreatRecord } from "../../shared/types/threat";

interface ThreatChartProps {
  threats: ThreatRecord[];
}

const SIGNAL_CATEGORIES = [
  {
    name: "Fake CAPTCHA",
    color: "#DC2626",
  },
  {
    name: "Execution Cmd",
    color: "#EA580C",
  },
  {
    name: "Suspicious Inst",
    color: "#D4A32C",
  },
  {
    name: "Clipboard",
    color: "#E5B83B",
  },
  {
    name: "Impersonation",
    color: "#3B82F6",
  },
  {
    name: "Bad Domain",
    color: "#8B5CF6",
  },
] as const;

const SIGNAL_LABELS: Record<string, string> = {
  FAKE_CAPTCHA: "Fake CAPTCHA",
  EXECUTION_INSTRUCTION: "Execution Cmd",
  SUSPICIOUS_INSTRUCTION: "Suspicious Inst",
  CLIPBOARD_MANIPULATION: "Clipboard",
  DOMAIN_IMPERSONATION: "Impersonation",
  SUSPICIOUS_DOMAIN: "Bad Domain",
};

export const ThreatChart: React.FC<ThreatChartProps> = ({ threats }) => {
  const data = useMemo(() => {
    const counts = new Map<string, number>(
      SIGNAL_CATEGORIES.map(({ name }) => [name, 0])
    );

    for (const threat of threats) {
      for (const signal of threat.signals ?? []) {
        const category = SIGNAL_LABELS[signal];

        // Ignore signal types that this chart does not currently visualize.
        if (category) {
          counts.set(category, (counts.get(category) ?? 0) + 1);
        }
      }
    }

    return SIGNAL_CATEGORIES.map(({ name, color }) => ({
      name,
      count: counts.get(name) ?? 0,
      color,
    }));
  }, [threats]);

  const totalSignals = data.reduce((total, item) => total + item.count, 0);

  if (totalSignals === 0) {
    return (
      <div
        className="w-full h-64 flex items-center justify-center rounded border border-dashed border-[#262626] bg-[#0D0D0D] font-mono text-xs text-neutral-500"
        role="status"
      >
        No recognized threat signals recorded yet.
      </div>
    );
  }

  return (
    <div
      className="w-full h-72 font-mono text-xs"
      role="img"
      aria-label={`Threat signal distribution. ${data
        .filter((item) => item.count > 0)
        .map((item) => `${item.name}: ${item.count}`)
        .join(", ")}`}
    >
      <ResponsiveContainer width="100%" height="100%">
        <BarChart
          data={data}
          margin={{ top: 12, right: 12, left: -16, bottom: 34 }}
          barCategoryGap="22%"
        >
          <CartesianGrid
            stroke="#292929"
            strokeDasharray="3 3"
            vertical={false}
          />

          <XAxis
            dataKey="name"
            axisLine={{ stroke: "#444444" }}
            tickLine={false}
            tick={{ fill: "#A3A3A3", fontSize: 10 }}
            angle={-18}
            textAnchor="end"
            interval={0}
            height={48}
          />

          <YAxis
            axisLine={false}
            tickLine={false}
            stroke="#666666"
            tick={{ fill: "#888888", fontSize: 11 }}
            allowDecimals={false}
            domain={[0, "dataMax"]}
            width={34}
          />

          <Tooltip
            cursor={{ fill: "#FFFFFF", fillOpacity: 0.04 }}
            contentStyle={{
              backgroundColor: "#171717",
              borderColor: "#333333",
              color: "#F5F5F5",
              borderRadius: "4px",
              fontFamily: "monospace",
              fontSize: "11px",
            }}
            labelStyle={{ color: "#E5B83B", marginBottom: "4px" }}
            itemStyle={{ color: "#F5F5F5" }}
            formatter={(value) => [value, "Occurrences"]}
          />

          <Bar dataKey="count" name="Occurrences" radius={[4, 4, 0, 0]}>
            {data.map((item) => (
              <Cell key={item.name} fill={item.color} />
            ))}
          </Bar>
        </BarChart>
      </ResponsiveContainer>
    </div>
  );
};
