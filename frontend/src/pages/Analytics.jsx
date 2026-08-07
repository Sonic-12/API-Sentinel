import { ResponsiveContainer, BarChart, Bar, XAxis, YAxis, Tooltip, CartesianGrid, Cell } from "recharts";
import { useLiveData, api } from "../api";
import EmptyState from "../components/EmptyState";
import { BarChart3 } from "lucide-react";

const CATEGORY_COLOR = {
  BOLA: "var(--high)",
  Enumeration: "var(--medium)",
  "Rate Abuse": "var(--medium)",
  "Sensitive Path": "var(--brand)",
  BFLA: "var(--high)",
  "Missing Auth": "var(--medium)",
  "Invalid Method": "var(--text-muted)",
  Other: "var(--text-faint)",
};

export default function Analytics() {
  const { data: stats } = useLiveData(api.statistics, 3000);

  const breakdown = stats?.attack_breakdown || {};
  const chartData = Object.entries(breakdown).map(([name, count]) => ({ name, count }));
  const maxCount = Math.max(1, ...chartData.map((d) => d.count));

  return (
    <div className="stack">
      <div className="page-header">
        <p className="page-eyebrow">Behavioral Authorization AI</p>
        <h1 className="page-title">Analytics</h1>
        <p className="page-sub">Every category here comes from classifying the alert strings the engine actually raised.</p>
      </div>

      <div className="panel">
        <p className="panel-title">Attack Types</p>
        {chartData.length ? (
          <ResponsiveContainer width="100%" height={240}>
            <BarChart data={chartData}>
              <CartesianGrid stroke="var(--border-soft)" vertical={false} />
              <XAxis dataKey="name" tick={{ fill: "var(--text-faint)", fontSize: 11 }} axisLine={{ stroke: "var(--border)" }} tickLine={false} />
              <YAxis allowDecimals={false} tick={{ fill: "var(--text-faint)", fontSize: 11 }} axisLine={false} tickLine={false} width={24} />
              <Tooltip
                cursor={{ fill: "var(--bg-panel-alt)" }}
                contentStyle={{ background: "var(--bg-raised)", border: "1px solid var(--border)", borderRadius: 6, fontSize: 12 }}
              />
              <Bar dataKey="count" radius={[4, 4, 0, 0]}>
                {chartData.map((d) => (
                  <Cell key={d.name} fill={CATEGORY_COLOR[d.name] || "var(--brand)"} />
                ))}
              </Bar>
            </BarChart>
          </ResponsiveContainer>
        ) : (
          <EmptyState icon={BarChart3} message="No alerts have been raised yet, so there's nothing to break down." />
        )}
      </div>

      <div className="panel">
        <p className="panel-title">Risk Analytics</p>
        {chartData.length ? (
          <div className="stack" style={{ gap: 12 }}>
            {chartData
              .sort((a, b) => b.count - a.count)
              .map((d) => (
                <div key={d.name}>
                  <div style={{ display: "flex", justifyContent: "space-between", fontSize: 12.5, marginBottom: 4 }}>
                    <span>{d.name}</span>
                    <span className="mono muted">{d.count}</span>
                  </div>
                  <div style={{ background: "var(--bg-panel-alt)", borderRadius: 3, height: 6 }}>
                    <div
                      style={{
                        width: `${(d.count / maxCount) * 100}%`,
                        background: CATEGORY_COLOR[d.name] || "var(--brand)",
                        height: "100%",
                        borderRadius: 3,
                      }}
                    />
                  </div>
                </div>
              ))}
          </div>
        ) : (
          <EmptyState message="Nothing to rank yet." />
        )}
      </div>
    </div>
  );
}