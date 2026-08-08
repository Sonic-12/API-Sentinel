import { ResponsiveContainer, LineChart, Line, XAxis, YAxis, Tooltip, CartesianGrid, PieChart, Pie, Cell } from "recharts";
import { useLiveData, api } from "../api";
import StatCard from "../components/StatCard";
import MethodBadge from "../components/MethodBadge";
import SeverityBadge from "../components/SeverityBadge";
import EmptyState from "../components/EmptyState";
import { ShieldAlert } from "lucide-react";

const RISK_COLORS = { Clean: "var(--clean)", Low: "var(--low)", Medium: "var(--medium)", High: "var(--high)" };

export default function Dashboard() {
  const { data: stats } = useLiveData(api.statistics, 3000);
  const { data: alerts } = useLiveData(() => api.alerts(6), 3000);

  const riskData = stats
    ? Object.entries(stats.risk_distribution)
        .filter(([, v]) => v > 0)
        .map(([name, value]) => ({ name, value }))
    : [];
  const riskTotal = riskData.reduce((sum, d) => sum + d.value, 0);

  return (
    <div className="stack">
      <div className="page-header">
        <p className="page-eyebrow">Overview</p>
        <h1 className="page-title">Dashboard</h1>
        <p className="page-sub">
          System's security posture and activity.
        </p>
      </div>

      <div className="grid grid-stats">
        <StatCard label="Total Requests" value={stats?.total_requests ?? "—"} accent="var(--brand)" />
        <StatCard label="Active Alerts" value={stats?.alerts_generated ?? "—"} accent="var(--medium)" />
        <StatCard label="Blocked Flows" value={stats?.blocked_flows ?? "—"} accent="var(--high)" />
        <StatCard label="Avg Risk" value={stats?.average_risk ?? "—"} accent="var(--low)" />
      </div>

      <div className="grid grid-2">
        <div className="panel">
          <p className="panel-title">Request Trend · Last 30 Min</p>
          <ResponsiveContainer width="100%" height={200}>
            <LineChart data={stats?.trend || []}>
              <CartesianGrid stroke="var(--border-soft)" vertical={false} />
              <XAxis dataKey="label" tick={{ fill: "var(--text-faint)", fontSize: 11 }} axisLine={{ stroke: "var(--border)" }} tickLine={false} />
              <YAxis allowDecimals={false} tick={{ fill: "var(--text-faint)", fontSize: 11 }} axisLine={false} tickLine={false} width={24} />
              <Tooltip contentStyle={{ background: "var(--bg-raised)", border: "1px solid var(--border)", borderRadius: 6, fontSize: 12 }} />
              <Line type="monotone" dataKey="count" stroke="var(--brand)" strokeWidth={2} dot={false} />
            </LineChart>
          </ResponsiveContainer>
        </div>

        <div className="panel">
          <p className="panel-title">Risk Distribution</p>
          {riskData.length ? (
            <div style={{ display: "flex", alignItems: "center", gap: 16 }}>
              <div style={{ position: "relative", width: 160, height: 200, flexShrink: 0 }}>
                <ResponsiveContainer width="100%" height={200}>
                  <PieChart>
                    <Pie
                      data={riskData}
                      dataKey="value"
                      nameKey="name"
                      innerRadius={45}
                      outerRadius={75}
                      paddingAngle={3}
                      label={({ value }) => `${Math.round((value / riskTotal) * 100)}%`}
                      labelLine={false}
                    >
                      {riskData.map((entry) => (
                        <Cell key={entry.name} fill={RISK_COLORS[entry.name]} stroke="var(--bg-panel)" />
                      ))}
                    </Pie>
                    <Tooltip
                      formatter={(value, name) => [`${value} (${Math.round((value / riskTotal) * 100)}%)`, name]}
                      contentStyle={{ background: "var(--bg-raised)", border: "1px solid var(--border)", borderRadius: 6, fontSize: 12 }}
                    />
                  </PieChart>
                </ResponsiveContainer>
                <div className="donut-center">
                  <span className="donut-total">{riskTotal}</span>
                  <span className="donut-label">requests</span>
                </div>
              </div>
              <div className="stack" style={{ gap: 8, flex: 1 }}>
                {riskData
                  .sort((a, b) => b.value - a.value)
                  .map((d) => (
                    <div key={d.name} style={{ display: "flex", alignItems: "center", gap: 8, fontSize: 12.5 }}>
                      <span
                        style={{
                          width: 8,
                          height: 8,
                          borderRadius: "50%",
                          background: RISK_COLORS[d.name],
                          flexShrink: 0,
                        }}
                      />
                      <span style={{ color: "var(--text-muted)", flex: 1 }}>{d.name}</span>
                      <span className="mono">{d.value}</span>
                      <span className="mono muted" style={{ width: 38, textAlign: "right" }}>
                        {Math.round((d.value / riskTotal) * 100)}%
                      </span>
                    </div>
                  ))}
              </div>
            </div>
          ) : (
            <EmptyState message="No traffic observed yet. Run the test harness to populate this chart." />
          )}
        </div>
      </div>

      <div className="panel">
        <p className="panel-title">Live Security Alerts</p>
        {alerts?.length ? (
          <div className="table-wrap">
            <table>
              <thead>
                <tr>
                  <th>Method</th>
                  <th>Path</th>
                  <th>Risk</th>
                  <th>Alerts</th>
                </tr>
              </thead>
              <tbody>
                {alerts.map((a, i) => (
                  <tr key={i}>
                    <td><MethodBadge method={a.method} /></td>
                    <td className="mono">{a.path_template}</td>
                    <td><SeverityBadge score={a.risk_score} /></td>
                    <td>
                      <ul className="alert-list">
                        {a.alerts.map((txt, j) => (
                          <li key={j}>{txt}</li>
                        ))}
                      </ul>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        ) : (
          <EmptyState icon={ShieldAlert} message="No alerts yet — traffic is clean, or the harness hasn't been run against this backend." />
        )}
      </div>
    </div>
  );
}