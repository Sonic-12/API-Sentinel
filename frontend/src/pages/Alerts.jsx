import { useMemo, useState } from "react";
import { useLiveData, useAlertStream, downloadCSV, downloadJSON, api } from "../api";
import MethodBadge from "../components/MethodBadge";
import SeverityBadge from "../components/SeverityBadge";
import EmptyState from "../components/EmptyState";
import ToastStack from "../components/Toast";
import { Siren, Download, X } from "lucide-react";

function primaryModule(alerts) {
  const text = (alerts?.[0] || "").toLowerCase();
  if (text.includes("bola")) return "BOLA";
  if (text.includes("enumeration")) return "Enum";
  if (text.includes("rate abuse") || text.includes("bot")) return "RateLimit";
  if (text.includes("sensitive path")) return "Sensitive";
  if (text.includes("function level")) return "BFLA";
  if (text.includes("missing authorization")) return "Auth";
  return "General";
}

function severityLabel(score) {
  if (score <= 0) return "Clean";
  if (score <= 40) return "Low";
  if (score <= 80) return "Medium";
  return "High";
}

const MODULES = ["BOLA", "Enum", "RateLimit", "Sensitive", "BFLA", "Auth", "General"];
const SEVERITIES = ["High", "Medium", "Low", "Clean"];

const EXPORT_COLUMNS = [
  { key: (a) => new Date(a.timestamp * 1000).toISOString(), label: "Time" },
  { key: "risk_score", label: "Risk" },
  { key: (a) => severityLabel(a.risk_score), label: "Severity" },
  { key: (a) => primaryModule(a.alerts), label: "Module" },
  { key: "method", label: "Method" },
  { key: "path_template", label: "Path" },
  { key: (a) => a.identity || "anon", label: "Identity" },
  { key: (a) => (a.alerts || []).join(" | "), label: "Alerts" },
];

export default function Alerts() {
  const { data: alerts } = useLiveData(() => api.alerts(150), 3000);

  const [severity, setSeverity] = useState("");
  const [module, setModule] = useState("");
  const [identityQuery, setIdentityQuery] = useState("");
  const [toasts, setToasts] = useState([]);

  useAlertStream((entry) => {
    if (!entry?.alerts?.length) return;
    if (severityLabel(entry.risk_score) !== "High") return;
    setToasts((prev) => [
      ...prev,
      {
        id: `${entry.timestamp}-${Math.random().toString(36).slice(2, 7)}`,
        title: `${entry.method} ${entry.path_template} — risk ${entry.risk_score}`,
        body: entry.alerts[0],
      },
    ]);
  });

  const filtered = useMemo(() => {
    if (!alerts) return alerts;
    return alerts.filter((a) => {
      if (severity && severityLabel(a.risk_score) !== severity) return false;
      if (module && primaryModule(a.alerts) !== module) return false;
      if (identityQuery && !(a.identity || "anon").toLowerCase().includes(identityQuery.toLowerCase())) {
        return false;
      }
      return true;
    });
  }, [alerts, severity, module, identityQuery]);

  const hasFilters = severity || module || identityQuery;

  function clearFilters() {
    setSeverity("");
    setModule("");
    setIdentityQuery("");
  }

  function exportData(format) {
    if (!filtered?.length) return;
    const stamp = new Date().toISOString().replace(/[:.]/g, "-");
    if (format === "csv") {
      downloadCSV(`alerts-${stamp}.csv`, filtered, EXPORT_COLUMNS);
    } else {
      downloadJSON(`alerts-${stamp}.json`, filtered);
    }
  }

  return (
    <div className="stack">
      <ToastStack toasts={toasts} onDismiss={(id) => setToasts((prev) => prev.filter((t) => t.id !== id))} />

      <div className="page-header">
        <p className="page-eyebrow">Live Feed</p>
        <h1 className="page-title">Alerts</h1>
        <p className="page-sub">Real-time alerts and notifications</p>
      </div>

      <div className="panel">
        <div className="filter-bar">
          <select className="filter-select" value={severity} onChange={(e) => setSeverity(e.target.value)}>
            <option value="">All severities</option>
            {SEVERITIES.map((s) => (
              <option key={s} value={s}>
                {s}
              </option>
            ))}
          </select>

          <select className="filter-select" value={module} onChange={(e) => setModule(e.target.value)}>
            <option value="">All modules</option>
            {MODULES.map((m) => (
              <option key={m} value={m}>
                {m}
              </option>
            ))}
          </select>

          <input
            className="filter-input"
            placeholder="Filter by identity..."
            value={identityQuery}
            onChange={(e) => setIdentityQuery(e.target.value)}
          />

          {hasFilters && (
            <button className="filter-clear" onClick={clearFilters}>
              <X size={13} strokeWidth={2} /> Clear
            </button>
          )}

          <div style={{ marginLeft: "auto", display: "flex", gap: 8 }}>
            <button className="export-btn" onClick={() => exportData("csv")} disabled={!filtered?.length}>
              <Download size={13} strokeWidth={2} /> CSV
            </button>
            <button className="export-btn" onClick={() => exportData("json")} disabled={!filtered?.length}>
              <Download size={13} strokeWidth={2} /> JSON
            </button>
          </div>
        </div>

        {alerts === null ? null : filtered.length ? (
          <div className="table-wrap">
            <table>
              <thead>
                <tr>
                  <th>Time</th>
                  <th>Severity</th>
                  <th>Module</th>
                  <th>Method</th>
                  <th>Path</th>
                  <th>Identity</th>
                  <th>Alert</th>
                </tr>
              </thead>
              <tbody>
                {filtered.map((a, i) => (
                  <tr key={i}>
                    <td className="mono muted">{new Date(a.timestamp * 1000).toLocaleTimeString()}</td>
                    <td><SeverityBadge score={a.risk_score} /></td>
                    <td className="mono">{primaryModule(a.alerts)}</td>
                    <td><MethodBadge method={a.method} /></td>
                    <td className="mono">{a.path_template}</td>
                    <td>
                      <button
                        className="identity-link mono"
                        onClick={() => setIdentityQuery(a.identity || "anon")}
                        title="Filter to this identity"
                      >
                        {a.identity || "anon"}
                      </button>
                    </td>
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
        ) : hasFilters ? (
          <EmptyState message="No alerts match the current filters." />
        ) : (
          <EmptyState icon={Siren} message="No alerts raised yet. Traffic is either clean or hasn't hit this backend." />
        )}
      </div>
    </div>
  );
}
