import { useLiveData, downloadCSV, downloadJSON, api } from "../api";
import MethodBadge from "../components/MethodBadge";
import EmptyState from "../components/EmptyState";
import { EyeOff, Download } from "lucide-react";

const BODY_FIELDS = ["username", "email", "password", "phone", "full_name"];

function LogCard({ log }) {
  const body = typeof log.body === "object" && log.body ? log.body : {};
  const rows = [
    ...BODY_FIELDS.filter((k) => body[k] !== undefined).map((k) => [k, body[k]]),
    ["Authorization", log.headers?.Authorization],
    ["Client IP", log.client_ip],
  ].filter(([, v]) => v !== undefined && v !== null && v !== "");

  return (
    <div className="panel">
      <div style={{ display: "flex", alignItems: "center", gap: 10, marginBottom: 10 }}>
        <MethodBadge method={log.method} />
        <span className="mono" style={{ fontSize: 13 }}>{log.path}</span>
        <span className="muted mono" style={{ fontSize: 11, marginLeft: "auto" }}>risk {log.risk_score}</span>
      </div>
      {rows.map(([key, value]) => (
        <div className="field-row" key={key}>
          <span className="field-key" style={{ textTransform: "capitalize" }}>{key}</span>
          <span className="field-val">{String(value)}</span>
        </div>
      ))}
      {!rows.length && <p className="muted" style={{ fontSize: 12.5, margin: 0 }}>No sensitive fields in this request.</p>}
    </div>
  );
}

const EXPORT_COLUMNS = [
  { key: "method", label: "Method" },
  { key: "path", label: "Path" },
  { key: "risk_score", label: "Risk" },
  { key: (l) => l.headers?.Authorization || "", label: "Authorization" },
  { key: "client_ip", label: "Client IP" },
  {
    key: (l) => (typeof l.body === "object" && l.body ? JSON.stringify(l.body) : ""),
    label: "Body",
  },
];

export default function MaskedLogs() {
  const { data: logs } = useLiveData(() => api.logs(30), 4000);

  function exportData(format) {
    if (!logs?.length) return;
    const stamp = new Date().toISOString().replace(/[:.]/g, "-");
    if (format === "csv") {
      downloadCSV(`masked-logs-${stamp}.csv`, logs, EXPORT_COLUMNS);
    } else {
      downloadJSON(`masked-logs-${stamp}.json`, logs);
    }
  }

  return (
    <div className="stack">
      <div className="page-header" style={{ display: "flex", alignItems: "flex-end", justifyContent: "space-between", gap: 16 }}>
        <div>
          <p className="page-eyebrow">masking</p>
          <h1 className="page-title">Masked Logs</h1>
          <p className="page-sub">Redacted logs for privacy and compliance.</p>
        </div>
        <div style={{ display: "flex", gap: 8, flexShrink: 0 }}>
          <button className="export-btn" onClick={() => exportData("csv")} disabled={!logs?.length}>
            <Download size={13} strokeWidth={2} /> CSV
          </button>
          <button className="export-btn" onClick={() => exportData("json")} disabled={!logs?.length}>
            <Download size={13} strokeWidth={2} /> JSON
          </button>
        </div>
      </div>

      {logs?.length ? (
        <div className="grid" style={{ gridTemplateColumns: "repeat(auto-fill, minmax(300px, 1fr))" }}>
          {logs.map((log, i) => (
            <LogCard log={log} key={i} />
          ))}
        </div>
      ) : (
        <div className="panel">
          <EmptyState icon={EyeOff} message="No logged requests yet — entries appear here once a request's risk score is greater than zero." />
        </div>
      )}
    </div>
  );
}