const SETTINGS = [
  { label: "Block Threshold", value: "60", unit: "risk score", desc: "Flows at or above this score get dropped by the eBPF enforcer." },
  { label: "Rate Limit Window", value: "10", unit: "seconds", desc: "Sliding window the rate limiter counts requests in." },
  { label: "Rate Limit Max Requests", value: "8", unit: "requests", desc: "Requests allowed per window before rate-abuse risk kicks in." },
  { label: "BOLA Unique Threshold", value: "3", unit: "foreign objects", desc: "Distinct non-owned object IDs before a BOLA alert fires." },
  { label: "BOLA Tracking Window", value: "20", unit: "object IDs", desc: "How many recent object IDs are remembered per identity." },
  { label: "Identity TTL", value: "900", unit: "seconds", desc: "How long an idle identity's history is kept before eviction." },
];

export default function Settings() {
  return (
    <div className="stack">
      <div className="page-header">
        <p className="page-eyebrow">Configuration</p>
        <h1 className="page-title">Settings</h1>
        <p className="page-sub">Current engine thresholds.(Read-only)</p>
      </div>

      <div className="panel">
        <p className="panel-title">Detection Thresholds</p>
        {SETTINGS.map((s) => (
          <div className="setting-row" key={s.label}>
            <div>
              <div className="setting-label">{s.label}</div>
              <div className="setting-desc">{s.desc}</div>
            </div>
            <div style={{ textAlign: "right" }}>
              <input className="setting-input" value={s.value} disabled readOnly />
              <div className="locked-note">{s.unit} · locked</div>
            </div>
          </div>
        ))}
      </div>
    </div>
  );
}