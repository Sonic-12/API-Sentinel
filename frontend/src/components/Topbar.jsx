import { useLiveData, api } from "../api";
import PulseLine from "./PulseLine";

function statusFromStats(stats) {
  if (!stats) return { tone: "", label: "Connecting..." };
  if (stats.blocked_flows > 0) return { tone: "danger", label: "Active enforcement" };
  if (stats.alerts_generated > 0) return { tone: "warn", label: "Alerts present" };
  return { tone: "", label: "System healthy" };
}

export default function Topbar() {
  const { data: stats, error } = useLiveData(api.statistics, 3000);
  const status = error ? { tone: "danger", label: "API unreachable" } : statusFromStats(stats);

  return (
    <header className="topbar">
      <span className="topbar-title">Runtime BOLA &amp; Shadow API Detection</span>
      <PulseLine trend={stats?.trend} color={status.tone === "danger" ? "var(--high)" : "var(--brand)"} />
      <div className="topbar-status">
        <span className={`status-dot ${status.tone}`} />
        {status.label}
      </div>
    </header>
  );
}