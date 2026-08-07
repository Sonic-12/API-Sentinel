import { useLiveData, api } from "../api";
import MethodBadge from "../components/MethodBadge";
import EmptyState from "../components/EmptyState";
import StatCard from "../components/StatCard";
import { Ghost } from "lucide-react";

function EndpointList({ items, empty, render }) {
  if (!items?.length) return <EmptyState message={empty} />;
  return (
    <ul className="alert-list" style={{ gap: 8 }}>
      {items.map((item, i) => (
        <li key={i} style={{ fontSize: 13 }}>
          {render(item)}
        </li>
      ))}
    </ul>
  );
}

export default function Discovery() {
  const { data } = useLiveData(api.discovery, 4000);

  return (
    <div className="stack">
      <div className="page-header">
        <p className="page-eyebrow">Shadow API Discovery Engine</p>
        <h1 className="page-title">Discovery</h1>
        <p className="page-sub">Straight from discovery_report.json — traffic compared against the official OpenAPI contract.</p>
      </div>

      <div className="grid grid-stats">
        <StatCard label="Observed APIs" value={data?.observed_endpoints?.length ?? "—"} accent="var(--brand)" />
        <StatCard label="Shadow APIs" value={data?.shadow_endpoints?.length ?? "—"} accent="var(--high)" />
        <StatCard label="Unseen Documented" value={data?.unseen_documented_endpoints?.length ?? "—"} accent="var(--medium)" />
        <StatCard label="Matched" value={data?.matched_count ?? "—"} accent="var(--low)" />
      </div>

      <div className="grid grid-2">
        <div className="panel">
          <p className="panel-title">Observed Endpoints</p>
          <EndpointList
            items={data?.observed_endpoints}
            empty="No traffic has been observed yet."
            render={(e) => (
              <span>
                <MethodBadge method={e.method} /> <span className="mono">{e.path_template}</span>{" "}
                <span className="muted mono" style={{ fontSize: 11 }}>
                  · {e.hit_count} hits
                </span>
              </span>
            )}
          />
        </div>

        <div className="panel">
          <p className="panel-title">Shadow APIs</p>
          <EndpointList
            items={data?.shadow_endpoints}
            empty="No undocumented endpoints detected — contract and traffic agree."
            render={(e) => (
              <span>
                <MethodBadge method={e.method} /> <span className="mono">{e.path}</span>
              </span>
            )}
          />
        </div>
      </div>

      <div className="panel">
        <p className="panel-title">Unseen Documented Endpoints</p>
        <p className="page-sub" style={{ marginTop: -4, marginBottom: 12 }}>
          Endpoints your OpenAPI spec promises that live traffic hasn't touched yet — dead documentation, or untested surface.
        </p>
        <EndpointList
          items={data?.unseen_documented_endpoints}
          empty="Every documented endpoint has been exercised by observed traffic."
          render={(e) => (
            <span>
              <MethodBadge method={e.method} /> <span className="mono">{e.path}</span>
            </span>
          )}
        />
      </div>

      {!data && (
        <EmptyState icon={Ghost} message="Waiting for the dashboard API..." />
      )}
    </div>
  );
}