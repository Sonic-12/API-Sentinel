import { useLiveData, api } from "../api";
import EmptyState from "../components/EmptyState";
import { ShieldCheck, CheckCircle2 } from "lucide-react";

const TOTAL_CATEGORIES = 10;

export default function Owasp() {
  const { data: coverage } = useLiveData(api.owasp, 4000);

  return (
    <div className="stack">
      <div className="page-header">
        <p className="page-eyebrow">OWASP API Security Top 10</p>
        <h1 className="page-title">Coverage</h1>
        <p className="page-sub">
          Live coverage of the OWASP API Security Top 10 categories, based on observed traffic and the official OpenAPI contract.
        </p>
      </div>

      <div className="panel">
        <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between", marginBottom: 18 }}>
          <p className="panel-title" style={{ margin: 0 }}>
            Categories Observed
          </p>
          <span className="mono" style={{ fontSize: 13, color: "var(--brand)" }}>
            {coverage?.length ?? 0} / {TOTAL_CATEGORIES}
          </span>
        </div>

        {coverage?.length ? (
          <div className="owasp-list">
            {coverage.map((item) => (
              <div className="owasp-row covered" key={item.id}>
                <CheckCircle2 className="owasp-icon" strokeWidth={2} />
                <span className="owasp-id mono">{item.id}</span>
                <span className="owasp-title">{item.title}</span>
                <span className="pill covered">Observed</span>
              </div>
            ))}
          </div>
        ) : (
          <EmptyState icon={ShieldCheck} message="No categories observed yet — run some traffic." />
        )}
      </div>
    </div>
  );
}