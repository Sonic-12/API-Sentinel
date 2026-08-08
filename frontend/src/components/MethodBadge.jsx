const COLORS = {
  GET: "var(--get)",
  POST: "var(--post)",
  PUT: "var(--put)",
  PATCH: "var(--put)",
  DELETE: "var(--delete)",
};

export default function MethodBadge({ method }) {
  const color = COLORS[method] || "var(--text-muted)";
  return (
    <span className="badge badge-method" style={{ color }}>
      {method}
    </span>
  );
}