function bucket(score) {
  if (score <= 0) return { label: "Clean", color: "var(--clean)" };
  if (score <= 40) return { label: "Low", color: "var(--low)" };
  if (score <= 80) return { label: "Medium", color: "var(--medium)" };
  return { label: "High", color: "var(--high)" };
}

export default function SeverityBadge({ score }) {
  const { label, color } = bucket(score);
  return (
    <span className="badge badge-severity" style={{ color }}>
      {label} · {score}
    </span>
  );
}