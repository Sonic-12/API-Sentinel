export default function PulseLine({ trend = [], color = "var(--brand)" }) {
  const width = 240;
  const height = 28;
  const values = trend.length ? trend.map((t) => t.count) : [0];
  const max = Math.max(1, ...values);

  const points = values.map((v, i) => {
    const x = (i / Math.max(1, values.length - 1)) * width;
    const y = height - (v / max) * (height - 6) - 3;
    return `${x.toFixed(1)},${y.toFixed(1)}`;
  });

  const path = points.length > 1 ? `M${points.join(" L")}` : "";

  return (
    <svg
      className="pulse"
      viewBox={`0 0 ${width} ${height}`}
      preserveAspectRatio="none"
      role="img"
      aria-label="Request volume over the last 30 minutes"
    >
      <line x1="0" y1={height - 1} x2={width} y2={height - 1} stroke="var(--border-soft)" strokeWidth="1" />
      {path && <path d={path} fill="none" stroke={color} strokeWidth="1.5" strokeLinejoin="round" strokeLinecap="round" />}
      {points.length > 0 && (
        <circle cx={points[points.length - 1].split(",")[0]} cy={points[points.length - 1].split(",")[1]} r="2.5" fill={color} />
      )}
    </svg>
  );
}