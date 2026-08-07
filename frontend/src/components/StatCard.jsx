export default function StatCard({ label, value, suffix, accent }) {
  return (
    <div className="stat-card" style={accent ? { "--accent": accent } : undefined}>
      <p className="stat-label">{label}</p>
      <div className="stat-value">
        {value}
        {suffix && <small>{suffix}</small>}
      </div>
    </div>
  );
}