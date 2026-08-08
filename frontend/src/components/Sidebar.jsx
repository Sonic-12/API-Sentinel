import { NavLink } from "react-router-dom";
import { ShieldHalf, LayoutDashboard, BarChart3, Radar, Siren, EyeOff, ShieldCheck, Settings } from "lucide-react";

const LINKS = [
  { to: "/", label: "Dashboard", icon: LayoutDashboard, end: true },
  { to: "/analytics", label: "Analytics", icon: BarChart3 },
  { to: "/discovery", label: "Discovery", icon: Radar },
  { to: "/alerts", label: "Alerts", icon: Siren },
  { to: "/masked-logs", label: "Masked Logs", icon: EyeOff },
  { to: "/owasp", label: "OWASP Coverage", icon: ShieldCheck },
  { to: "/settings", label: "Settings", icon: Settings },
];

export default function Sidebar() {
  return (
    <aside className="sidebar">
      <div className="brand">
        <ShieldHalf className="brand-mark" strokeWidth={2.2} />
        API-Sentinel
      </div>
      <nav className="nav">
        {LINKS.map(({ to, label, icon: Icon, end }) => (
          <NavLink
            key={to}
            to={to}
            end={end}
            className={({ isActive }) => `nav-link${isActive ? " active" : ""}`}
          >
            <Icon strokeWidth={2} />
            {label}
          </NavLink>
        ))}
      </nav>
    </aside>
  );
}