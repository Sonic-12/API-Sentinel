import { Routes, Route } from "react-router-dom";
import Sidebar from "./components/Sidebar";
import Topbar from "./components/Topbar";
import Dashboard from "./pages/Dashboard";
import Analytics from "./pages/Analytics";
import Discovery from "./pages/Discovery";
import Alerts from "./pages/Alerts";
import MaskedLogs from "./pages/MaskedLogs";
import Owasp from "./pages/Owasp";
import Settings from "./pages/Settings";

export default function App() {
  return (
    <div className="shell">
      <Sidebar />
      <div className="main">
        <Topbar />
        <div className="content">
          <Routes>
            <Route path="/" element={<Dashboard />} />
            <Route path="/analytics" element={<Analytics />} />
            <Route path="/discovery" element={<Discovery />} />
            <Route path="/alerts" element={<Alerts />} />
            <Route path="/masked-logs" element={<MaskedLogs />} />
            <Route path="/owasp" element={<Owasp />} />
            <Route path="/settings" element={<Settings />} />
          </Routes>
        </div>
      </div>
    </div>
  );
}