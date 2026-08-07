import { useEffect, useState } from "react";

const BASE = "/api";

async function get(path) {
  const res = await fetch(`${BASE}${path}`);
  if (!res.ok) {
    throw new Error(`${path} responded ${res.status}`);
  }
  return res.json();
}

export const api = {
  health: () => get("/health"),
  discovery: () => get("/discovery"),
  alerts: (limit = 100) => get(`/alerts?limit=${limit}`),
  statistics: () => get("/statistics"),
  owasp: () => get("/owasp"),
  logs: (limit = 50) => get(`/logs?limit=${limit}`),
};

/**
 * Polls a fetcher function on an interval and exposes { data, error, loading }.
 * Used for the "live" feel described in the plan (2-5s refresh) without a
 * websocket -- the dashboard API is a thin, stateless read layer over
 * files on disk, so polling is the honest match for that architecture.
 */
/**
 * Subscribes to the /api/alerts/stream SSE endpoint and calls onAlert for
 * every newly flagged request the server pushes. Auto-reconnects (native
 * EventSource behaviour) if the connection drops -- e.g. backend restart.
 */
export function useAlertStream(onAlert) {
  useEffect(() => {
    let es;
    try {
      es = new EventSource(`${BASE}/alerts/stream`);
    } catch {
      return undefined;
    }

    es.onmessage = (event) => {
      if (!event.data) return;
      try {
        onAlert(JSON.parse(event.data));
      } catch {
        // ignore malformed/heartbeat frames
      }
    };

    return () => es.close();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);
}

function triggerDownload(filename, content, mime) {
  const blob = new Blob([content], { type: mime });
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url;
  a.download = filename;
  document.body.appendChild(a);
  a.click();
  a.remove();
  URL.revokeObjectURL(url);
}

export function downloadJSON(filename, rows) {
  triggerDownload(filename, JSON.stringify(rows, null, 2), "application/json");
}

export function downloadCSV(filename, rows, columns) {
  // columns: [{ key, label }] -- key can be a dotted path or a function(row)
  const get = (row, col) =>
    typeof col.key === "function" ? col.key(row) : row?.[col.key];

  const escape = (val) => {
    const s = val === undefined || val === null ? "" : String(val);
    return /[",\n]/.test(s) ? `"${s.replace(/"/g, '""')}"` : s;
  };

  const header = columns.map((c) => escape(c.label)).join(",");
  const lines = rows.map((row) => columns.map((c) => escape(get(row, c))).join(","));
  triggerDownload(filename, [header, ...lines].join("\n"), "text/csv");
}

export function useLiveData(fetcher, intervalMs = 3000, deps = []) {
  const [data, setData] = useState(null);
  const [error, setError] = useState(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    let cancelled = false;

    async function load() {
      try {
        const result = await fetcher();
        if (!cancelled) {
          setData(result);
          setError(null);
          setLoading(false);
        }
      } catch (err) {
        if (!cancelled) {
          setError(err);
          setLoading(false);
        }
      }
    }

    load();
    const id = setInterval(load, intervalMs);
    return () => {
      cancelled = true;
      clearInterval(id);
    };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, deps);

  return { data, error, loading };
}