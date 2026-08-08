import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";

// Proxies /api/* to the FastAPI dashboard service in dev, so the frontend can always just call fetch("/api/...") regardless of host/port.
export default defineConfig({
  plugins: [react()],
  server: {
    port: 5173,
    proxy: {
      "/api": {
        target: "http://127.0.0.1:8010",
        changeOrigin: true,
      },
    },
  },
});