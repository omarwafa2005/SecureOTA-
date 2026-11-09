import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";

// The console server (python console/server.py) listens on 127.0.0.1:8000.
const server = "http://127.0.0.1:8000";

export default defineConfig({
  plugins: [react()],
  server: { proxy: { "/api": server, "/demo": server } },
});
