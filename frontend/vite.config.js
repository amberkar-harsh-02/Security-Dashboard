import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";

// The dev server proxies /api to Flask, so the browser sees one origin and the
// session cookie works without cross-site settings.
const backend = process.env.SIEM_BACKEND_URL || "http://127.0.0.1:5000";

export default defineConfig({
  // Served at /siem/ behind Caddy: build with SIEM_BASE_PATH=/siem/. Development stays at /.
  base: process.env.SIEM_BASE_PATH || "/",
  plugins: [react()],
  server: {
    port: 3000,
    proxy: {
      "/api": { target: backend, changeOrigin: false },
    },
  },
  preview: {
    port: 3000,
    proxy: {
      "/api": { target: backend, changeOrigin: false },
    },
  },
  test: {
    environment: "jsdom",
    setupFiles: "./src/test/setup.js",
    css: false,
  },
});
