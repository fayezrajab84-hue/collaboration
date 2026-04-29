import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";
import path from "path";

export default defineConfig({
  plugins: [react()],
  resolve: {
    alias: {
      "@": path.resolve(__dirname, "./src"),
      "@devsecops/types": path.resolve(__dirname, "../../packages/types/src/index.ts"),
    },
  },
  server: {
    port: 5173,
    // Vite 5+ blocks unknown Host headers as a DNS-rebinding defence. When
    // the dev server is fronted by a Cloudflare Tunnel (Phase A6) or any
    // reverse proxy, the tunnel hostname has to be allowed explicitly.
    // Driven by env var so operators with different domains don't edit
    // source — defaults cover the local docker-compose patterns.
    //
    // Set VITE_ALLOWED_HOSTS in docker-compose.override.yml's web service
    // env when fronting via a tunnel:
    //   VITE_ALLOWED_HOSTS: "localhost,breachlens.fortisentinel.org"
    allowedHosts: (process.env.VITE_ALLOWED_HOSTS ?? "localhost,127.0.0.1,web")
      .split(",")
      .map((s) => s.trim())
      .filter(Boolean),
    watch: {
      usePolling: true,   // required on Windows/Docker — inotify events don't propagate
      interval: 1000,
    },
    proxy: {
      "/api": {
        target: process.env.API_URL ?? "http://localhost:3000",
        changeOrigin: true,
      },
      "/auth": {
        target: process.env.API_URL ?? "http://localhost:3000",
        changeOrigin: true,
      },
    },
  },
  build: {
    outDir: "dist",
    sourcemap: false,
  },
});
