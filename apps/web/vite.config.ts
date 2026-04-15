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
