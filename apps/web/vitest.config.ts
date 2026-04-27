import { defineConfig } from "vitest/config";
import path from "node:path";

export default defineConfig({
  resolve: {
    alias: {
      "@devsecops/types": path.resolve(__dirname, "../../packages/types/src/index.ts"),
    },
  },
  test: {
    include: ["src/**/*.test.ts", "src/**/*.test.tsx"],
    pool: "forks",
    testTimeout: 5000,
  },
});
