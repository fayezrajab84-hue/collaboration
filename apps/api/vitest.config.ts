import { defineConfig } from "vitest/config";

export default defineConfig({
  test: {
    // Co-located *.test.ts files alongside the code under test
    // (apps/api/src/foo/bar.test.ts), not a top-level __tests__ tree.
    // Easier to find the test from the code and vice versa.
    include: ["src/**/*.test.ts"],

    // Tests must be isolated — Prisma mocks in one suite must NOT leak
    // into another. `pool: "forks"` gives each test file its own
    // process; slower than threads but avoids module-cache pollution
    // when we mock @prisma/client.
    pool: "forks",

    // 30s default is too generous for unit tests; if a test takes >5s
    // something is probably hanging on a real network call (we mock
    // those, so this is a smoke alarm).
    testTimeout: 5000,

    // Surface unhandled promise rejections from async middleware as
    // test failures instead of silent fall-throughs.
    dangerouslyIgnoreUnhandledErrors: false,
  },
});
