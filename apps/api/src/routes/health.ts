import { Router } from "express";
import prisma from "../db.js";
import { redis } from "../redis.js";
import { config } from "../config.js";

const router = Router();

// ── /health ──────────────────────────────────────────────────────────────────
// Shallow liveness probe. Read-only checks against DB + Redis. Used by the
// docker healthcheck and any external load balancer probe — fast, cheap,
// runs on every interval. Does NOT verify writability or downstream
// reachability; for that, use /healthz.
router.get("/health", async (_req, res) => {
  const checks: Record<string, string> = {};

  try {
    await prisma.$queryRaw`SELECT 1`;
    checks["db"] = "ok";
  } catch {
    checks["db"] = "error";
  }

  try {
    await redis.ping();
    checks["redis"] = "ok";
  } catch {
    checks["redis"] = "error";
  }

  const allOk = Object.values(checks).every((v) => v === "ok");
  res.status(allOk ? 200 : 503).json({
    status: allOk ? "ok" : "degraded",
    ...checks,
  });
});

// ── /healthz ─────────────────────────────────────────────────────────────────
// Deep readiness probe. Verifies write paths and downstream reachability,
// not just connectivity. More expensive than /health (a few writes + an
// outbound HTTP call); intended for operator dashboards, smoke tests, and
// periodic ops checks — not for every-second LB polls.
//
// Checks performed:
//   • db        — PostgreSQL is writable (advisory-lock acquire/release,
//                 which fails on a read replica or DB in recovery)
//   • redis     — Redis is writable (SET + GET roundtrip on a TTL'd probe key)
//   • scanner   — Python scanner service is reachable on its /health endpoint
//
// Each check captures a latency measurement so dashboards can alert on
// slow degradation before it becomes a hard failure.
router.get("/healthz", async (_req, res) => {
  type CheckResult = { status: "ok" | "error"; latencyMs: number; error?: string };
  const checks: Record<string, CheckResult> = {};

  // ── DB write check ────────────────────────────────────────────────────────
  // pg_try_advisory_lock writes to the internal lock table; it succeeds on
  // a primary in normal operation and fails on a read-only replica. The lock
  // key 0xBEEF1E48 is arbitrary and namespaced to this probe to avoid
  // colliding with any application-level advisory locks.
  {
    const t0 = Date.now();
    try {
      const rows = await prisma.$queryRaw<Array<{ acquired: boolean }>>`
        SELECT pg_try_advisory_lock(3203961928) AS acquired
      `;
      const acquired = rows[0]?.acquired === true;
      if (acquired) {
        await prisma.$executeRaw`SELECT pg_advisory_unlock(3203961928)`;
        checks["db"] = { status: "ok", latencyMs: Date.now() - t0 };
      } else {
        checks["db"] = { status: "error", latencyMs: Date.now() - t0, error: "advisory lock not acquired" };
      }
    } catch (err) {
      checks["db"] = { status: "error", latencyMs: Date.now() - t0, error: err instanceof Error ? err.message : String(err) };
    }
  }

  // ── Redis write check ─────────────────────────────────────────────────────
  // SET with a 10-second TTL so failed probes garbage-collect themselves;
  // round-trip the value to confirm both write and read paths.
  {
    const t0 = Date.now();
    const probeKey = `healthz:probe:${process.pid}`;
    const probeValue = String(Date.now());
    try {
      await redis.set(probeKey, probeValue, "EX", 10);
      const echoed = await redis.get(probeKey);
      if (echoed === probeValue) {
        checks["redis"] = { status: "ok", latencyMs: Date.now() - t0 };
      } else {
        checks["redis"] = { status: "error", latencyMs: Date.now() - t0, error: `value mismatch: wrote ${probeValue}, read ${echoed}` };
      }
    } catch (err) {
      checks["redis"] = { status: "error", latencyMs: Date.now() - t0, error: err instanceof Error ? err.message : String(err) };
    }
  }

  // ── Scanner reachability ──────────────────────────────────────────────────
  // The scanner is a separate FastAPI process; a healthy API doesn't mean
  // scans can run. AbortController gives us a hard 2-second cap so a stuck
  // scanner doesn't slow down the probe past the LB's timeout window.
  {
    const t0 = Date.now();
    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), 2000);
    try {
      const resp = await fetch(`${config.SCANNER_URL}/health`, { signal: controller.signal });
      if (resp.ok) {
        checks["scanner"] = { status: "ok", latencyMs: Date.now() - t0 };
      } else {
        checks["scanner"] = { status: "error", latencyMs: Date.now() - t0, error: `HTTP ${resp.status}` };
      }
    } catch (err) {
      const msg = err instanceof Error
        ? (err.name === "AbortError" ? "timeout (>2s)" : err.message)
        : String(err);
      checks["scanner"] = { status: "error", latencyMs: Date.now() - t0, error: msg };
    } finally {
      clearTimeout(timeout);
    }
  }

  const allOk = Object.values(checks).every((c) => c.status === "ok");
  res.status(allOk ? 200 : 503).json({
    status: allOk ? "ok" : "degraded",
    checks,
  });
});

export default router;
