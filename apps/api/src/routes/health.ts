import { Router } from "express";
import prisma from "../db.js";
import { redis } from "../redis.js";

const router = Router();

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

export default router;
