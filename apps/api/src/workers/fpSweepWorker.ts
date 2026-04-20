/**
 * FP Sweep Worker
 *
 * Runs on a repeatable BullMQ schedule (every 10 minutes).
 * Checks OPEN DAST/PENTEST findings for false positives while the system is idle.
 *
 * Safety guardrails:
 *  1. Skips if ANY scan job is currently RUNNING (not idle)
 *  2. Only analyses DAST / PENTEST / PENTEST_FULL findings
 *     (concrete HTTP evidence → highest AI accuracy)
 *  3. Auto-ignores ONLY when verdict = LIKELY_FP AND confidence = HIGH
 *  4. Never touches ACKNOWLEDGED / FALSE_POSITIVE / FIXED / IGNORED findings
 *  5. Processes max 3 findings per run to avoid monopolising Ollama on CPU
 *  6. Re-processes findings only if unchecked or last checked > 6 hours ago
 *  7. Every decision is logged with the AI's reasoning for auditability
 */

import { Worker } from "bullmq";
import { bullRedis } from "../redis.js";
import { logger } from "../logger.js";
import prisma from "../db.js";
import { checkFalsePositive } from "../services/falsePositiveService.js";
import { fpSweepQueue } from "../queues/definitions.js";

const BATCH_SIZE   = 3;
const RECHECK_AGE  = 6 * 60 * 60 * 1000; // 6 hours
const SWEEP_TARGET_SCAN_TYPES = ["DAST", "PENTEST", "PENTEST_FULL"] as const;

// ── Core sweep logic (exported so it can be called directly if needed) ────────

export async function runFpSweep(): Promise<{
  skipped:     boolean;
  reason?:     string;
  processed:   number;
  autoIgnored: number;
}> {
  // ── Guard: skip if any scan is actively running ───────────────────────────
  const activeScans = await prisma.scanJob.count({
    where: { status: "RUNNING" },
  });

  if (activeScans > 0) {
    logger.info(`[fp-sweep] idle check failed — ${activeScans} active scan(s), skipping`);
    return { skipped: true, reason: `${activeScans} active scan(s)`, processed: 0, autoIgnored: 0 };
  }

  // ── Find candidates ───────────────────────────────────────────────────────
  const recheckCutoff = new Date(Date.now() - RECHECK_AGE);

  const candidates = await prisma.finding.findMany({
    where: {
      status:   "OPEN",
      scanType: { in: [...SWEEP_TARGET_SCAN_TYPES] },
      OR: [
        { aiFpAnalysedAt: null },
        { aiFpAnalysedAt: { lt: recheckCutoff } },
      ],
    },
    // Prioritise: CRITICAL first (most impactful to validate), then oldest
    orderBy: [{ severity: "asc" }, { firstSeen: "asc" }],
    take: BATCH_SIZE,
    select: { id: true, scanType: true, severity: true, title: true, orgId: true },
  });

  if (candidates.length === 0) {
    logger.info("[fp-sweep] no unchecked DAST/PENTEST findings — nothing to do");
    return { skipped: false, processed: 0, autoIgnored: 0 };
  }

  logger.info(`[fp-sweep] analysing ${candidates.length} candidate finding(s)`);

  let autoIgnored = 0;

  for (const finding of candidates) {
    try {
      // force=true so we always get a fresh analysis during the sweep
      const analysis = await checkFalsePositive(finding.id, true);

      const willIgnore =
        analysis.verdict    === "LIKELY_FP" &&
        analysis.confidence === "HIGH";

      if (willIgnore) {
        await prisma.finding.update({
          where: { id: finding.id },
          data:  { status: "IGNORED", resolvedAt: new Date() },
        });
        autoIgnored++;

        logger.info(
          `[fp-sweep] AUTO-IGNORED finding ${finding.id} ` +
          `[${finding.severity} ${finding.scanType}] "${finding.title.slice(0, 80)}" ` +
          `— reasoning: ${analysis.reasoning.slice(0, 150)}`,
        );
      } else {
        logger.info(
          `[fp-sweep] kept OPEN finding ${finding.id} ` +
          `[${finding.severity} ${finding.scanType}] ` +
          `verdict=${analysis.verdict} confidence=${analysis.confidence}`,
        );
      }
    } catch (err) {
      // Never let a single failed analysis abort the whole sweep
      logger.warn(
        `[fp-sweep] failed to analyse finding ${finding.id}: ${(err as Error).message}`,
      );
    }
  }

  logger.info(
    `[fp-sweep] done — processed ${candidates.length}, ` +
    `auto-ignored ${autoIgnored}`,
  );

  return { skipped: false, processed: candidates.length, autoIgnored };
}

// ── BullMQ worker ─────────────────────────────────────────────────────────────

export function initFpSweepWorker(): void {
  const worker = new Worker(
    "fp-sweep",
    async () => {
      await runFpSweep();
    },
    {
      connection: bullRedis,
      concurrency: 1, // only one sweep at a time
    },
  );

  worker.on("completed", (job) => {
    logger.info(`[fp-sweep] job ${job.id} completed`);
  });

  worker.on("failed", (job, err) => {
    logger.error(`[fp-sweep] job ${job?.id} failed: ${err.message}`);
  });

  logger.info("[fp-sweep] worker initialised");
}

// ── Schedule repeatable job ───────────────────────────────────────────────────
// Runs every 10 minutes. BullMQ deduplicates — safe to call on every startup.

export async function scheduleFpSweep(): Promise<void> {
  await fpSweepQueue.add(
    "fp-sweep-tick",
    {},
    {
      repeat:  { every: 10 * 60 * 1000 }, // every 10 minutes
      jobId:   "fp-sweep-repeatable",     // stable ID prevents duplicate schedules
    },
  );
  logger.info("[fp-sweep] repeatable job scheduled (every 10 min)");
}
