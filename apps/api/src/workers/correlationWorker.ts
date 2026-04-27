/**
 * correlationWorker — Phase 27 Slice B.
 *
 * Hourly recurring job that runs the correlation engine across every org.
 * The scan worker also triggers narrow refreshes inline via
 * `runCorrelationForFinding()` so newly persisted findings get correlated
 * within seconds; this hourly sweep catches drift — e.g. when an operator
 * declares NEW asset relations and prior findings need their chains updated
 * to reflect the new linkage.
 *
 * Single concurrency to avoid two simultaneous full-org sweeps (would race
 * on the same Finding rows). Cheap to re-run at hourly cadence even at
 * 10k findings — the bridge calls themselves are microseconds.
 */
import { Worker } from "bullmq";
import { bullRedis } from "../redis.js";
import { logger } from "../logger.js";
import prisma from "../db.js";
import { correlationQueue } from "../queues/definitions.js";
import { runCorrelationForOrg } from "../services/correlation/correlationService.js";

const STABLE_JOB_ID = "correlation-repeatable";

export function initCorrelationWorker(): void {
  const worker = new Worker(
    "correlation",
    async () => {
      // Iterate every org with at least one finding. Cheap query (groupBy
      // hits the Finding(orgId) index). Empty orgs cost nothing.
      const orgs = await prisma.finding.groupBy({
        by:    ["orgId"],
        where: { status: { not: "FALSE_POSITIVE" } },
      });
      for (const { orgId } of orgs) {
        try {
          const summary = await runCorrelationForOrg(orgId);
          if (summary.bridgeMatches > 0 || summary.groupsFormed > 0) {
            logger.info(
              `[correlation] org ${orgId}: ${summary.findingsConsidered} findings → ` +
              `${summary.bridgeMatches} matches, ${summary.groupsFormed} groups (${summary.durationMs}ms)`,
            );
          }
        } catch (err) {
          logger.error(`[correlation] org ${orgId} failed: ${(err as Error).message}`);
        }
      }
    },
    { connection: bullRedis, concurrency: 1 },
  );

  worker.on("failed", (job, err) => {
    logger.error(`[correlation] job ${job?.id} failed: ${err.message}`);
  });

  logger.info("[correlation] worker initialised");
}

export async function scheduleCorrelation(): Promise<void> {
  await correlationQueue.add(
    "correlation-tick",
    {},
    {
      // Hourly is the right balance — bridge work is cheap, but findings
      // change throughout the day as scans complete + operators link assets.
      repeat: { every: 60 * 60 * 1000 },
      jobId:  STABLE_JOB_ID,
    },
  );
  logger.info("[correlation] repeatable job scheduled (every 60 min)");
}
