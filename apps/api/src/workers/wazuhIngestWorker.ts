/**
 * wazuhIngestWorker — Phase 28 Slice A.
 *
 * Drives the Wazuh ingestion sweep on a BullMQ recurring schedule. Single
 * concurrency because we don't want overlapping polls hammering the manager.
 *
 * Schedule cadence is operator-tunable via WAZUH_POLL_INTERVAL_SECONDS (env;
 * minimum 30s, default 60s). The schedule is added with a stable jobId so
 * BullMQ deduplicates on every API restart — no operator action needed.
 *
 * Worker is *always* initialised so the schedule lives in Redis. The
 * ingestion service itself short-circuits when WAZUH_API_URL is not set,
 * which keeps the path predictable: the recurring job runs, observes
 * "ingestion disabled" from the service, and exits in <1ms.
 */
import { Worker } from "bullmq";
import { bullRedis } from "../redis.js";
import { logger } from "../logger.js";
import { config } from "../config.js";
import { wazuhIngestQueue } from "../queues/definitions.js";
import { runWazuhIngestionSweep } from "../services/runtime/wazuhIngestService.js";

const STABLE_JOB_ID = "wazuh-ingest-repeatable";

export function initWazuhIngestWorker(): void {
  const worker = new Worker(
    "wazuh-ingest",
    async () => {
      const summary = await runWazuhIngestionSweep();
      if (!summary.enabled) {
        // Don't spam the log — only emit when reason changes meaningfully.
        // For v1, log once per process start; the "enabled=false" path is
        // intentionally cheap so the no-op cost is invisible.
        return summary;
      }
      if (summary.errors.length > 0) {
        logger.warn(`[wazuh-ingest] ${summary.errors.length} agent error(s): ${summary.errors.join("; ")}`);
      }
      if (summary.alertsIngested > 0 || summary.findingsTouched > 0) {
        logger.info(
          `[wazuh-ingest] swept ${summary.agentsPolled}/${summary.agentsConsidered} agent(s); ` +
          `${summary.alertsIngested} alert(s) → ${summary.findingsTouched} finding(s) touched`,
        );
      }
      return summary;
    },
    {
      connection:  bullRedis,
      concurrency: 1,
    },
  );

  worker.on("failed", (job, err) => {
    logger.error(`[wazuh-ingest] job ${job?.id} failed: ${err.message}`);
  });

  logger.info("[wazuh-ingest] worker initialised");
}

export async function scheduleWazuhIngest(): Promise<void> {
  const intervalMs = config.WAZUH_POLL_INTERVAL_SECONDS * 1000;
  await wazuhIngestQueue.add(
    "wazuh-ingest-tick",
    {},
    {
      repeat: { every: intervalMs },
      jobId:  STABLE_JOB_ID,
    },
  );
  if (config.WAZUH_API_URL) {
    logger.info(
      `[wazuh-ingest] repeatable job scheduled (every ${config.WAZUH_POLL_INTERVAL_SECONDS}s) — ingestion ENABLED`,
    );
  } else {
    logger.info(
      `[wazuh-ingest] repeatable job scheduled (every ${config.WAZUH_POLL_INTERVAL_SECONDS}s) — ingestion no-op (WAZUH_API_URL unset)`,
    );
  }
}
