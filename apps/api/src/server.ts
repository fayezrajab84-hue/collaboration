import app from "./app.js";
import { config } from "./config.js";
import { logger } from "./logger.js";
import prisma from "./db.js";
import { initWorkers } from "./workers/scanWorker.js";
import { initFpSweepWorker, scheduleFpSweep } from "./workers/fpSweepWorker.js";
import { initAiTriageWorker } from "./workers/aiTriageWorker.js";
import { initWazuhIngestWorker, scheduleWazuhIngest } from "./workers/wazuhIngestWorker.js";
import { initCorrelationWorker, scheduleCorrelation } from "./workers/correlationWorker.js";
import { startRecordingIdleSweeper } from "./services/recordingService.js";

async function start() {
  // Run Prisma migrations on startup in development
  if (config.NODE_ENV !== "production") {
    logger.info("Checking database connection...");
    await prisma.$connect();
    logger.info("Database connected.");
  }

  // Initialize BullMQ scan workers
  initWorkers();
  logger.info("BullMQ scan workers initialized.");

  // Initialize & schedule AI false-positive sweep
  initFpSweepWorker();
  await scheduleFpSweep();

  // Initialize AI triage worker (pre-populates analysis + fix for new findings)
  initAiTriageWorker();

  // Phase 28 Slice A — Wazuh runtime ingestion. Worker is always initialised
  // so the schedule lives in Redis; the service no-ops gracefully when
  // WAZUH_API_URL is unset, so this is safe in environments without Wazuh.
  initWazuhIngestWorker();
  await scheduleWazuhIngest();

  // Phase 27 Slice B — hourly attack-path correlation sweep across every org.
  // Catches drift when operators declare new asset relations after findings
  // already existed; the scan worker also triggers narrow refreshes inline
  // so freshly persisted findings get correlated within seconds.
  initCorrelationWorker();
  await scheduleCorrelation();

  // Sweep idle DAST recording sessions (60min idle / 4hr hard cap)
  startRecordingIdleSweeper();

  app.listen(config.PORT, () => {
    logger.info(`🚀 API server running on port ${config.PORT} (${config.NODE_ENV})`);
  });
}

start().catch((err) => {
  logger.error("Failed to start server", { error: err.message });
  process.exit(1);
});
