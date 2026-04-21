import app from "./app.js";
import { config } from "./config.js";
import { logger } from "./logger.js";
import prisma from "./db.js";
import { initWorkers } from "./workers/scanWorker.js";
import { initFpSweepWorker, scheduleFpSweep } from "./workers/fpSweepWorker.js";
import { initAiTriageWorker } from "./workers/aiTriageWorker.js";

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

  app.listen(config.PORT, () => {
    logger.info(`🚀 API server running on port ${config.PORT} (${config.NODE_ENV})`);
  });
}

start().catch((err) => {
  logger.error("Failed to start server", { error: err.message });
  process.exit(1);
});
