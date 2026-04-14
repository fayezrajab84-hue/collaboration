import app from "./app.js";
import { config } from "./config.js";
import { logger } from "./logger.js";
import prisma from "./db.js";
import { initWorkers } from "./workers/scanWorker.js";

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

  app.listen(config.PORT, () => {
    logger.info(`🚀 API server running on port ${config.PORT} (${config.NODE_ENV})`);
  });
}

start().catch((err) => {
  logger.error("Failed to start server", { error: err.message });
  process.exit(1);
});
