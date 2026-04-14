import IORedis from "ioredis";
import { config } from "./config.js";

// General-purpose Redis client (sessions, caching)
export const redis = new IORedis(config.REDIS_URL, {
  maxRetriesPerRequest: null,
  enableReadyCheck: false,
});

// Dedicated BullMQ connection (BullMQ requires its own IORedis instance)
export const bullRedis = new IORedis(config.REDIS_URL, {
  maxRetriesPerRequest: null,
  enableReadyCheck: false,
});

redis.on("error", (err) => {
  console.error("[Redis] Connection error:", err.message);
});

bullRedis.on("error", (err) => {
  console.error("[BullMQ Redis] Connection error:", err.message);
});

export default redis;
