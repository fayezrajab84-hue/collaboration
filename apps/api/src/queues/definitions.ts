import { Queue } from "bullmq";
import { bullRedis } from "../redis.js";
import type { ScanType } from "@devsecops/types";

export interface ScanJobPayload {
  scanJobId: string;
  orgId: string;
  targetType: "REPOSITORY" | "CONTAINER" | "DOMAIN";
  targetId: string;
  scanType: ScanType;
  // Repository
  repoUrl?: string;
  branch?: string;
  encryptedGitToken?: string;
  // Container
  imageRef?: string;
  // Domain
  domain?: string;
}

const QUEUE_OPTS = {
  connection: bullRedis,
  defaultJobOptions: {
    attempts: 2,
    backoff: { type: "exponential" as const, delay: 5000 },
    removeOnComplete: 100,
    removeOnFail: 200,
    timeout: 1_560_000, // 26 min — scanner timeout is 24 min
  },
};

export const scanQueues: Record<ScanType, Queue<ScanJobPayload>> = {
  SAST: new Queue("scan-SAST", QUEUE_OPTS),
  SCA: new Queue("scan-SCA", QUEUE_OPTS),
  SECRET: new Queue("scan-SECRET", QUEUE_OPTS),
  IAC: new Queue("scan-IAC", QUEUE_OPTS),
  CONTAINER: new Queue("scan-CONTAINER", QUEUE_OPTS),
  DAST: new Queue("scan-DAST", QUEUE_OPTS),
  PENTEST: new Queue("scan-PENTEST", QUEUE_OPTS),
};
