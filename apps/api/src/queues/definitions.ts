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
  // PENTEST_FULL extras
  selectedSubdomains?: string[];
  pentestDepth?: "STANDARD" | "AGGRESSIVE";
  // Authenticated scan — domain auth config id (looked up + decrypted in worker)
  domainAuthConfigId?: string;
}

const QUEUE_OPTS = {
  connection: bullRedis,
  defaultJobOptions: {
    attempts: 2,
    backoff: { type: "exponential" as const, delay: 5000 },
    removeOnComplete: 100,
    removeOnFail: 200,
  },
};

// ── AI Triage queue ───────────────────────────────────────────────────────────
// Processes new findings immediately after a scan: runs AI analysis +
// fix-suggestion generation so the drawer is pre-populated for the developer.
// Concurrency = 1 because Ollama can only handle one inference at a time.

export interface AiTriageJobPayload {
  findingId: string;
  scanType:  string;
  severity:  string;
}

export const aiTriageQueue = new Queue<AiTriageJobPayload>("ai-triage", {
  connection: bullRedis,
  defaultJobOptions: {
    attempts:         3,
    backoff:          { type: "exponential" as const, delay: 15_000 },
    removeOnComplete: 500,
    removeOnFail:     200,
  },
});

// ── FP Sweep queue ────────────────────────────────────────────────────────────
// Runs a repeatable job every 10 minutes to auto-ignore high-confidence FPs.
export const fpSweepQueue = new Queue("fp-sweep", {
  connection: bullRedis,
  defaultJobOptions: {
    removeOnComplete: 10,
    removeOnFail:     20,
  },
});

export const scanQueues: Record<ScanType, Queue<ScanJobPayload>> = {
  SAST: new Queue("scan-SAST", QUEUE_OPTS),
  SCA: new Queue("scan-SCA", QUEUE_OPTS),
  SECRET: new Queue("scan-SECRET", QUEUE_OPTS),
  IAC: new Queue("scan-IAC", QUEUE_OPTS),
  CONTAINER: new Queue("scan-CONTAINER", QUEUE_OPTS),
  DAST: new Queue("scan-DAST", QUEUE_OPTS),
  PENTEST: new Queue("scan-PENTEST", QUEUE_OPTS),
  PENTEST_FULL: new Queue("scan-PENTEST_FULL", QUEUE_OPTS),
};
