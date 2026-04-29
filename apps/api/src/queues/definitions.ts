import { Queue } from "bullmq";
import { bullRedis } from "../redis.js";
import type { ScanType } from "@devsecops/types";

export interface ScanJobPayload {
  scanJobId: string;
  orgId: string;
  // Phase 29 — adds CLOUD_ACCOUNT to support CSPM scans. Cloud-specific
  // credentials are NOT in the queue payload — the worker fetches the
  // CloudAccount row by targetId and decrypts at scan-trigger time
  // (same pattern as DomainAuthConfig and encryptedGitToken).
  targetType: "REPOSITORY" | "CONTAINER" | "DOMAIN" | "CLOUD_ACCOUNT";
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
  pentestDepth?: "QUICK" | "STANDARD" | "AGGRESSIVE";
  // Authenticated scan — domain auth config id (looked up + decrypted in worker)
  domainAuthConfigId?: string;
  // Interactive provenance — recorded ZAP context to active-scan against.
  // Presence of recordingContextName flips DAST scans from /scan (crawl) to
  // /dast/recording/scan (replay). Provenance is no longer encoded in scanType.
  recordingContextId?: string;
  recordingContextName?: string;
  recordingTargetUrl?: string;
  recordingSessionId?: string;
  // Tier 1 — incremental scanning (restrict scanner to these paths)
  changedFiles?: string[];
  commitSha?:    string;
  baseCommitSha?: string;
  prNumber?:     number;
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

// ── Wazuh ingestion queue (Phase 28 Slice A) ──────────────────────────────────
// Recurring job (default 60s) — pulls Wazuh alerts and turns them into
// scanType=RUNTIME findings. The worker no-ops gracefully when WAZUH_API_URL
// is not configured, so unblocking the env var alone enables ingestion.
export const wazuhIngestQueue = new Queue("wazuh-ingest", {
  connection: bullRedis,
  defaultJobOptions: {
    // Poll history is mostly noise — keep tail short.
    removeOnComplete: 20,
    removeOnFail:     50,
  },
});

// ── Correlation queue (Phase 27 Slice B) ─────────────────────────────────────
// Recurring nightly sweep that runs the Bridge engine across every org's
// findings and persists correlationGroupId + correlationEdges. The scan
// worker also calls runCorrelationForFinding() inline after each upsert
// for fresh-finding latency; this recurring sweep catches drift (e.g. when
// an operator declares new asset relations after findings already existed).
export const correlationQueue = new Queue("correlation", {
  connection: bullRedis,
  defaultJobOptions: {
    removeOnComplete: 30,
    removeOnFail:     100,
  },
});

// Partial<Record<...>> rather than Record<...>: RUNTIME has no queue
// because Wazuh ingest is push-based (recurring sweep via wazuhIngestQueue),
// not triggered by triggerScan(). triggerScan() still runtime-checks via
// the `if (!queue) throw` path so an unknown ScanType fails loud rather
// than silently dropping.
export const scanQueues: Partial<Record<ScanType, Queue<ScanJobPayload>>> = {
  SAST: new Queue("scan-SAST", QUEUE_OPTS),
  SCA: new Queue("scan-SCA", QUEUE_OPTS),
  SECRET: new Queue("scan-SECRET", QUEUE_OPTS),
  IAC: new Queue("scan-IAC", QUEUE_OPTS),
  CONTAINER: new Queue("scan-CONTAINER", QUEUE_OPTS),
  DAST: new Queue("scan-DAST", QUEUE_OPTS),
  PENTEST: new Queue("scan-PENTEST", QUEUE_OPTS),
  PENTEST_FULL: new Queue("scan-PENTEST_FULL", QUEUE_OPTS),
  // Phase 29 Slice A — CSPM (Prowler-Azure). Same queue pattern as the
  // other scanner types; the scanWorker dispatches based on scanType.
  CLOUD: new Queue("scan-CLOUD", QUEUE_OPTS),
};
