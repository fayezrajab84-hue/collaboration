/**
 * wazuhIngestService — Phase 28 Slice A.
 *
 * Polls a Wazuh manager's REST API on a schedule (default 60s; configurable
 * via WAZUH_POLL_INTERVAL_SECONDS). For each org with at least one enrolled
 * `WorkloadAgent`, fetches new alerts and turns them into `Finding` rows
 * with scanType=RUNTIME so they flow through the existing findings pipeline
 * (compliance mapping, SSE, notifications) without further code change.
 *
 * Two architectural decisions worth holding onto:
 *
 *   1. Hourly-bucket fingerprint. A busy Wazuh agent emits 100+ alerts/day;
 *      a naive "one Finding per alert" model would balloon the table and
 *      drown the UI in noise. Fingerprint = SHA-256(orgId + agentId + ruleId
 *      + hourBucket) so every matching alert in the same hour collapses
 *      into the SAME `Finding` row — `lastSeen` updates and the underlying
 *      alerts append into `rawOutput.alerts[]` for drill-down.
 *
 *   2. Wazuh severity 0-15 → BreachLens severity. Wazuh's `rule.level`
 *      field is the canonical signal; the table below is the documented
 *      mapping (see Phase 28 scope doc, Slice A "Severity mapping").
 *
 * Service is a no-op when WAZUH_API_URL is unset — the platform still
 * compiles and the rest of the work doesn't depend on Wazuh being deployed.
 * Operators with Wazuh supply the env vars and ingestion turns on without
 * a code change.
 */
import { createHash, randomUUID } from "node:crypto";
import { Agent as HttpsAgent } from "node:https";
import axios, { type AxiosInstance } from "axios";
import { config } from "../../config.js";
import { logger } from "../../logger.js";
import prisma from "../../db.js";
import type { Severity } from "@devsecops/types";

// ── Types ─────────────────────────────────────────────────────────────────

export interface WazuhAlert {
  /** Numeric agent ID assigned by the Wazuh manager (e.g. "001"). */
  agent_id:   string;
  agent_name: string;
  /** ISO timestamp from Wazuh; we trust this as the alert time. */
  timestamp:  string;
  rule: {
    id:          string;
    /** 0-15 severity scale. */
    level:       number;
    description: string;
    /** Optional MITRE ATT&CK technique IDs (e.g. ["T1059"]). */
    mitre_ids?:  string[];
    /** Free-form group tags ("syscheck", "audit", "command"). */
    groups?:     string[];
  };
  /** Free-form per-alert location string (file path, command, etc.). */
  location?:    string;
  /** Source IP if alert is network-related. */
  src_ip?:      string;
  /** Raw text the agent reported, kept verbatim for evidence. */
  full_log?:    string;
  /** Anything else Wazuh sent us — preserved for the drill-down UI. */
  [extra: string]: unknown;
}

export interface IngestRunSummary {
  enabled:           boolean;
  reason?:           string;
  agentsConsidered:  number;
  agentsPolled:      number;
  alertsIngested:    number;
  findingsTouched:   number;
  errors:            string[];
}

// ── Public entry points ───────────────────────────────────────────────────

/**
 * Run one ingestion sweep across every org with at least one WorkloadAgent.
 * Idempotent — safe to call from a recurring BullMQ job. Returns a summary
 * the worker can log; never throws (errors are collected per-agent).
 */
export async function runWazuhIngestionSweep(
  // Override hooks for unit testing — production passes undefined.
  fetcher: AlertsFetcher = defaultAlertsFetcher,
): Promise<IngestRunSummary> {
  if (!config.WAZUH_API_URL) {
    return {
      enabled:          false,
      reason:           "WAZUH_API_URL not configured — runtime ingestion disabled",
      agentsConsidered: 0,
      agentsPolled:     0,
      alertsIngested:   0,
      findingsTouched:  0,
      errors:           [],
    };
  }

  const agents = await prisma.workloadAgent.findMany({
    orderBy: { lastHeartbeatAt: { sort: "asc", nulls: "first" } },
  });

  const summary: IngestRunSummary = {
    enabled:          true,
    agentsConsidered: agents.length,
    agentsPolled:     0,
    alertsIngested:   0,
    findingsTouched:  0,
    errors:           [],
  };

  if (agents.length === 0) {
    return summary; // nothing to poll yet
  }

  const sinceWindow = pollSince();

  for (const agent of agents) {
    try {
      const alerts = await fetcher(agent.wazuhAgentId, sinceWindow);
      summary.agentsPolled++;
      summary.alertsIngested += alerts.length;

      const touched = await ingestAlertsForAgent(agent.id, agent.orgId, alerts);
      summary.findingsTouched += touched;

      await prisma.workloadAgent.update({
        where: { id: agent.id },
        data: {
          status:          alerts.length > 0 ? "HEALTHY" : healthFromHeartbeat(agent.lastHeartbeatAt),
          lastIngestError: null,
          // We can only really know lastHeartbeat by querying Wazuh's agent
          // status endpoint — for v1, treat "successful poll" as a heartbeat.
          // Full agent-status sync is a Phase 28.x enhancement.
          lastHeartbeatAt: new Date(),
          ...(alerts.length > 0 ? { lastAlertAt: new Date() } : {}),
        },
      });
    } catch (err) {
      const msg = (err as Error).message;
      summary.errors.push(`agent ${agent.wazuhAgentId}: ${msg}`);
      await prisma.workloadAgent.update({
        where: { id: agent.id },
        data:  { lastIngestError: msg.slice(0, 500), status: "OFFLINE" },
      });
    }
  }

  return summary;
}

// ── Severity mapping (Wazuh 0-15 → BreachLens severity) ──────────────────
// Documented in Phase 28 scope doc Slice A. Boundaries match Wazuh's own
// "alert level" guidance: 13+ is "exploit attempt", 10-12 is "high probability
// of attack", 7-9 is "noteworthy", 4-6 is "low priority", 0-3 is "info / debug".
export function mapWazuhLevelToSeverity(level: number): Severity {
  if (level >= 13) return "CRITICAL";
  if (level >= 10) return "HIGH";
  if (level >= 7)  return "MEDIUM";
  if (level >= 4)  return "LOW";
  return "INFO";
}

// ── Alert → Finding ingestion (the dedup-via-fingerprint heart) ──────────

async function ingestAlertsForAgent(
  agentRowId: string,
  orgId:      string,
  alerts:     WazuhAlert[],
): Promise<number> {
  if (alerts.length === 0) return 0;

  // Phase 28 Slice C — load the agent's linked Container (if the operator
  // has set one). Persisting it on Finding.containerId is what lets
  // runtimeBridge fire on freshly-ingested alerts without needing
  // BridgeContext fallback. Cheap single lookup; cached implicitly by
  // Prisma's connection pool.
  const agentRow = await prisma.workloadAgent.findUnique({
    where:  { id: agentRowId },
    select: { linkedContainerId: true },
  });
  const linkedContainerId = agentRow?.linkedContainerId ?? null;

  // Phase 28 Slice C bugfix (P3 follow-up): reuse a per-container ScanJob
  // row across polls instead of creating a fresh one every 60 seconds.
  //
  // The previous design created a new ScanJob per ingestion run per agent
  // — fine in theory, but with the recurring sweep firing every 60s and
  // the mock-wazuh service always returning canned alerts, this churned
  // 60 ScanJob rows/hour into the scan history (38 spam rows in 38
  // minutes during a real test session). The Finding.scanJobId FK
  // requires a real ScanJob, so the original create-per-run pattern was
  // safe but UX-hostile: the Scans page filled up with empty
  // "RUNTIME (Wazuh)" rows the operator never asked for.
  //
  // Find-or-create: one canonical ScanJob row per
  // (orgId, containerId, scanType=RUNTIME) tuple. ScanJob has typed FKs
  // (containerId / repositoryId / domainId) — no generic targetId
  // column — so we use linkedContainerId as the natural key. Multiple
  // agents on the same container share one row (good — they're
  // monitoring the same workload anyway). Unlinked agents share a single
  // null-container row (acceptable; operator should link the agent to
  // get clean attribution).
  let scanJob = await prisma.scanJob.findFirst({
    where: {
      orgId,
      targetType: "CONTAINER",
      containerId: linkedContainerId,
      scanTypes:  { has: "RUNTIME" },
    },
    select: { id: true },
  });
  if (!scanJob) {
    scanJob = await prisma.scanJob.create({
      data: {
        orgId,
        targetType:     "CONTAINER",
        containerId:    linkedContainerId,
        scanTypes:      ["RUNTIME"],
        status:         "COMPLETED",
        totalScans:     1,
        completedScans: 1,
        startedAt:      new Date(),
        completedAt:    new Date(),
      },
      select: { id: true },
    });
  } else {
    // Touch the timestamps so the Scans page reflects "last ingest run"
    // rather than "first ever ingest".
    await prisma.scanJob.update({
      where: { id: scanJob.id },
      data:  { startedAt: new Date(), completedAt: new Date(), status: "COMPLETED" },
    });
  }

  // Bucket by hour + agent + rule so 100 shell-spawn alerts in the same hour
  // upsert into ONE Finding row (matches the Phase 28 scope decision).
  const buckets = new Map<string, { fingerprint: string; alerts: WazuhAlert[]; rep: WazuhAlert }>();
  for (const a of alerts) {
    const ts = new Date(a.timestamp);
    const hourBucket = `${ts.getUTCFullYear()}-${ts.getUTCMonth() + 1}-${ts.getUTCDate()}T${ts.getUTCHours()}`;
    const fingerprint = sha256(`${orgId}|${a.agent_id}|${a.rule.id}|${hourBucket}`);
    const bucket = buckets.get(fingerprint);
    if (bucket) bucket.alerts.push(a);
    else buckets.set(fingerprint, { fingerprint, alerts: [a], rep: a });
  }

  let touched = 0;

  for (const { fingerprint, alerts: bucketAlerts, rep } of buckets.values()) {
    const severity = mapWazuhLevelToSeverity(rep.rule.level);
    const title    = rep.rule.description;
    const description =
      `Wazuh runtime alert: ${title}` +
      (rep.location ? ` · location: ${rep.location}` : "") +
      ` · ${bucketAlerts.length} occurrence(s) in this hour.`;

    // Upsert by unique fingerprint — same key → same Finding row updated.
    const existing = await prisma.finding.findUnique({ where: { fingerprint } });
    if (existing) {
      const previousAlerts = Array.isArray((existing.rawOutput as { alerts?: unknown })?.alerts)
        ? ((existing.rawOutput as { alerts: unknown[] }).alerts)
        : [];
      await prisma.finding.update({
        where: { id: existing.id },
        data: {
          lastSeen: new Date(),
          // Cap appended raw alerts at 200 per row to keep JSONB rows small;
          // the more recent ones are kept for drill-down.
          rawOutput: {
            ...(existing.rawOutput as object),
            alerts: [...previousAlerts, ...bucketAlerts].slice(-200),
          },
        },
      });
    } else {
      await prisma.finding.create({
        data: {
          orgId,
          scanJobId:   scanJob.id,
          targetType:  "CONTAINER",
          // Phase 28 Slice C — when the operator has linked the WorkloadAgent
          // to a Container, set Finding.containerId so runtimeBridge can fire
          // without BridgeContext fallback resolution. Null when unlinked
          // (the bridge falls back to the BridgeContext map).
          containerId: linkedContainerId,
          scanType:    "RUNTIME",
          title,
          description,
          severity,
          scanner:     "wazuh",
          ruleId:      rep.rule.id,
          fingerprint,
          confidence:  "POSSIBLE",
          rawOutput:   { source: "wazuh", agent_id: rep.agent_id, alerts: bucketAlerts },
          // MITRE / Wazuh group tags surface as references — useful when
          // operators pivot from a finding into ATT&CK navigator etc.
          references:  [
            ...(rep.rule.mitre_ids ?? []).map((t) => `MITRE ATT&CK ${t}`),
            ...(rep.rule.groups ?? []),
          ],
        },
      });
    }
    touched++;
  }

  return touched;
}

// ── Wazuh REST client ─────────────────────────────────────────────────────

export type AlertsFetcher = (
  wazuhAgentId: string,
  sinceIso:     string,
) => Promise<WazuhAlert[]>;

/**
 * Production fetcher — calls the Wazuh manager's `/security/user/authenticate`
 * to get a JWT, then `/security/user/me` and the alerts endpoint. We cache
 * the JWT in-process for its TTL.
 *
 * Note: Wazuh's REST API has historically shifted between Wazuh Indexer
 * (OpenSearch-backed) and Wazuh Manager APIs. This implementation targets
 * the Wazuh Manager API 4.x, which most installs use. Operators on the
 * indexer-only path (no Manager API exposed) need the Phase 28.x adapter.
 */
async function defaultAlertsFetcher(wazuhAgentId: string, sinceIso: string): Promise<WazuhAlert[]> {
  const client = await getWazuhClient();
  // Wazuh Manager API queries an OpenSearch index for alerts. The manager
  // exposes `/elasticsearch/wazuh-alerts-*/_search` as a passthrough.
  // For environments using Wazuh's API "alerts" endpoint, swap in here.
  const response = await client.post(
    `/security/events/_search`,
    {
      size: 200,
      query: {
        bool: {
          must: [
            { term:  { "agent.id":   wazuhAgentId } },
            { range: { "timestamp": { gte: sinceIso } } },
          ],
        },
      },
      sort: [{ timestamp: "asc" }],
    },
  );
  const hits = (response.data?.hits?.hits ?? []) as Array<{ _source: Record<string, unknown> }>;
  return hits.map((hit) => normaliseAlert(hit._source)).filter(Boolean) as WazuhAlert[];
}

let cachedClient: AxiosInstance | null = null;
let cachedToken:  { value: string; expiresAt: number } | null = null;

async function getWazuhClient(): Promise<AxiosInstance> {
  if (!cachedClient) {
    cachedClient = axios.create({
      baseURL: config.WAZUH_API_URL!,
      timeout: 15_000,
      ...(config.WAZUH_INSECURE_TLS
        ? { httpsAgent: new HttpsAgent({ rejectUnauthorized: false }) }
        : {}),
    });
  }
  // Lazy auth; refresh token 60s before expiry.
  if (!cachedToken || cachedToken.expiresAt < Date.now() + 60_000) {
    if (!config.WAZUH_API_USER || !config.WAZUH_API_PASSWORD) {
      throw new Error("WAZUH_API_USER + WAZUH_API_PASSWORD required for ingestion");
    }
    const auth = await cachedClient.post(`/security/user/authenticate`, undefined, {
      auth: { username: config.WAZUH_API_USER, password: config.WAZUH_API_PASSWORD },
    });
    cachedToken = {
      value:     auth.data?.data?.token ?? "",
      // Wazuh JWTs default to 900s. Use 800s to be safe.
      expiresAt: Date.now() + 800_000,
    };
    cachedClient.defaults.headers.common["Authorization"] = `Bearer ${cachedToken.value}`;
  }
  return cachedClient;
}

function normaliseAlert(src: Record<string, unknown>): WazuhAlert | null {
  const rule = (src["rule"] ?? {}) as Record<string, unknown>;
  const agent = (src["agent"] ?? {}) as Record<string, unknown>;
  const id  = String(rule["id"]    ?? "");
  const lvl = Number(rule["level"] ?? 0);
  if (!id || Number.isNaN(lvl)) return null;
  return {
    agent_id:   String(agent["id"]   ?? ""),
    agent_name: String(agent["name"] ?? ""),
    timestamp:  String(src["timestamp"] ?? new Date().toISOString()),
    rule: {
      id,
      level:       lvl,
      description: String(rule["description"] ?? "Wazuh alert"),
      mitre_ids:   Array.isArray(rule["mitre"]) ? (rule["mitre"] as string[]) : undefined,
      groups:      Array.isArray(rule["groups"]) ? (rule["groups"] as string[]) : undefined,
    },
    location: src["location"] as string | undefined,
    src_ip:   src["srcip"]    as string | undefined,
    full_log: src["full_log"] as string | undefined,
    ...src,
  };
}

// ── Helpers ───────────────────────────────────────────────────────────────

function pollSince(): string {
  // Look back 2× the poll interval as a buffer for clock skew + slow agents.
  const lookback = config.WAZUH_POLL_INTERVAL_SECONDS * 2 * 1000;
  return new Date(Date.now() - lookback).toISOString();
}

function healthFromHeartbeat(lastHeartbeat: Date | null): "HEALTHY" | "STALE" | "OFFLINE" | "UNKNOWN" {
  if (!lastHeartbeat) return "UNKNOWN";
  const ageMs = Date.now() - lastHeartbeat.getTime();
  if (ageMs < 2 * 60 * 1000)  return "HEALTHY";
  if (ageMs < 10 * 60 * 1000) return "STALE";
  return "OFFLINE";
}

function sha256(input: string): string {
  return createHash("sha256").update(input).digest("hex");
}

// Test-only re-export so unit tests can construct a fake fetcher easily.
export const _testing = { healthFromHeartbeat, sha256 };
