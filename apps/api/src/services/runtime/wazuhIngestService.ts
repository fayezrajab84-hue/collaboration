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
  /**
   * Vulnerability state docs ingested per sweep — Wazuh 4.13's VD module
   * writes to `wazuh-states-vulnerabilities-*` rather than the deprecated
   * /vulnerability/<id> manager API. We pick those up alongside alerts so
   * each agent's per-package CVE inventory becomes RUNTIME findings with
   * proper cveId / packageName / fixVersion / cvssScore.
   */
  vulnerabilitiesIngested: number;
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
  vdFetcher: VulnerabilityStateFetcher = defaultVulnerabilityStateFetcher,
): Promise<IngestRunSummary> {
  if (!config.WAZUH_API_URL) {
    return {
      enabled:          false,
      reason:           "WAZUH_API_URL not configured — runtime ingestion disabled",
      agentsConsidered: 0,
      agentsPolled:     0,
      alertsIngested:   0,
      vulnerabilitiesIngested: 0,
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
    vulnerabilitiesIngested: 0,
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

      // Vulnerability state sweep — only when the indexer is configured
      // (modern Wazuh 4.13+; the legacy manager path doesn't expose VD).
      // VD docs are PER-PACKAGE state, not time-series alerts, so we
      // always pull the full agent inventory; dedup by stable fingerprint
      // means re-pulling the same 26 vulns just refreshes lastSeen.
      if (config.WAZUH_INDEXER_URL) {
        try {
          const vdDocs = await vdFetcher(agent.wazuhAgentId);
          summary.vulnerabilitiesIngested += vdDocs.length;
          if (vdDocs.length > 0) {
            const vdTouched = await ingestVulnerabilitiesForAgent(agent.id, agent.orgId, vdDocs);
            summary.findingsTouched += vdTouched;
          }
        } catch (err) {
          // VD failure shouldn't kill the alert-ingest path for the same
          // agent — operators may have alerts working but VD disabled.
          summary.errors.push(`agent ${agent.wazuhAgentId} VD: ${(err as Error).message}`);
        }
      }

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

    // Phase 28 enrichment — extract threat-hunting attributes from the
    // representative alert so the Findings UI can render rich columns
    // (attacker IP, process, user, MITRE, host) without forcing the
    // operator to dig into rawOutput.alerts[].
    //
    // All of these are best-effort: not every Wazuh rule populates them.
    // The UI handles missing fields gracefully (renders "—").
    const evidence = extractRuntimeEvidence(rep, bucketAlerts);

    // Upsert by unique fingerprint — same key → same Finding row updated.
    const existing = await prisma.finding.findUnique({ where: { fingerprint } });
    if (existing) {
      const previousAlerts = Array.isArray((existing.rawOutput as { alerts?: unknown })?.alerts)
        ? ((existing.rawOutput as { alerts: unknown[] }).alerts)
        : [];
      // Merge evidence — keep the most-recent attacker context (from `rep`)
      // but bump occurrence + lastSeen counts.
      const previousEvidence = (existing.evidence as Record<string, unknown> | null) ?? {};
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
          evidence: {
            ...previousEvidence,
            ...evidence,
            // Cumulative occurrence count: sum of prior + this bucket.
            occurrencesTotal:
              ((previousEvidence["occurrencesTotal"] as number | undefined) ?? 0) +
              bucketAlerts.length,
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
          evidence: {
            ...evidence,
            occurrencesTotal: bucketAlerts.length,
          },
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

// ── Threat-hunting evidence extraction ───────────────────────────────────
//
// Pulls structured fields out of a Wazuh alert that map to the standard
// "what / where / who / how / why-it-matters" forensic dimensions.
//
// Shape rules:
//   - Top-level fields are the FLAT, most-queried attributes — these
//     are what the Findings table renders as columns and what the
//     Findings filter chips key off (attackerIp, processId, etc).
//   - Nested groups (`geo`, `mitre`, `compliance`, `vulnerability`,
//     `processTree`, `http`, `audit`, `detection`) carry the richer
//     drill-down structure for the drawer's "Threat Hunt" panel.
//   - Every field is optional and best-effort. Different Wazuh rule
//     classes populate different fields:
//       web-server  → http.*, attackerIp, geo.*
//       audit       → process.*, processTree.*, audit.*
//       syscheck    → file*
//       VD          → vulnerability.*
//       all rules   → mitre.*, compliance.*, detection.*
//   - The UI renders "—" for missing fields so partial population is
//     fine; the goal is "capture everything that's there", not
//     "synthesize what's missing".
//
// Bound the JSON: aggregate fields (attackerIps[]) cap at 10 entries,
// nested arrays cap at the same. A single Finding row's evidence
// shouldn't exceed ~5KB even for high-traffic rules.
function extractRuntimeEvidence(
  rep:     WazuhAlert,
  bucket:  WazuhAlert[],
): Record<string, unknown> {
  const r = rep as Record<string, unknown>;
  const data     = (r["data"]     as Record<string, unknown> | undefined) ?? {};
  const proc     = (data["process"] as Record<string, unknown> | undefined)
                    ?? (r["process"]    as Record<string, unknown> | undefined)
                    ?? {};
  const syscheck = r["syscheck"] as Record<string, unknown> | undefined;
  const audit    = data["audit"]   as Record<string, unknown> | undefined;
  const geo      = r["GeoLocation"] as Record<string, unknown> | undefined;
  const vuln     = r["vulnerability"] as Record<string, unknown> | undefined;
  const ruleRaw  = (r["rule"] as Record<string, unknown> | undefined) ?? {};
  const mitreObj = ruleRaw["mitre"] as Record<string, unknown> | undefined;
  const decoder  = r["decoder"]   as Record<string, unknown> | undefined;
  const manager  = r["manager"]   as Record<string, unknown> | undefined;
  const cluster  = r["cluster"]   as Record<string, unknown> | undefined;
  const predec   = r["predecoder"] as Record<string, unknown> | undefined;
  const agent    = r["agent"]     as Record<string, unknown> | undefined;

  // Aggregate distinct attacker IPs + countries across the bucket —
  // operators care when a single rule fires from many IPs (broad scan)
  // vs one IP (targeted attack). Cap to 10 to keep JSON bounded.
  //
  // Wazuh puts srcip in different paths per rule class:
  //   audit / network rules:       a.srcip       (top-level)
  //   web-accesslog rules:         a.data.srcip  (nested under data)
  //   sshd / firewall rules:       a.src_ip      (with underscore)
  // Read all three, prefer top-level when present.
  const distinctIps       = new Set<string>();
  const distinctCountries = new Set<string>();
  for (const a of bucket) {
    const ad = a["data"] as Record<string, unknown> | undefined;
    const ip = (a["src_ip"] as string | undefined)
              ?? (a["srcip"]  as string | undefined)
              ?? (ad?.["srcip"] as string | undefined);
    if (ip) distinctIps.add(ip);
    const ageo = a["GeoLocation"] as Record<string, unknown> | undefined;
    const country = ageo?.["country_name"] as string | undefined;
    if (country) distinctCountries.add(country);
  }

  // Privilege escalation signal — ruid != euid means a setuid binary
  // ran. Common in container escapes. Cheap to compute, useful to
  // surface as a flag in the UI.
  const ruid = proc["ruid"] as number | string | undefined;
  const euid = proc["euid"] as number | string | undefined;
  const privEscalated =
    ruid !== undefined && euid !== undefined && String(ruid) !== String(euid);

  return {
    // ── FLAT TOP-LEVEL (most-queried, drives filter chips + columns) ──
    // Wazuh's per-rule-class field locations vary; read all three so
    // web-accesslog (data.srcip), audit (top-level srcip), and sshd
    // (top-level src_ip) all populate the same flat field.
    attackerIp:      (r["src_ip"] as string | undefined)
                      ?? (r["srcip"]  as string | undefined)
                      ?? (data["srcip"] as string | undefined) ?? null,
    attackerIpCount: distinctIps.size,
    attackerIps:     [...distinctIps].slice(0, 10),
    destIp:          (data["dstip"] as string | undefined) ?? null,
    destPort:        (data["dstport"] as string | undefined) ?? null,
    srcPort:         (data["srcport"] as string | undefined) ?? null,
    userAgent:       (data["user_agent"] as string | undefined)
                      ?? (r["user_agent"] as string | undefined) ?? null,

    processId:       proc["pid"]     ?? null,
    processName:     proc["name"]    ?? proc["exe"] ?? null,
    processCommand:  proc["cmdline"] ?? proc["command"] ?? data["command"] ?? null,
    parentProcessId: proc["parent"]  ?? proc["ppid"]    ?? null,
    workingDir:      data["cwd"]     ?? null,

    user: (r["dstuser"] as string | undefined)
            ?? (data["dstuser"] as string | undefined)
            ?? (data["user"] as string | undefined)
            ?? (r["srcuser"] as string | undefined) ?? null,

    filePath:      syscheck?.["path"] ?? null,
    fileHash:      syscheck?.["sha256_after"] ?? syscheck?.["sha1_after"] ?? syscheck?.["md5_after"] ?? null,
    fileEvent:     syscheck?.["event"] ?? null,
    fileSizeAfter: syscheck?.["size_after"] ?? null,

    wazuhRuleId:    rep.rule.id,
    wazuhRuleLevel: rep.rule.level,
    wazuhAgentName: rep.agent_name,
    wazuhAgentId:   rep.agent_id,
    location:       rep.location ?? null,
    fullLog:        rep.full_log ?? null,

    occurrencesInBucket: bucket.length,
    firstAlertAt:        bucket[0]?.timestamp ?? null,
    latestAlertAt:       bucket[bucket.length - 1]?.timestamp ?? null,

    // ── NESTED GROUPS (drill-down for the drawer) ───────────────────

    // Geographic enrichment from Wazuh's MaxMind integration. Country +
    // city are the high-signal fields; lat/lon enables map widgets.
    // Cap distinctCountries to 5 — beyond that "this rule fires from
    // everywhere" is the takeaway.
    geo: geo ? {
      country:   geo["country_name"] ?? null,
      city:      geo["city_name"]    ?? null,
      region:    geo["region_name"]  ?? null,
      latitude:  (geo["location"] as Record<string, unknown> | undefined)?.["lat"] ?? null,
      longitude: (geo["location"] as Record<string, unknown> | undefined)?.["lon"] ?? null,
      distinctCountries: [...distinctCountries].slice(0, 5),
    } : null,

    // Full MITRE mapping — IDs, tactics, technique names. The flat
    // `references` array on Finding gets the IDs alone (for legacy
    // compatibility); this captures the readable tactic + technique.
    mitre: (rep.rule.mitre_ids?.length || mitreObj) ? {
      ids:        rep.rule.mitre_ids ?? (mitreObj?.["id"] as string[] | undefined) ?? [],
      tactics:    (mitreObj?.["tactic"]    as string[] | undefined) ?? [],
      techniques: (mitreObj?.["technique"] as string[] | undefined) ?? [],
    } : null,

    // Compliance framework mappings — each finding can claim coverage
    // under PCI-DSS / GDPR / HIPAA / NIST / SOC 2 controls. Big for
    // procurement: "show me all findings tagged PCI-DSS 6.5".
    compliance: hasComplianceMappings(ruleRaw) ? {
      pci_dss:     (ruleRaw["pci_dss"]     as string[] | undefined) ?? [],
      gdpr:        (ruleRaw["gdpr"]        as string[] | undefined) ?? [],
      hipaa:       (ruleRaw["hipaa"]       as string[] | undefined) ?? [],
      nist_800_53: (ruleRaw["nist_800_53"] as string[] | undefined) ?? [],
      tsc:         (ruleRaw["tsc"]         as string[] | undefined) ?? [],
    } : null,

    // Wazuh's Vulnerability Detector module — when active, reports CVE
    // findings on the host's installed packages. Overlaps with our
    // CONTAINER scanner findings (same CVE → bridge edge candidate).
    vulnerability: vuln ? {
      cve:            vuln["cve"] ?? null,
      cvss3Score:     ((vuln["cvss"] as Record<string, unknown> | undefined)?.["cvss3"] as Record<string, unknown> | undefined)?.["base_score"] ?? null,
      packageName:    (vuln["package"] as Record<string, unknown> | undefined)?.["name"] ?? null,
      packageVersion: (vuln["package"] as Record<string, unknown> | undefined)?.["version"] ?? null,
      severity:       vuln["severity"] ?? null,
      status:         vuln["status"]   ?? null,
      title:          vuln["title"]    ?? null,
      published:      vuln["published"] ?? null,
      updated:        vuln["updated"]  ?? null,
    } : null,

    // Process tree for audit-rule findings — shows parent → child
    // lineage and the privilege-escalation signal. The drawer renders
    // this as a "apache → bash → id" chain.
    processTree: (proc["pid"] || proc["name"]) ? {
      pid:           proc["pid"]     ?? null,
      name:          proc["name"]    ?? proc["exe"] ?? null,
      executable:    proc["exe"]     ?? null,
      cmdline:       proc["cmdline"] ?? proc["command"] ?? null,
      parent:        proc["parent"]  ?? null,
      parentName:    proc["parent_name"] ?? null,
      ppid:          proc["ppid"]    ?? null,
      ruid:          ruid ?? null,
      euid:          euid ?? null,
      privEscalated,
    } : null,

    // HTTP forensics for web-rule findings — full request context.
    http: (data["url"] || data["user_agent"]) ? {
      url:        data["url"] ?? null,
      method:     data["method"] ?? data["protocol"] ?? null,
      statusCode: data["id"] ?? null,
      referrer:   data["referrer"] ?? null,
      userAgent:  data["user_agent"] ?? null,
      tld:        data["tld"] ?? null,
    } : null,

    // Audit-rule details — captures the audit subsystem's own fields
    // (audit type EXECVE/OPEN/CONNECT, audit key, session ID).
    audit: audit ? {
      type:    audit["type"]    ?? null,
      key:     audit["key"]     ?? null,
      session: audit["session"] ?? null,
      success: audit["success"] ?? null,
    } : null,

    // Detection metadata — rule-engine internals. Useful for tuning
    // ("rule 31151 fires 200x/day; let's review it") and for
    // multi-cluster deployments where it matters which manager fired.
    detection: {
      ruleId:       rep.rule.id,
      ruleLevel:    rep.rule.level,
      groups:       rep.rule.groups ?? [],
      frequency:    ruleRaw["frequency"] ?? null,
      firedTimes:   ruleRaw["firedtimes"] ?? null,
      decoder:      decoder?.["name"] ?? null,
      manager:      manager?.["name"] ?? null,
      cluster:      cluster?.["name"] ?? null,
      predecoder:   predec?.["program_name"] ?? null,
      agentLabels:  (agent?.["labels"] as Record<string, unknown> | undefined) ?? null,
    },
  };
}

/** True when at least one compliance framework array has entries — keeps
 *  empty `compliance: {}` blocks out of evidence for rules that don't
 *  carry framework mappings. */
function hasComplianceMappings(rule: Record<string, unknown>): boolean {
  for (const key of ["pci_dss", "gdpr", "hipaa", "nist_800_53", "tsc"]) {
    const v = rule[key];
    if (Array.isArray(v) && v.length > 0) return true;
  }
  return false;
}

// ── Backfill ────────────────────────────────────────────────────────────
//
// One-shot re-extraction across every RUNTIME finding whose `evidence`
// column is missing/empty. Works because we already preserve the raw
// Wazuh alerts in `rawOutput.alerts[]` (capped at 200 per finding) —
// running them back through extractRuntimeEvidence reconstructs the
// rich threat-hunt fields the original ingest didn't capture.
//
// Idempotent: subsequent calls only touch findings whose evidence is
// still empty. Safe to re-run after deploys.

export interface BackfillResult {
  considered: number;
  updated:    number;
  skipped:    number;
  errors:     string[];
}

export async function backfillRuntimeEvidence(): Promise<BackfillResult> {
  const result: BackfillResult = {
    considered: 0,
    updated:    0,
    skipped:    0,
    errors:     [],
  };

  // Load every RUNTIME finding lacking evidence. Prisma's JSON null
  // semantics are tricky — `equals: null` matches the JSON literal
  // `null`, not SQL NULL — so use Prisma.AnyNull (or DbNull) to catch
  // both. Then we additionally filter the {} case in JS.
  const allRuntime = await prisma.finding.findMany({
    where: { scanType: "RUNTIME" },
    select: { id: true, rawOutput: true, evidence: true },
  });
  const candidates = allRuntime.filter((f) => {
    if (f.evidence === null || f.evidence === undefined) return true;
    if (typeof f.evidence === "object" && Object.keys(f.evidence as object).length === 0) return true;
    return false;
  });
  result.considered = candidates.length;

  for (const f of candidates) {
    try {
      const raw = f.rawOutput as { alerts?: unknown[] } | null;
      const alerts = (raw?.alerts ?? []) as WazuhAlert[];
      if (alerts.length === 0) {
        result.skipped++;
        continue;
      }
      const rep = alerts[alerts.length - 1] ?? alerts[0]!;
      const evidence = extractRuntimeEvidence(rep, alerts);
      await prisma.finding.update({
        where: { id: f.id },
        data: {
          evidence: {
            ...evidence,
            occurrencesTotal: alerts.length,
          },
        },
      });
      result.updated++;
    } catch (err) {
      const msg = (err as Error).message;
      result.errors.push(`${f.id}: ${msg}`);
    }
  }

  return result;
}

// ── Wazuh REST client ─────────────────────────────────────────────────────

export type AlertsFetcher = (
  wazuhAgentId: string,
  sinceIso:     string,
) => Promise<WazuhAlert[]>;

/**
 * Production fetcher — Wazuh 4.x architecture:
 *   - Manager API (port 55000, JWT auth) → agent management, config status
 *   - **Indexer API (port 9200, basic auth) → alerts** ← what we need here
 *
 * Routing rule: if `WAZUH_INDEXER_URL` is configured, query the indexer
 * directly (the modern + correct path). Otherwise fall back to the
 * legacy manager-passthrough endpoint, which works on older Wazuh
 * deployments where the manager proxied indexer queries — but Wazuh
 * 4.13+ doesn't expose that route, so the fallback returns an empty
 * array on modern stacks.
 *
 * The two paths return the same OpenSearch hit shape, so the rest of
 * the ingest pipeline doesn't care which one fired.
 */
async function defaultAlertsFetcher(wazuhAgentId: string, sinceIso: string): Promise<WazuhAlert[]> {
  const client = config.WAZUH_INDEXER_URL
    ? await getIndexerClient()
    : await getWazuhClient();

  const path = config.WAZUH_INDEXER_URL
    ? `/wazuh-alerts-*/_search`
    : `/security/events/_search`;

  const response = await client.post(
    path,
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

// ── Vulnerability state ingestion (Wazuh 4.13+ VD module) ────────────────
//
// Wazuh 4.13 retired the manager API path `/vulnerability/<id>` (returns
// 404 even with valid auth) and now writes the VD module's per-package
// CVE inventory directly to OpenSearch indices named
// `wazuh-states-vulnerabilities-<cluster_name>`. Each doc represents ONE
// (agent, package, CVE) tuple — not a time-series alert.
//
// Doc shape (Wazuh schema 1.0.0):
//   agent.{id,name,version}
//   host.os.{full,kernel,name,platform,type,version}
//   package.{architecture,description,name,size,type,version}
//   vulnerability.{id, severity, score.{base,version}, scanner.condition,
//                  fix.versions[], description, reference, detected_at,
//                  published_at, classification, enumeration, category,
//                  under_evaluation}
//
// Ingestion model:
//   - Fingerprint = SHA-256(orgId|wazuhAgentId|cveId|packageName|packageVersion)
//     so the same vuln on the same agent ends up in the same Finding row
//     across polls. Re-running the sweep just bumps lastSeen.
//   - severity, cveId, packageName, packageVersion, fixVersion, cvssScore,
//     references all flow into the typed Finding columns — operators get
//     the same drill-down they have for Trivy CONTAINER findings.
//   - confidence = LIKELY (one notch above POSSIBLE since the package is
//     observed installed on a running host, vs. potentially-unused base
//     image layers in a container scan).
//   - When the agent is operator-linked to a Container, Finding.containerId
//     is populated so the Reachability drawer surfaces these as BOTH /
//     RUNTIME_ONLY tier rows alongside the Trivy image scan.

export interface WazuhVulnerabilityDoc {
  agent: { id: string; name?: string };
  host?: {
    os?: { full?: string; name?: string; platform?: string; version?: string };
  };
  package?: {
    name?:    string;
    version?: string;
    architecture?: string;
    type?:    string;
    description?: string;
  };
  vulnerability: {
    id:           string;
    severity?:    string;
    description?: string;
    reference?:   string;
    detected_at?: string;
    published_at?: string;
    classification?: string;
    score?:       { base?: number; version?: string };
    fix?:         { versions?: string[] };
    scanner?:     { condition?: string; reference?: string; source?: string; vendor?: string };
  };
}

export type VulnerabilityStateFetcher = (
  wazuhAgentId: string,
) => Promise<WazuhVulnerabilityDoc[]>;

/**
 * Pulls VD state for a single agent from the indexer. Paginates via
 * `search_after` so we can scale past the default 10k window if an
 * agent has unusually many vulns. Cap at 5k per sweep to bound JSON
 * size — operators with denser inventories can rerun more frequently.
 */
async function defaultVulnerabilityStateFetcher(
  wazuhAgentId: string,
): Promise<WazuhVulnerabilityDoc[]> {
  if (!config.WAZUH_INDEXER_URL) return [];
  const client = await getIndexerClient();

  const collected: WazuhVulnerabilityDoc[] = [];
  let searchAfter: unknown[] | null = null;
  // Hard cap protects the API process from a runaway agent — 5k vulns is
  // already excessive for any single workload; an operator hitting this
  // wall has a bigger inventory hygiene issue.
  const HARD_CAP = 5000;

  while (collected.length < HARD_CAP) {
    const body: Record<string, unknown> = {
      size:  500,
      query: { term: { "agent.id": wazuhAgentId } },
      sort:  [{ "vulnerability.detected_at": "asc" }, { _id: "asc" }],
    };
    if (searchAfter) body["search_after"] = searchAfter;

    const response = await client.post(`/wazuh-states-vulnerabilities-*/_search`, body);
    const hits = (response.data?.hits?.hits ?? []) as Array<{
      _source: Record<string, unknown>;
      sort?:   unknown[];
    }>;
    if (hits.length === 0) break;

    for (const hit of hits) {
      // Cast through unknown — _source is a generic Record<string, unknown>
      // while WazuhVulnerabilityDoc has typed nested fields. The
      // structural fields we read are runtime-validated by the
      // `src?.vulnerability?.id` guard below before we trust the doc.
      const src = hit._source as unknown as WazuhVulnerabilityDoc;
      if (src?.vulnerability?.id) collected.push(src);
    }
    if (hits.length < 500) break;
    searchAfter = hits[hits.length - 1]!.sort ?? null;
    if (!searchAfter) break;
  }

  return collected;
}

/**
 * Wazuh `vulnerability.severity` strings → BreachLens Severity enum.
 * Wazuh emits "Critical" | "High" | "Medium" | "Low" | "Untriaged" (or
 * empty); we fold Untriaged/empty to LOW so the row still appears but
 * doesn't dominate the dashboard.
 */
function mapVdSeverity(s: string | undefined): Severity {
  switch ((s ?? "").toUpperCase()) {
    case "CRITICAL": return "CRITICAL";
    case "HIGH":     return "HIGH";
    case "MEDIUM":   return "MEDIUM";
    case "LOW":      return "LOW";
    default:         return "INFO";
  }
}

/**
 * Parse a fix-version hint out of `vulnerability.scanner.condition` when
 * `fix.versions[]` is empty. Wazuh's Debian feed populates `condition`
 * as e.g. "Package less than 3.5.5-1~deb13u2" — extract the version
 * after the keyword.
 */
function extractFixVersion(vd: WazuhVulnerabilityDoc["vulnerability"]): string | null {
  const fromVersions = vd.fix?.versions?.[0];
  if (fromVersions) return fromVersions;
  const cond = vd.scanner?.condition ?? "";
  const m = cond.match(/(?:less than|<=?|>=?|equal to|equals)\s*([\w.\-+~:]+)/i);
  return m ? m[1]! : null;
}

// ── MITRE synthesis on VD findings ───────────────────────────────────────
//
// Wazuh's VD module doesn't tag CVEs with MITRE ATT&CK — but the dashboard
// MITRE-tactic chart reads `evidence.mitre.tactics[]` on every RUNTIME
// finding to compute its bars, so VD findings without MITRE are invisible
// to the chart. We classify them with a small heuristic over the CVE
// description + CVSS score.
//
// Coverage hierarchy (first match wins):
//   1. RCE / arbitrary code execution     → Execution + Initial Access
//   2. Privilege escalation                → Privilege Escalation
//   3. Auth bypass / credential disclosure → Credential Access
//   4. SSRF / SQL injection / XSS / IDOR   → Initial Access (web vector)
//   5. Denial of service / crash           → Impact
//   6. Default for CVSS ≥ 7                → Initial Access (network attack)
//   7. Otherwise                           → no tactics (chart skips it)
//
// Every classification carries `synthesized: true` so the UI can mark
// these as "(inferred from CVE)" — the operator can tell at a glance
// whether MITRE on a row came from Wazuh detection (event evidence) or
// our heuristic (state inference). Event-only predicates
// (runtime-attack / runtime-exploit / activeAttacks24h) explicitly skip
// scanner=wazuh-vd findings so synthesized MITRE doesn't contaminate
// attack counters.
//
// Calibration corpus: openssl + libssl + ngtcp2 CVEs from Debian 13
// agent c0263b172aab (the dev-cluster's only linked agent). This is a
// deliberately conservative classifier — false negatives default to "no
// MITRE", which is honest, rather than over-tagging things as Initial
// Access. Operators can refine the rules as new CVE description shapes
// surface; the regex blocks below are the single source of truth.

interface SynthesisedMitre {
  tactics:     string[];
  techniques:  string[];
  synthesized: true;
  basis:       string;  // short human-readable why-this-classification
}

function vulnToMitre(v: WazuhVulnerabilityDoc["vulnerability"]): SynthesisedMitre | null {
  const desc  = (v.description ?? "").toLowerCase();
  const score = typeof v.score?.base === "number" ? v.score.base : 0;

  // 1. RCE / arbitrary code execution. Hits openssl heap-overflow
  //    "attacker controlled code execution", BIND remote-RCE, etc.
  if (/\b(remote\s+code\s+execution|rce|arbitrary\s+code|attacker[ -]?controlled\s+code|command\s+injection)\b/i.test(desc)) {
    return {
      tactics:     ["Execution", "Initial Access"],
      techniques:  ["T1203", "T1190"],
      synthesized: true,
      basis:       "RCE keyword in CVE description",
    };
  }

  // 2. Privilege escalation. "local privilege escalation", "privesc".
  if (/\bprivilege[ -]?escalat(?:ion|ed|e)|local\s+privilege|privesc\b/i.test(desc)) {
    return {
      tactics:     ["Privilege Escalation"],
      techniques:  ["T1068"],
      synthesized: true,
      basis:       "Privilege escalation in CVE description",
    };
  }

  // 3. Auth bypass / credential disclosure / password recovery.
  if (/\b(authentication\s+bypass|auth(?:n|z)?[ -]?bypass|credential[s]?\s+(?:disclosure|theft|leak)|password\s+(?:disclosure|recovery)|hardcoded\s+credential)\b/i.test(desc)) {
    return {
      tactics:     ["Credential Access"],
      techniques:  ["T1078"],
      synthesized: true,
      basis:       "Credential / auth-bypass in CVE description",
    };
  }

  // 4. Web-vector classics — SSRF, SQLi, XSS, IDOR, path traversal,
  //    deserialization. All map to Initial Access via T1190 (Exploit
  //    Public-Facing Application).
  if (/\b(ssrf|server[ -]?side\s+request|sql\s+injection|sqli|cross[ -]?site\s+scripting|xss|idor|insecure\s+direct\s+object|path\s+traversal|directory\s+traversal|deserialization|unsafe\s+deserialization|xxe|xml\s+external\s+entity)\b/i.test(desc)) {
    return {
      tactics:     ["Initial Access"],
      techniques:  ["T1190"],
      synthesized: true,
      basis:       "Web-vector class (SSRF/SQLi/XSS/etc.) in description",
    };
  }

  // 5. Denial of service / crash — Impact, not Initial Access.
  //    Heap-overflow "may lead to a crash" is ambiguous (could be RCE),
  //    so we order rule 1 before this so RCE wins when both keywords appear.
  if (/\b(denial[ -]?of[ -]?service|\bdos\b|crash|hang|infinite\s+loop)\b/i.test(desc)) {
    return {
      tactics:     ["Impact"],
      techniques:  ["T1499"],
      synthesized: true,
      basis:       "DoS / crash in CVE description",
    };
  }

  // 6. CVSS-score fallback. ≥7 base score on a network-reachable CVE
  //    almost always represents an Initial Access opportunity even when
  //    the description doesn't use any of the keywords above.
  if (score >= 7.0) {
    return {
      tactics:     ["Initial Access"],
      techniques:  ["T1190"],
      synthesized: true,
      basis:       `High CVSS (${score.toFixed(1)}) — default Initial Access`,
    };
  }

  // 7. Below-threshold + no keyword match — leave unclassified rather
  //    than synthesise a wrong tactic. Honest "we don't know" beats a
  //    false-precise label.
  return null;
}

async function ingestVulnerabilitiesForAgent(
  agentRowId: string,
  orgId:      string,
  docs:       WazuhVulnerabilityDoc[],
): Promise<number> {
  if (docs.length === 0) return 0;

  // Mirror ingestAlertsForAgent's container-linking + ScanJob-reuse
  // pattern so VD findings land on the same canonical RUNTIME ScanJob
  // row as Wazuh alerts (they describe the same workload).
  const agentRow = await prisma.workloadAgent.findUnique({
    where:  { id: agentRowId },
    select: { linkedContainerId: true, wazuhAgentId: true, wazuhAgentName: true },
  });
  if (!agentRow) return 0;
  const linkedContainerId = agentRow.linkedContainerId ?? null;

  let scanJob = await prisma.scanJob.findFirst({
    where: {
      orgId,
      targetType:  "CONTAINER",
      containerId: linkedContainerId,
      scanTypes:   { has: "RUNTIME" },
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
  }

  let touched = 0;
  for (const doc of docs) {
    const v   = doc.vulnerability;
    const pkg = doc.package ?? {};
    const cveId          = v.id;
    const packageName    = pkg.name ?? null;
    const packageVersion = pkg.version ?? null;
    const fixVersion     = extractFixVersion(v);
    const cvssScore      = typeof v.score?.base === "number" ? v.score.base : null;
    const severity       = mapVdSeverity(v.severity);

    // Stable fingerprint — same (agent, package, CVE) → same Finding row.
    const fingerprint = sha256(
      `${orgId}|${doc.agent.id}|${cveId}|${packageName ?? ""}|${packageVersion ?? ""}`,
    );

    const title       = `${cveId} in ${packageName ?? "unknown"}${packageVersion ? "@" + packageVersion : ""}`;
    const description =
      v.description?.slice(0, 1000) ??
      `Wazuh VD detected ${cveId} on ${doc.agent.name ?? doc.agent.id}.`;

    // Synthesize MITRE classification from CVE description + CVSS so VD
    // findings show up in the dashboard's tactic chart. `synthesized: true`
    // marks these as inferred (vs. observed); event-only predicates skip
    // scanner=wazuh-vd findings so this never contaminates attack
    // counters (see findingTags.hasActiveAttack + runtime/dashboard).
    const synthesized = vulnToMitre(v);

    const evidence: Record<string, unknown> = {
      source:       "wazuh-vd",
      agentId:      doc.agent.id,
      agentName:    doc.agent.name,
      package:      pkg,
      hostOs:       doc.host?.os,
      vulnerability: {
        cveId,
        severity:    v.severity,
        cvssScore,
        cvssVersion: v.score?.version,
        fixVersion,
        condition:   v.scanner?.condition,
        feedSource:  v.scanner?.source,
        reference:   v.reference,
        detectedAt:  v.detected_at,
        publishedAt: v.published_at,
      },
      ...(synthesized ? { mitre: synthesized } : {}),
    };

    const references: string[] = [];
    if (v.reference)         references.push(v.reference);
    if (v.scanner?.reference) references.push(v.scanner.reference);
    // Surface MITRE technique IDs as references too — the existing
    // FindingDetailDrawer renders any "MITRE ATT&CK <T-id>" reference
    // as a clickable link to attack.mitre.org/techniques/<id>.
    for (const t of synthesized?.techniques ?? []) {
      references.push(`MITRE ATT&CK ${t}`);
    }

    const existing = await prisma.finding.findUnique({ where: { fingerprint } });
    if (existing) {
      await prisma.finding.update({
        where: { id: existing.id },
        data: {
          lastSeen: new Date(),
          // Severity / fix version can shift as Wazuh's CVE feed updates;
          // refresh them on every poll so the operator sees current state.
          severity,
          cvssScore,
          fixVersion,
          evidence,
          // Refresh the references list (synthesized MITRE T-codes shift
          // with classifier updates). Preserve operator status
          // (ACKNOWLEDGED, FALSE_POSITIVE, FIXED) — never auto-revert
          // to OPEN on re-ingest.
          references,
        },
      });
    } else {
      await prisma.finding.create({
        data: {
          orgId,
          scanJobId:   scanJob.id,
          targetType:  "CONTAINER",
          containerId: linkedContainerId,
          scanType:    "RUNTIME",
          title,
          description,
          severity,
          cveId,
          packageName,
          packageVersion,
          fixVersion,
          cvssScore,
          scanner:     "wazuh-vd",
          ruleId:      cveId,
          fingerprint,
          confidence:  "LIKELY",
          rawOutput:   { source: "wazuh-vd", doc: doc as unknown as Record<string, unknown> },
          evidence,
          references,
        },
      });
    }
    touched++;
  }

  logger.info(
    `[wazuh-vd] agent ${agentRow.wazuhAgentId}: ingested ${docs.length} doc(s), touched ${touched} finding(s)`,
  );
  return touched;
}

let cachedIndexerClient: AxiosInstance | null = null;

async function getIndexerClient(): Promise<AxiosInstance> {
  if (cachedIndexerClient) return cachedIndexerClient;
  if (!config.WAZUH_INDEXER_URL || !config.WAZUH_INDEXER_USER || !config.WAZUH_INDEXER_PASSWORD) {
    throw new Error(
      "WAZUH_INDEXER_URL + WAZUH_INDEXER_USER + WAZUH_INDEXER_PASSWORD required when querying alerts via the indexer",
    );
  }
  // OpenSearch / Wazuh indexer uses HTTP Basic Auth on every request —
  // no JWT, no token refresh.
  cachedIndexerClient = axios.create({
    baseURL: config.WAZUH_INDEXER_URL,
    timeout: 15_000,
    auth: {
      username: config.WAZUH_INDEXER_USER,
      password: config.WAZUH_INDEXER_PASSWORD,
    },
    ...(config.WAZUH_INSECURE_TLS
      ? { httpsAgent: new HttpsAgent({ rejectUnauthorized: false }) }
      : {}),
  });
  return cachedIndexerClient;
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

// ── Phase 28 Slice B — operator-facing agent discovery ───────────────────
//
// The ingestion sweep (above) only polls agents already enrolled into
// `WorkloadAgent`. Discovery is the inverse: ask the Wazuh manager which
// agents *exist*, and surface them so the operator can link each one to a
// Container in BreachLens.
//
// Idempotent: re-running discovery upserts on (orgId, wazuhAgentId) and
// preserves the operator's `linkedContainerId` choice. Discovery does NOT
// remove agents that have left the Wazuh manager — that's a destructive
// op that should be operator-confirmed via DELETE /api/runtime/agents/:id.

export interface DiscoveredAgent {
  wazuhAgentId:   string;
  wazuhAgentName: string;
  status:         "HEALTHY" | "STALE" | "OFFLINE" | "UNKNOWN";
  agentVersion:   string | null;
}

export interface DiscoverResult {
  enabled:    boolean;
  reason?:    string;
  discovered: DiscoveredAgent[];
  upserted:   number;  // rows we touched in WorkloadAgent
}

/**
 * Pull the agent list from the Wazuh manager and upsert WorkloadAgent
 * rows for the given org. Returns the discovered list so the UI can
 * render "found N agents" feedback.
 *
 * Skips agent ID "000" (Wazuh's manager-self entry — never useful as a
 * runtime monitoring target).
 */
export async function discoverWazuhAgents(orgId: string): Promise<DiscoverResult> {
  if (!config.WAZUH_API_URL) {
    return {
      enabled:    false,
      reason:     "WAZUH_API_URL not configured — runtime discovery disabled",
      discovered: [],
      upserted:   0,
    };
  }

  const client = await getWazuhClient();
  // Wazuh's /agents response: { data: { affected_items: [...] } }. Each
  // item has id, name, status ("active"|"disconnected"|"never_connected"|
  // "pending"), version, lastKeepAlive, etc.
  const response = await client.get(`/agents`, {
    params: { limit: 500 }, // sane upper bound; pagination can come later
  });
  const items = (response.data?.data?.affected_items ?? []) as Array<Record<string, unknown>>;

  const discovered: DiscoveredAgent[] = [];
  for (const item of items) {
    const wazuhAgentId = String(item["id"] ?? "");
    if (!wazuhAgentId || wazuhAgentId === "000") continue; // skip manager-self
    const wazuhAgentName = String(item["name"] ?? wazuhAgentId);
    const wazuhStatus    = String(item["status"] ?? "").toLowerCase();
    const status: DiscoveredAgent["status"] =
      wazuhStatus === "active"       ? "HEALTHY"
      : wazuhStatus === "pending"    ? "STALE"
      : wazuhStatus === "disconnected" || wazuhStatus === "never_connected" ? "OFFLINE"
      : "UNKNOWN";
    const agentVersion = item["version"] ? String(item["version"]) : null;

    discovered.push({ wazuhAgentId, wazuhAgentName, status, agentVersion });

    await prisma.workloadAgent.upsert({
      where: { orgId_wazuhAgentId: { orgId, wazuhAgentId } },
      // On create: stamp every column. On update: keep the operator's
      // linkedContainerId choice; only refresh status / version / name
      // (in case the agent was renamed in Wazuh).
      create: {
        orgId,
        wazuhAgentId,
        wazuhAgentName,
        status,
        agentVersion,
      },
      update: {
        wazuhAgentName,
        status,
        agentVersion,
      },
    });
  }

  return {
    enabled:    true,
    discovered,
    upserted:   discovered.length,
  };
}
