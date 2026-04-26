import { Worker } from "bullmq";
import axios from "axios";
import { bullRedis } from "../redis.js";
import { config } from "../config.js";
import { logger } from "../logger.js";
import prisma from "../db.js";
import { upsertFindings, countBySeverity } from "../services/findingService.js";
import { aiTriageQueue, scanQueues } from "../queues/definitions.js";
import { emitStatusChange, emitFindingsBatch } from "../services/sseService.js";
import { decrypt } from "../services/encryptionService.js";
import type { ScanJobPayload } from "../queues/definitions.js";
import type { NormalizedFinding, ScanType, TargetType } from "@devsecops/types";
import type { ScanResult } from "@devsecops/types";
import { notifyNewFindings } from "../services/notificationService.js";
import { backfillSnippetsForScanJob } from "../services/sastSnippetService.js";
import { generateScanSummary } from "../services/scanSummaryService.js";
import { scoreTarget } from "../services/riskScoringService.js";
import { generateTargetReport } from "../services/reportHtmlService.js";
import { resolvePolicy, evaluatePolicy } from "../services/policyService.js";
import { markInProgress as markCheckInProgress, completeCheck } from "../services/prCheckService.js";
import { extractApiSpecUrls } from "../services/openApiUrlExtractor.js";

const SCAN_TYPES: ScanType[] = ["SAST", "SCA", "SECRET", "IAC", "CONTAINER", "DAST", "PENTEST", "PENTEST_FULL"];

async function processScanJob(payload: ScanJobPayload) {
  const { scanJobId, orgId, targetType, targetId, scanType, encryptedGitToken } = payload;

  logger.info("Processing scan job", { scanJobId, scanType, targetType });

  // Mark ScanJob as RUNNING on first job processed
  const job = await prisma.scanJob.findUnique({ where: { id: scanJobId } });
  if (job?.status === "PENDING") {
    await prisma.scanJob.update({
      where: { id: scanJobId },
      data: { status: "RUNNING", startedAt: new Date() },
    });
    emitStatusChange(scanJobId, "RUNNING");
    // Transition the GitHub Check Run (if any) to in_progress
    markCheckInProgress(scanJobId).catch((err) =>
      logger.warn("prCheck in-progress failed", { err: (err as Error).message })
    );
  }

  // Decrypt git token if present (never log)
  let gitToken: string | undefined;
  if (encryptedGitToken) {
    try {
      gitToken = decrypt(encryptedGitToken);
    } catch {
      logger.error("Failed to decrypt git token", { scanJobId });
    }
  }

  // Decrypt domain auth config if present (DAST / PENTEST scans only)
  let authConfig: Record<string, unknown> | null = null;
  if (targetType === "DOMAIN" && payload.domainAuthConfigId) {
    try {
      const cfg = await prisma.domainAuthConfig.findUnique({
        where: { id: payload.domainAuthConfigId },
      });
      if (cfg) {
        const creds = JSON.parse(decrypt(cfg.encryptedCreds)) as Record<string, string>;
        authConfig = {
          auth_type:        cfg.authType,
          login_url:        cfg.loginUrl        ?? null,
          username_field:   cfg.usernameField,
          password_field:   cfg.passwordField,
          username:         creds["username"]   ?? null,
          password:         creds["password"]   ?? null,
          logged_in_pattern:  cfg.loggedInPattern,
          logged_out_pattern: cfg.loggedOutPattern,
          header_name:      cfg.headerName      ?? null,
          header_value:     creds["headerValue"] ?? null,
          // OAuth2 fields — secret (clientSecret) from encrypted blob, non-secrets from DB
          oauth2_token_url:    cfg.oauth2TokenUrl    ?? null,
          oauth2_client_id:    cfg.oauth2ClientId    ?? null,
          oauth2_client_secret: creds["clientSecret"] ?? null,
          oauth2_scope:        cfg.oauth2Scope       ?? null,
          oauth2_grant_type:   cfg.oauth2GrantType   ?? "client_credentials",
          // CSRF tracking — passed to crawler payload by the scanner. Null
          // values mean "no CSRF tracking", crawler skips the prime/refresh.
          csrf_meta_selector:  cfg.csrfMetaSelector  ?? null,
          csrf_cookie_name:    cfg.csrfCookieName    ?? null,
          csrf_header_name:    cfg.csrfHeaderName    ?? null,
        };
      }
    } catch (err) {
      logger.error("Failed to decrypt domain auth config", { scanJobId, error: (err as Error).message });
    }
  }

  // Extract API spec URLs from imported OpenAPI/Swagger spec (DAST & PENTEST_FULL only).
  // Heavy lifting (per-operation enumeration, type-aware param substitution,
  // server-URL resolution) lives in `openApiUrlExtractor` so the worker stays
  // focused on dispatch.
  let apiSpecUrls: string[] = [];
  if (targetType === "DOMAIN" && payload.domain && ["DAST", "PENTEST_FULL", "PENTEST"].includes(scanType)) {
    try {
      const spec = await prisma.domainApiSpec.findUnique({ where: { domainId: targetId } });
      if (spec?.specJson) {
        const { urls, operations } = extractApiSpecUrls(spec.specJson, payload.domain);
        apiSpecUrls = urls;
        logger.info(
          `OpenAPI spec: ${urls.length} URL(s) from ${operations} operation(s)`,
          { scanJobId },
        );
      }
    } catch (err) {
      logger.warn("Failed to extract OpenAPI spec URLs", { scanJobId, error: (err as Error).message });
    }
  }

  // Build scanner request payload
  const scanRequest = {
    scan_job_id: scanJobId,
    org_id: orgId,
    target_id: targetId,
    scan_type: scanType,
    target_type: targetType,
    repo_url: payload.repoUrl,
    branch: payload.branch,
    git_token: gitToken, // decrypted, sent over internal Docker network
    image_ref: payload.imageRef,
    domain: payload.domain,
    selected_subdomains: payload.selectedSubdomains ?? [],
    pentest_depth: payload.pentestDepth ?? "STANDARD",
    auth_config: authConfig,  // decrypted, sent over internal Docker network only
    api_spec_urls: apiSpecUrls,
    // "Promote recording to Full Pentest" plumbing — when set, the scanner's
    // PENTEST_FULL orchestrator skips Playwright and pulls URLs from the live
    // ZAP context. Harmless for other scan types (ignored by the Pydantic model).
    recording_context_name: payload.recordingContextName,
    recording_target_url:   payload.recordingTargetUrl,
    // Internal callback so scanner can report phase progress via SSE
    api_url: config.API_INTERNAL_URL ?? null,
    // Tier 1 — incremental scanning (empty = full-tree scan)
    changed_files:    payload.changedFiles    ?? [],
    commit_sha:       payload.commitSha       ?? null,
    base_commit_sha:  payload.baseCommitSha   ?? null,
    pr_number:        payload.prNumber        ?? null,
  };

  // Route PENTEST_FULL to the dedicated pentest scanner if configured
  const scannerUrl =
    scanType === "PENTEST_FULL" && config.SCANNER_PENTEST_URL
      ? config.SCANNER_PENTEST_URL
      : config.SCANNER_URL;

  // Call Python scanner service. DAST scans tied to a recording session skip
  // the full /scan pipeline — they re-scan an existing ZAP context populated
  // by browser proxy traffic, so we POST to /dast/recording/scan with the
  // recorded context info. Interactive provenance is signalled by the
  // presence of `recordingContextName` on the payload, NOT by scanType.
  let result: ScanResult;
  try {
    const isInteractive =
      scanType === "DAST" && Boolean(payload.recordingContextName);
    const endpoint = isInteractive ? "/dast/recording/scan" : "/scan";
    const body = isInteractive
      ? {
          ...scanRequest,
          contextId:   payload.recordingContextId,
          contextName: payload.recordingContextName,
          targetUrl:   payload.recordingTargetUrl,
        }
      : scanRequest;
    // Per-scan-type axios timeout. Pentest runs legitimately exceed an hour
    // (ZAP active + Nuclei + Nikto + sqlmap + Dalfox across 50+ URLs at
    // AGGRESSIVE depth). DAST can reach ~45 min; everything else is quick.
    // These numbers MUST be <= the corresponding worker `lockDuration` below.
    const timeoutMs =
      scanType === "PENTEST_FULL"    ? 7_200_000 : // 2 h
      scanType === "DAST"            ? 3_600_000 : // 1 h (covers interactive)
                                       1_800_000;  // 30 min (SAST/SCA/SECRET/IAC/CONTAINER)
    const response = await axios.post<ScanResult>(
      `${scannerUrl}${endpoint}`,
      body,
      { timeout: timeoutMs },
    );
    result = response.data;
  } catch (err) {
    const msg = (err as Error).message;
    logger.error("Scanner service call failed", { scanJobId, scanType, error: msg });
    result = {
      scanJobId,
      scanType,
      scanner: scanType.toLowerCase(),
      success: false,
      findings: [],
      error: msg,
      durationMs: 0,
    };
  }

  // Surface scanner-side exceptions: when the FastAPI handler catches an
  // exception inside scan(), it returns success=false with an error string
  // but HTTP 200. Without this we'd silently mark the ScanJob COMPLETED with
  // 0 findings and no diagnostic — the failure mode that hid the DVWA DAST
  // ZAP timeout for 13 minutes.
  //
  // Append the failed scanType to ScanJob.failedScanTypes so the diff endpoint
  // can exclude it (a 0-finding failed DAST scan must NOT make prior DAST
  // findings appear "removed/fixed") and the finalize step can promote the
  // parent status from COMPLETED → FAILED if every sub-scan failed.
  if (!result.success) {
    logger.error("Scanner reported failure", {
      scanJobId,
      scanType,
      error: result.error ?? "(no error message)",
      durationMs: result.durationMs,
    });
    // Use a raw SQL append to avoid a read-modify-write race when multiple
    // scan-type workers finish in parallel. array_append is idempotent in
    // practice because each scanType only runs once per ScanJob.
    await prisma.$executeRaw`
      UPDATE "ScanJob"
      SET "failedScanTypes" = array_append("failedScanTypes", ${scanType}::"ScanType")
      WHERE "id" = ${scanJobId}
    `.catch((err: Error) =>
      logger.error("Failed to append failedScanTypes", { scanJobId, scanType, error: err.message })
    );
  }

  // Persist the in-scope URL list captured by the scanner. PENTEST_FULL
  // (crawler_urls.txt) and DAST-recording scans return a populated list;
  // other scan types return []. We persist EVEN empty arrays so the diff
  // endpoint can distinguish "scanner ran but reported no URL surface"
  // (empty) from "URL list never captured" (null) — without this, the
  // scope-aware classification was silently falling back to the legacy
  // "treat everything as in-scope" path for every scan whose write got
  // skipped, defeating the whole purpose of the column.
  //
  // Merge with whatever's already on the ScanJob row so a multi-scan-type
  // job (e.g. PENTEST_FULL + DAST) doesn't have one type clobber the
  // other's URL list. Capped at 5000 to bound the JSON column size.
  //
  // The diagnostic log up front exists because previously several
  // PENTEST_FULL scans completed without populating this column even
  // though the scanner produced a 50+ URL crawler_urls.txt — we want the
  // raw response shape on every run so future regressions are immediately
  // visible without DB archaeology.
  try {
    const incoming = Array.isArray(result.targetUrls) ? result.targetUrls : [];
    logger.info("[targetUrls] received from scanner", {
      scanJobId, scanType,
      count: incoming.length,
      isArray: Array.isArray(result.targetUrls),
      rawType: typeof result.targetUrls,
    });
    const existing = await prisma.scanJob.findUnique({
      where: { id: scanJobId },
      select: { targetUrls: true },
    });
    const prior: string[] = Array.isArray(existing?.targetUrls)
      ? (existing!.targetUrls as unknown as string[])
      : [];
    const merged = Array.from(new Set([...prior, ...incoming])).slice(0, 5000);
    await prisma.scanJob.update({
      where: { id: scanJobId },
      data:  { targetUrls: merged },
    });
    if (merged.length > 0) {
      logger.info("[targetUrls] persisted in-scope URL list", {
        scanJobId, scanType, count: merged.length, addedThisType: incoming.length,
      });
    }
  } catch (err) {
    logger.warn("[targetUrls] failed to persist URL list", {
      scanJobId, scanType, error: (err as Error).message,
    });
  }

  // Store findings and auto-fix any that disappeared since the last scan
  let newCount = 0;
  if (result.success) {
    const upsertResult = await upsertFindings({
      scanJobId,
      orgId,
      targetType: targetType as TargetType,
      targetId,
      scanType: scanType as ScanType,
      findings: result.findings as unknown as NormalizedFinding[],
    });
    newCount = upsertResult.newCount;

    logger.info("Findings upsert summary", {
      scanJobId,
      scanType,
      new:       upsertResult.newCount,
      confirmed: upsertResult.confirmedCount,
      fixed:     upsertResult.fixedCount,
      total:     upsertResult.totalCount,
    });

    if (upsertResult.fixedCount > 0) {
      logger.info("Auto-fixed resolved findings", { scanJobId, scanType, fixedCount: upsertResult.fixedCount });
    }

    // Backfill SAST snippets from GitHub when Semgrep returned nothing usable.
    // Fire-and-forget: we don't want a slow GitHub API round to delay scan
    // completion or AI triage enqueue. Errors are swallowed inside the service.
    if (scanType === "SAST" && targetType === "REPOSITORY") {
      backfillSnippetsForScanJob({ scanJobId, repositoryId: targetId })
        .then((r) => {
          if (r.updatedFindings > 0 || r.updatedLocations > 0) {
            logger.info("[sast-snippet] backfilled from GitHub", {
              scanJobId,
              updatedFindings:  r.updatedFindings,
              updatedLocations: r.updatedLocations,
            });
          }
        })
        .catch((err: Error) =>
          logger.warn("[sast-snippet] backfill failed", { scanJobId, error: err.message })
        );
    }

    // Enqueue AI triage for newly discovered findings (fire-and-forget)
    // Priority: CRITICAL=1 … INFO=5 so critical findings are triaged first
    const TRIAGE_PRIORITY: Record<string, number> = {
      CRITICAL: 1, HIGH: 2, MEDIUM: 3, LOW: 4, INFO: 5,
    };
    if (upsertResult.newFindings.length > 0) {
      const triageJobs = upsertResult.newFindings.map((f) => ({
        name:    "triage",
        data:    { findingId: f.id, scanType: f.scanType, severity: f.severity },
        opts:    {
          priority: TRIAGE_PRIORITY[f.severity] ?? 5,
          jobId:    `triage-${f.id}`,  // dedup: same finding never queued twice
        },
      }));
      aiTriageQueue.addBulk(triageJobs).catch((err: Error) =>
        logger.warn("Failed to enqueue AI triage jobs", { error: err.message })
      );
      logger.info(`[ai-triage] queued ${triageJobs.length} triage jobs`, { scanJobId, scanType });
    }

    if (result.findings.length > 0) {
      const breakdown = countBySeverity(result.findings as unknown as NormalizedFinding[]);
      emitFindingsBatch(scanJobId, scanType, result.findings.length, breakdown);
    }
  }

  // If the scan was cancelled while the scanner was running, bail out
  const currentStatus = await prisma.scanJob.findUnique({
    where: { id: scanJobId },
    select: { status: true },
  });
  if (currentStatus?.status === "CANCELLED") {
    logger.info("Scan job was cancelled — skipping completion", { scanJobId, scanType });
    return;
  }

  // Increment completedScans counter
  const updated = await prisma.scanJob.update({
    where: { id: scanJobId },
    data: {
      completedScans: { increment: 1 },
    },
    select: {
      completedScans: true,
      totalScans: true,
      status: true,
    },
  });

  // If all scans complete, finalize ScanJob
  if (updated.completedScans >= updated.totalScans) {
    // Aggregate severity counts for findings OBSERVED by this scan — i.e. either
    // first-seen or re-confirmed within this scan's time window. Strict
    // `scanJobId` equality undercounts because upsertFindings preserves the
    // *original* scanJobId when a fingerprint is re-observed, so re-confirmed
    // findings would not show up on subsequent scan rows.
    //
    // Pull failedScanTypes too so finalize can decide between COMPLETED,
    // COMPLETED-with-warnings, and fully FAILED.
    const jobRow = await prisma.scanJob.findUniqueOrThrow({
      where: { id: scanJobId },
      select: {
        orgId: true, targetType: true, scanTypes: true, startedAt: true,
        repositoryId: true, containerId: true, domainId: true,
        failedScanTypes: true,
      },
    });
    const windowStart = jobRow.startedAt ?? new Date(0);
    const windowEnd   = new Date();
    const targetFilter =
      jobRow.targetType === "REPOSITORY" ? { repositoryId: jobRow.repositoryId }
      : jobRow.targetType === "CONTAINER" ? { containerId: jobRow.containerId }
      : { domainId: jobRow.domainId };
    // Only count severities for scan types that DIDN'T fail — a failed DAST
    // sub-scan returns 0 findings, but those zero findings shouldn't push the
    // dashboard counts down for that target.
    const successfulScanTypes = jobRow.scanTypes.filter(
      (t) => !jobRow.failedScanTypes.includes(t)
    );
    const counts = successfulScanTypes.length === 0
      ? []
      : await prisma.finding.groupBy({
          by: ["severity"],
          where: {
            orgId:    jobRow.orgId,
            scanType: { in: successfulScanTypes },
            ...targetFilter,
            lastSeen: { gte: windowStart, lte: windowEnd },
          },
          _count: true,
        });
    const severityCounts: Record<string, number> = {};
    for (const c of counts) {
      severityCounts[c.severity] = c._count;
    }

    // Decide finalize status:
    //   - all sub-scans failed         → FAILED (with error summary)
    //   - some sub-scans failed        → COMPLETED + error string listing them
    //                                    (the user still has partial results)
    //   - none failed                  → COMPLETED, no error
    const failed = jobRow.failedScanTypes;
    const allFailed     = failed.length > 0 && failed.length === jobRow.scanTypes.length;
    const partialFailed = failed.length > 0 && failed.length < jobRow.scanTypes.length;
    const finalStatus: "COMPLETED" | "FAILED" = allFailed ? "FAILED" : "COMPLETED";
    const finalError =
      allFailed     ? `All scan types failed: ${failed.join(", ")}` :
      partialFailed ? `Partial failure: ${failed.join(", ")} did not complete (other scan types succeeded)` :
                      null;

    await prisma.scanJob.update({
      where: { id: scanJobId },
      data: {
        status: finalStatus,
        completedAt: new Date(),
        ...(finalError ? { error: finalError } : {}),
        criticalCount: severityCounts["CRITICAL"] ?? 0,
        highCount: severityCounts["HIGH"] ?? 0,
        mediumCount: severityCounts["MEDIUM"] ?? 0,
        lowCount: severityCounts["LOW"] ?? 0,
        infoCount: severityCounts["INFO"] ?? 0,
      },
    });

    // Update target's lastScannedAt — even on partial failure we still touched
    // the target. Skip only when EVERY sub-scan failed (no useful data).
    if (!allFailed) {
      if (targetType === "REPOSITORY") {
        await prisma.repository.update({ where: { id: targetId }, data: { lastScannedAt: new Date() } });
      } else if (targetType === "CONTAINER") {
        await prisma.container.update({ where: { id: targetId }, data: { lastScannedAt: new Date() } });
      } else if (targetType === "DOMAIN") {
        await prisma.domain.update({ where: { id: targetId }, data: { lastScannedAt: new Date() } });
      }
    }

    emitStatusChange(scanJobId, finalStatus, {
      criticalCount: severityCounts["CRITICAL"] ?? 0,
      highCount: severityCounts["HIGH"] ?? 0,
      ...(finalError ? { error: finalError } : {}),
    });

    // ── Policy evaluation + GitHub Check Run completion ─────────────────
    // Only for PR-triggered scans; fire-and-forget so check failures don't
    // block the rest of the finalize path (notifications, risk scoring, etc).
    (async () => {
      try {
        const prCheck = await prisma.prCheckRun.findUnique({ where: { scanJobId } });
        if (!prCheck || !jobRow.repositoryId) return;

        const repo = await prisma.repository.findUnique({
          where: { id: jobRow.repositoryId },
          select: { policyId: true, orgId: true },
        });
        if (!repo) return;

        const policy = await resolvePolicy(repo.orgId, jobRow.repositoryId, repo.policyId);
        const findings = await prisma.finding.findMany({
          where: { ...targetFilter, orgId: jobRow.orgId, lastSeen: { gte: windowStart } },
        });
        const baseCommitDate = prCheck.createdAt; // approximation — PR base commit time
        const evaluation = evaluatePolicy(policy, findings, {
          scanTypesRun: jobRow.scanTypes,
          baseCommitDate,
        });
        await completeCheck(scanJobId, findings, evaluation);
      } catch (err) {
        logger.error("prCheck finalize failed", {
          scanJobId, err: (err as Error).message,
        });
      }
    })();

    // If this was an interactive recording scan (DAST seeded from a ZAP
    // recording context, or PENTEST_FULL promoted from a recording),
    // mark the linked RecordingSession with the matching terminal status so
    // the UI clears the SCANNING state. Detected via payload, not scanType.
    if (payload.recordingSessionId) {
      await prisma.recordingSession.updateMany({
        where: { scanJobId, status: { in: ["SCANNING", "ACTIVE"] } },
        data:  allFailed
          ? { status: "FAILED", endedAt: new Date(), errorMessage: finalError ?? "scan failed" }
          : { status: "COMPLETED", endedAt: new Date() },
      }).catch(() => {/* non-fatal */});
    }

    // Send Slack/Teams alerts for new CRITICAL/HIGH findings
    const alertableFindings = await prisma.finding.findMany({
      where: {
        scanJobId,
        severity: { in: ["CRITICAL", "HIGH"] },
        // Only findings first seen in this scan job (within last 5 minutes)
        firstSeen: { gte: new Date(Date.now() - 5 * 60 * 1000) },
      },
    });
    if (alertableFindings.length > 0) {
      notifyNewFindings(orgId, alertableFindings).catch((err) =>
        logger.error("Notification dispatch failed", { error: (err as Error).message })
      );
    }

    logger.info("Scan job finalized", {
      scanJobId,
      finalStatus,
      failedScanTypes: failed,
      totalFindings: result.findings.length,
    });

    // The AI summary / risk score / HTML report are derived from findings — if
    // every sub-scan failed there are no fresh findings to summarise, and
    // running these would either produce a misleading "looks clean!" report or
    // re-use stale findings from prior scans. Skip them on full failure.
    if (!allFailed) {
      // Fire-and-forget AI scan summary (non-blocking)
      generateScanSummary(scanJobId).catch(() => {/* already logged inside */});

      // Fire-and-forget AI risk score for the scanned target (non-blocking)
      scoreTarget(targetType as TargetType, targetId).catch(() => {/* already logged inside */});

      // Fire-and-forget HTML security report — ON_SCAN_COMPLETE trigger
      generateTargetReport(scanJobId).catch(() => {/* already logged inside */});
    }
  }
}

// Module-level registry so closeWorkers() can drain every active worker on
// shutdown. Without this each scan-type worker would leak its Redis
// connection + lock on the next SIGTERM, producing the stalled-job pattern
// that has cancelled three scans in a single day.
const _activeWorkers: Worker<ScanJobPayload>[] = [];

export function initWorkers() {
  for (const scanType of SCAN_TYPES) {
    const worker = new Worker<ScanJobPayload>(
      `scan-${scanType}`,
      async (job) => {
        await processScanJob(job.data);
      },
      {
        connection: bullRedis,
        concurrency: 2,
        // Per-scan-type lock duration. BullMQ marks a job stalled if the
        // worker hasn't renewed its lock within this window; default 30s
        // would kill any DAST/pentest run instantly. Values match the axios
        // timeouts set in the scanner call above, plus 5 min of head-room
        // for result processing (findingService upserts, notifications).
        //
        //   Pentest (ZAP+Nuclei+Nikto+sqlmap+Dalfox, AGGRESSIVE, 50+ URLs): 2 h 5 min
        //   DAST crawl or interactive replay:                              1 h 5 min
        //   Everything else (SAST/SCA/SECRET/IAC/CONTAINER):               35 min
        lockDuration:
          scanType === "PENTEST_FULL" ? 7_500_000 :
          scanType === "DAST"         ? 3_900_000 :
                                        2_100_000,
        // Jobs that stall twice are terminal — re-delivery means duplicate
        // scanner work (two Nuclei processes against the same target) which
        // is worse than just failing cleanly. Default is 1; keep it but
        // be explicit so future readers don't wonder.
        maxStalledCount: 1,
      }
    );
    _activeWorkers.push(worker);

    worker.on("failed", async (job, err) => {
      if (!job) return;
      logger.error("Scan job failed", { jobId: job.id, scanType, error: err.message });
      const { scanJobId } = job.data;
      await prisma.scanJob.update({
        where: { id: scanJobId },
        data: { status: "FAILED", error: err.message, completedAt: new Date() },
      }).catch(() => {});
      // Release the linked recording session so the UI clears. Any interactive
      // run (DAST or PENTEST_FULL) carries `recordingSessionId` on its payload.
      if (job.data.recordingSessionId) {
        await prisma.recordingSession.updateMany({
          where: { scanJobId, status: { in: ["SCANNING", "ACTIVE"] } },
          data:  { status: "FAILED", endedAt: new Date(), errorMessage: err.message },
        }).catch(() => {});
      }
      emitStatusChange(scanJobId, "FAILED", { error: err.message });
    });

    // Stalled = lock expired before the worker reported completion. With
    // maxStalledCount=1 (set above), this is terminal: re-delivery would
    // spawn a second scanner run against the same target. The most common
    // cause in dev is `tsx watch` SIGKILL'ing the Node process mid-scan;
    // in prod it's container restart, OOM, or an upstream network blip.
    //
    // We can't recover the in-flight scanner result (the `await axios.post`
    // died with the worker), but we can mark the ScanJob terminal so it
    // (a) stops permanently blocking fp-sweep's idle window, and (b) the
    // user sees a clear, actionable failure instead of a perpetual RUNNING
    // row that needs manual DB surgery to clear.
    //
    // BullMQ job IDs are deterministic: `<scanJobId>-<scanType>` (set by
    // the scan-trigger route), so we can recover scanJobId from the
    // jobId without a DB lookup against bullJobIds.
    worker.on("stalled", async (jobId, prev) => {
      logger.error("[scan] job stalled — marking ScanJob CANCELLED", {
        jobId, scanType, prevState: prev,
      });
      const suffix = `-${scanType}`;
      const scanJobId = jobId.endsWith(suffix) ? jobId.slice(0, -suffix.length) : null;
      if (!scanJobId) {
        logger.warn("[scan] stalled jobId did not match expected format", { jobId, scanType });
        return;
      }
      await prisma.scanJob.update({
        where: { id: scanJobId },
        data: {
          status:      "CANCELLED",
          completedAt: new Date(),
          error: `Worker stalled mid-${scanType}: lock expired before completion (likely tsx hot-reload, container restart, or process kill). Re-run the scan to retry.`,
        },
      }).catch((err: Error) => logger.warn("[scan] failed to mark stalled scan CANCELLED", {
        scanJobId, scanType, error: err.message,
      }));
      emitStatusChange(scanJobId, "CANCELLED", { error: `Worker stalled mid-${scanType}` });
    });
  }

  logger.info("BullMQ workers started for all scan types");
}

/** Drain all scan workers and release their Redis locks. Called from the
 *  server's SIGTERM/SIGINT handler so jobs that were mid-processing release
 *  cleanly instead of stalling on the next start.
 *
 *  In dev (`tsx watch`), this is mostly aspirational — tsx SIGKILLs after
 *  a short SIGTERM grace, so we may not finish the close. The startup
 *  reaper (`reapOrphanScans`) is the real safety net for that case. */
export async function closeWorkers(): Promise<void> {
  logger.info(`[scan] closing ${_activeWorkers.length} scan worker(s)…`);
  await Promise.all(_activeWorkers.map((w) => w.close().catch(() => {})));
  _activeWorkers.length = 0;
  logger.info("[scan] all scan workers closed");
}

/**
 * Reap orphan ScanJobs on API startup.
 *
 * BullMQ workers don't survive a hard process kill (SIGKILL by tsx-watch
 * on hot-reload, container restart, OOM). When that happens the ScanJob
 * row stays in PENDING/RUNNING forever — fp-sweep then permanently skips
 * its idle window because it sees an "active scan" that no worker is
 * actually processing.
 *
 * On every startup we look for non-terminal ScanJobs older than 30s
 * (skip fresh inserts the new workers might be about to dequeue), then
 * cross-check BullMQ for an active/waiting/delayed job linked to each.
 * If BullMQ has nothing live, the row is orphaned and we mark it
 * CANCELLED with a clear, user-actionable error message.
 *
 * The 30s grace window matters: without it, scans inserted in the brief
 * gap between server boot and worker start would be killed before they
 * had a chance to run.
 */
export async function reapOrphanScans(): Promise<void> {
  const cutoff = new Date(Date.now() - 30_000);
  const orphans = await prisma.scanJob.findMany({
    where: {
      status:    { in: ["PENDING", "RUNNING"] },
      createdAt: { lt: cutoff },
    },
    select: { id: true, status: true, scanTypes: true, bullJobIds: true },
  });
  if (orphans.length === 0) {
    logger.info("[scan-reap] no orphan scans on startup");
    return;
  }
  logger.warn(`[scan-reap] found ${orphans.length} non-terminal scan(s) on startup — checking BullMQ for liveness`);

  const reaped: string[] = [];
  for (const scan of orphans) {
    // bullJobIds shape: { "PENTEST_FULL": "<scanId>-PENTEST_FULL", ... }
    const ids = (scan.bullJobIds ?? {}) as Record<string, string>;
    let stillLive = false;
    for (const scanType of Object.keys(ids)) {
      const queue = scanQueues[scanType as ScanType];
      if (!queue) continue;
      const job = await queue.getJob(ids[scanType]!).catch(() => null);
      if (!job) continue;
      const state = await job.getState().catch(() => null);
      if (state === "active" || state === "waiting" || state === "delayed") {
        stillLive = true;
        break;
      }
    }
    if (stillLive) {
      logger.info(`[scan-reap] scan ${scan.id} still live in BullMQ — leaving alone`);
      continue;
    }
    await prisma.scanJob.update({
      where: { id: scan.id },
      data: {
        status:      "CANCELLED",
        completedAt: new Date(),
        error: "Reaped on API startup: worker died (process killed during scan, likely tsx hot-reload or container restart). Re-run the scan to retry.",
      },
    }).catch((err: Error) =>
      logger.warn("[scan-reap] failed to mark orphan CANCELLED", { scanJobId: scan.id, error: err.message })
    );
    emitStatusChange(scan.id, "CANCELLED", { error: "Reaped on startup" });
    reaped.push(scan.id);
  }
  logger.warn(`[scan-reap] cancelled ${reaped.length} orphan scan(s)`, { reaped });
}
