import { Worker } from "bullmq";
import axios from "axios";
import { bullRedis } from "../redis.js";
import { config } from "../config.js";
import { logger } from "../logger.js";
import prisma from "../db.js";
import { upsertFindings, countBySeverity } from "../services/findingService.js";
import { aiTriageQueue } from "../queues/definitions.js";
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
        };
      }
    } catch (err) {
      logger.error("Failed to decrypt domain auth config", { scanJobId, error: (err as Error).message });
    }
  }

  // Extract API spec URLs from imported OpenAPI/Swagger spec (DAST & PENTEST_FULL only)
  let apiSpecUrls: string[] = [];
  if (targetType === "DOMAIN" && payload.domain && ["DAST", "PENTEST_FULL", "PENTEST"].includes(scanType)) {
    try {
      const spec = await prisma.domainApiSpec.findUnique({ where: { domainId: targetId } });
      if (spec?.specJson) {
        const specJson = spec.specJson as Record<string, unknown>;
        const paths = (specJson.paths ?? {}) as Record<string, unknown>;

        // Resolve base URL from spec (OpenAPI 3.x servers[] or Swagger 2.x host+basePath)
        let baseUrl = `http://${payload.domain}`;
        const servers = specJson.servers as Array<{ url: string }> | undefined;
        if (servers?.length) {
          // Use first server; if relative, resolve against the domain
          const serverUrl = servers[0]!.url;
          baseUrl = serverUrl.startsWith("http") ? serverUrl : `http://${payload.domain}${serverUrl}`;
        } else if (specJson.host) {
          const scheme = (specJson.schemes as string[] | undefined)?.[0] ?? "http";
          const basePath = (specJson.basePath as string) ?? "";
          baseUrl = `${scheme}://${specJson.host}${basePath}`;
        }

        // Build a URL for each path (one per path, not per method — tools enumerate methods)
        const methods = ["get", "post", "put", "patch", "delete"];
        for (const [path, pathItem] of Object.entries(paths)) {
          const item = pathItem as Record<string, unknown>;
          const hasOp = methods.some((m) => item[m]);
          if (!hasOp) continue;
          // Replace path params with placeholder values so URLs are valid
          const concretePath = path.replace(/\{[^}]+\}/g, "1");
          apiSpecUrls.push(`${baseUrl.replace(/\/$/, "")}${concretePath}`);
        }
        logger.info(`OpenAPI spec: ${apiSpecUrls.length} endpoint URLs extracted`, { scanJobId });
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
  if (!result.success) {
    logger.error("Scanner reported failure", {
      scanJobId,
      scanType,
      error: result.error ?? "(no error message)",
      durationMs: result.durationMs,
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
    const jobRow = await prisma.scanJob.findUniqueOrThrow({
      where: { id: scanJobId },
      select: {
        orgId: true, targetType: true, scanTypes: true, startedAt: true,
        repositoryId: true, containerId: true, domainId: true,
      },
    });
    const windowStart = jobRow.startedAt ?? new Date(0);
    const windowEnd   = new Date();
    const targetFilter =
      jobRow.targetType === "REPOSITORY" ? { repositoryId: jobRow.repositoryId }
      : jobRow.targetType === "CONTAINER" ? { containerId: jobRow.containerId }
      : { domainId: jobRow.domainId };
    const counts = await prisma.finding.groupBy({
      by: ["severity"],
      where: {
        orgId:    jobRow.orgId,
        scanType: { in: jobRow.scanTypes },
        ...targetFilter,
        lastSeen: { gte: windowStart, lte: windowEnd },
      },
      _count: true,
    });
    const severityCounts: Record<string, number> = {};
    for (const c of counts) {
      severityCounts[c.severity] = c._count;
    }

    await prisma.scanJob.update({
      where: { id: scanJobId },
      data: {
        status: "COMPLETED",
        completedAt: new Date(),
        criticalCount: severityCounts["CRITICAL"] ?? 0,
        highCount: severityCounts["HIGH"] ?? 0,
        mediumCount: severityCounts["MEDIUM"] ?? 0,
        lowCount: severityCounts["LOW"] ?? 0,
        infoCount: severityCounts["INFO"] ?? 0,
      },
    });

    // Update target's lastScannedAt
    if (targetType === "REPOSITORY") {
      await prisma.repository.update({ where: { id: targetId }, data: { lastScannedAt: new Date() } });
    } else if (targetType === "CONTAINER") {
      await prisma.container.update({ where: { id: targetId }, data: { lastScannedAt: new Date() } });
    } else if (targetType === "DOMAIN") {
      await prisma.domain.update({ where: { id: targetId }, data: { lastScannedAt: new Date() } });
    }

    emitStatusChange(scanJobId, "COMPLETED", {
      criticalCount: severityCounts["CRITICAL"] ?? 0,
      highCount: severityCounts["HIGH"] ?? 0,
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
    // mark the linked RecordingSession as COMPLETED so the UI clears
    // the SCANNING state. Detected via payload, not scanType.
    if (payload.recordingSessionId) {
      await prisma.recordingSession.updateMany({
        where: { scanJobId, status: { in: ["SCANNING", "ACTIVE"] } },
        data:  { status: "COMPLETED", endedAt: new Date() },
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

    logger.info("Scan job completed", { scanJobId, totalFindings: result.findings.length });

    // Fire-and-forget AI scan summary (non-blocking)
    generateScanSummary(scanJobId).catch(() => {/* already logged inside */});

    // Fire-and-forget AI risk score for the scanned target (non-blocking)
    scoreTarget(targetType as TargetType, targetId).catch(() => {/* already logged inside */});

    // Fire-and-forget HTML security report — ON_SCAN_COMPLETE trigger
    generateTargetReport(scanJobId).catch(() => {/* already logged inside */});
  }
}

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
  }

  logger.info("BullMQ workers started for all scan types");
}
