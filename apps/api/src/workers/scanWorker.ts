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
import { generateScanSummary } from "../services/scanSummaryService.js";
import { scoreTarget } from "../services/riskScoringService.js";
import { generateTargetReport } from "../services/reportHtmlService.js";

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
    // Internal callback so scanner can report phase progress via SSE
    api_url: config.API_INTERNAL_URL ?? null,
  };

  // Route PENTEST_FULL to the dedicated pentest scanner if configured
  const scannerUrl =
    scanType === "PENTEST_FULL" && config.SCANNER_PENTEST_URL
      ? config.SCANNER_PENTEST_URL
      : config.SCANNER_URL;

  // Call Python scanner service
  let result: ScanResult;
  try {
    const response = await axios.post<ScanResult>(
      `${scannerUrl}/scan`,
      scanRequest,
      { timeout: 1_500_000 } // 25 min
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

    if (upsertResult.fixedCount > 0) {
      logger.info("Auto-fixed resolved findings", { scanJobId, scanType, fixedCount: upsertResult.fixedCount });
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
    // Aggregate severity counts from all findings for this scan job
    const counts = await prisma.finding.groupBy({
      by: ["severity"],
      where: { scanJobId },
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
      emitStatusChange(scanJobId, "FAILED", { error: err.message });
    });
  }

  logger.info("BullMQ workers started for all scan types");
}
