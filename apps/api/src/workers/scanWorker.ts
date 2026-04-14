import { Worker } from "bullmq";
import axios from "axios";
import { bullRedis } from "../redis.js";
import { config } from "../config.js";
import { logger } from "../logger.js";
import prisma from "../db.js";
import { upsertFindings, countBySeverity } from "../services/findingService.js";
import { emitStatusChange, emitFindingsBatch } from "../services/sseService.js";
import { decrypt } from "../services/encryptionService.js";
import type { ScanJobPayload } from "../queues/definitions.js";
import type { NormalizedFinding, ScanType, TargetType } from "@devsecops/types";
import type { ScanResult } from "@devsecops/types";
import { notifyNewFindings } from "../services/notificationService.js";

const SCAN_TYPES: ScanType[] = ["SAST", "SCA", "SECRET", "IAC", "CONTAINER", "DAST", "PENTEST"];

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

  // Build scanner request payload
  const scanRequest = {
    scan_job_id: scanJobId,
    org_id: orgId,
    scan_type: scanType,
    target_type: targetType,
    repo_url: payload.repoUrl,
    branch: payload.branch,
    git_token: gitToken, // decrypted, sent over internal Docker network
    image_ref: payload.imageRef,
    domain: payload.domain,
  };

  // Call Python scanner service
  let result: ScanResult;
  try {
    const response = await axios.post<ScanResult>(
      `${config.SCANNER_URL}/scan`,
      scanRequest,
      { timeout: 660_000 }
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

  // Store findings
  let newCount = 0;
  if (result.success && result.findings.length > 0) {
    const upsertResult = await upsertFindings({
      scanJobId,
      orgId,
      targetType: targetType as TargetType,
      targetId,
      findings: result.findings as unknown as NormalizedFinding[],
    });
    newCount = upsertResult.newCount;

    const breakdown = countBySeverity(result.findings as unknown as NormalizedFinding[]);
    emitFindingsBatch(scanJobId, scanType, result.findings.length, breakdown);
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
  }
}

export function initWorkers() {
  for (const scanType of SCAN_TYPES) {
    const worker = new Worker<ScanJobPayload>(
      `scan:${scanType}`,
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
