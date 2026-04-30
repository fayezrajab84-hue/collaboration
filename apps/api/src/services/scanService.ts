import prisma from "../db.js";
import { scanQueues, type ScanJobPayload } from "../queues/definitions.js";
import { decrypt } from "./encryptionService.js";
import { createQueuedCheck } from "./prCheckService.js";
import { logger } from "../logger.js";
import type { ScanType } from "@devsecops/types";

type ScanTrigger = "MANUAL" | "PUSH" | "PULL_REQUEST" | "SCHEDULED";

interface TriggerScanOptions {
  orgId: string;
  // Phase 29 — adds CLOUD_ACCOUNT (Slice A) + GITHUB_ACCOUNT (Slice C1).
  targetType: "REPOSITORY" | "CONTAINER" | "DOMAIN" | "CLOUD_ACCOUNT" | "GITHUB_ACCOUNT";
  targetId: string;
  scanTypes: ScanType[];
  repoUrl?: string;
  branch?: string;
  encryptedGitToken?: string;
  imageRef?: string;
  domain?: string;
  selectedSubdomains?: string[];
  pentestDepth?: "QUICK" | "STANDARD" | "AGGRESSIVE";
  domainAuthConfigId?: string;
  // Interactive provenance — recorded ZAP context to active-scan against
  recordingContextId?: string;
  recordingContextName?: string;
  recordingTargetUrl?: string;
  recordingSessionId?: string;
  // Tier 1 — PR / incremental
  triggerType?:   ScanTrigger;
  commitSha?:     string;
  baseCommitSha?: string;
  prNumber?:      number;
  changedFiles?:  string[];
}

export async function triggerScan(opts: TriggerScanOptions) {
  const { orgId, targetType, targetId, scanTypes } = opts;

  // Create parent ScanJob
  const scanJob = await prisma.scanJob.create({
    data: {
      orgId,
      targetType,
      repositoryId:   targetType === "REPOSITORY"     ? targetId : null,
      containerId:    targetType === "CONTAINER"      ? targetId : null,
      domainId:       targetType === "DOMAIN"         ? targetId : null,
      // Phase 29 — CSPM target FK (Slice A).
      cloudAccountId:  targetType === "CLOUD_ACCOUNT"  ? targetId : null,
      // Phase 29 Slice C1 — GitHub posture target FK.
      githubAccountId: targetType === "GITHUB_ACCOUNT" ? targetId : null,
      scanTypes,
      totalScans: scanTypes.length,
      completedScans: 0,
      status: "PENDING",
      triggerType:   opts.triggerType   ?? "MANUAL",
      commitSha:     opts.commitSha     ?? null,
      baseCommitSha: opts.baseCommitSha ?? null,
      branch:        opts.branch        ?? null,
      prNumber:      opts.prNumber      ?? null,
      changedFiles:  opts.changedFiles  ?? [],
    },
  });

  const bullJobIds: Record<string, string> = {};

  // Enqueue one BullMQ job per scan type
  for (const scanType of scanTypes) {
    const payload: ScanJobPayload = {
      scanJobId: scanJob.id,
      orgId,
      targetType,
      targetId,
      scanType,
      repoUrl: opts.repoUrl,
      branch: opts.branch,
      encryptedGitToken: opts.encryptedGitToken,
      imageRef: opts.imageRef,
      domain: opts.domain,
      selectedSubdomains: opts.selectedSubdomains,
      pentestDepth: opts.pentestDepth,
      domainAuthConfigId: opts.domainAuthConfigId,
      recordingContextId:   opts.recordingContextId,
      recordingContextName: opts.recordingContextName,
      recordingTargetUrl:   opts.recordingTargetUrl,
      recordingSessionId:   opts.recordingSessionId,
      changedFiles:         opts.changedFiles,
      commitSha:            opts.commitSha,
      baseCommitSha:        opts.baseCommitSha,
      prNumber:             opts.prNumber,
    };

    const queue = scanQueues[scanType];
    if (!queue) throw new Error(`No queue for scan type: ${scanType}`);
    const job = await queue.add(`${scanType}-${scanJob.id}`, payload, {
      jobId: `${scanJob.id}-${scanType}`,
    });
    bullJobIds[scanType] = job.id ?? "";
  }

  // Store BullMQ job IDs
  await prisma.scanJob.update({
    where: { id: scanJob.id },
    data: { bullJobIds },
  });

  // ── PR check run — register a queued GitHub check as soon as a PR scan fires
  // Fire-and-forget: GitHub App may not be configured or repo may not have the
  // App installed; prCheckService handles both cases silently.
  if (
    opts.triggerType === "PULL_REQUEST" &&
    opts.prNumber &&
    opts.commitSha &&
    opts.baseCommitSha &&
    targetType === "REPOSITORY"
  ) {
    const repo = await prisma.repository.findUnique({
      where: { id: targetId },
      select: { githubAppInstallationId: true, fullName: true },
    });
    if (repo?.githubAppInstallationId) {
      const [owner, name] = repo.fullName.split("/");
      if (owner && name) createQueuedCheck({
        scanJobId: scanJob.id,
        repositoryId: targetId,
        installationId: repo.githubAppInstallationId,
        owner,
        repo: name,
        prNumber: opts.prNumber,
        headSha:  opts.commitSha,
        baseSha:  opts.baseCommitSha,
      }).catch((err) => logger.warn("prCheck create failed", { err: (err as Error).message }));
    }
  }

  return {
    scanJobId: scanJob.id,
    status: "PENDING" as const,
    scanTypes,
  };
}
