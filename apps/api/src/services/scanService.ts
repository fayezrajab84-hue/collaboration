import prisma from "../db.js";
import { scanQueues, type ScanJobPayload } from "../queues/definitions.js";
import { decrypt } from "./encryptionService.js";
import type { ScanType } from "@devsecops/types";

interface TriggerScanOptions {
  orgId: string;
  targetType: "REPOSITORY" | "CONTAINER" | "DOMAIN";
  targetId: string;
  scanTypes: ScanType[];
  repoUrl?: string;
  branch?: string;
  encryptedGitToken?: string;
  imageRef?: string;
  domain?: string;
  selectedSubdomains?: string[];
  pentestDepth?: "STANDARD" | "AGGRESSIVE";
  domainAuthConfigId?: string;
}

export async function triggerScan(opts: TriggerScanOptions) {
  const { orgId, targetType, targetId, scanTypes } = opts;

  // Create parent ScanJob
  const scanJob = await prisma.scanJob.create({
    data: {
      orgId,
      targetType,
      repositoryId: targetType === "REPOSITORY" ? targetId : null,
      containerId: targetType === "CONTAINER" ? targetId : null,
      domainId: targetType === "DOMAIN" ? targetId : null,
      scanTypes,
      totalScans: scanTypes.length,
      completedScans: 0,
      status: "PENDING",
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

  return {
    scanJobId: scanJob.id,
    status: "PENDING" as const,
    scanTypes,
  };
}
