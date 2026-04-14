import prisma from "../db.js";
import type { NormalizedFinding, TargetType } from "@devsecops/types";

interface UpsertOptions {
  scanJobId: string;
  orgId: string;
  targetType: TargetType;
  targetId: string;
  findings: NormalizedFinding[];
}

export async function upsertFindings(opts: UpsertOptions): Promise<{ newCount: number; totalCount: number }> {
  const { scanJobId, orgId, targetType, targetId, findings } = opts;

  if (findings.length === 0) return { newCount: 0, totalCount: 0 };

  let newCount = 0;

  for (const f of findings) {
    const data = {
      orgId,
      scanJobId,
      targetType,
      repositoryId: targetType === "REPOSITORY" ? targetId : undefined,
      containerId: targetType === "CONTAINER" ? targetId : undefined,
      domainId: targetType === "DOMAIN" ? targetId : undefined,
      scanType: f.scanType,
      title: f.title,
      description: f.description,
      severity: f.severity,
      status: "OPEN" as const,
      filePath: f.filePath ?? null,
      lineStart: f.lineStart ?? null,
      lineEnd: f.lineEnd ?? null,
      codeSnippet: f.codeSnippet ?? null,
      cveId: f.cveId ?? null,
      cweId: f.cweId ?? null,
      packageName: f.packageName ?? null,
      packageVersion: f.packageVersion ?? null,
      fixVersion: f.fixVersion ?? null,
      cvssScore: f.cvssScore ?? null,
      scanner: f.scanner,
      ruleId: f.ruleId,
      fingerprint: f.fingerprint,
      remediation: f.remediation ?? null,
      references: f.references ?? [],
      rawOutput: f.rawOutput as object,
      lastSeen: new Date(),
    };

    const result = await prisma.finding.upsert({
      where: { fingerprint: f.fingerprint },
      create: { ...data, firstSeen: new Date() },
      update: { lastSeen: new Date(), description: f.description },
    });

    // Count truly new findings (firstSeen === lastSeen within ~1 second)
    const isNew = Math.abs(result.firstSeen.getTime() - result.lastSeen.getTime()) < 2000;
    if (isNew) newCount++;
  }

  return { newCount, totalCount: findings.length };
}

export function countBySeverity(findings: NormalizedFinding[]): Record<string, number> {
  const counts: Record<string, number> = { CRITICAL: 0, HIGH: 0, MEDIUM: 0, LOW: 0, INFO: 0 };
  for (const f of findings) {
    counts[f.severity] = (counts[f.severity] ?? 0) + 1;
  }
  return counts;
}
