/**
 * One-time migration: merge per-location SAST findings into one
 * finding per ruleId per target — matching the new mergeSastFindings() logic.
 *
 * Run: docker exec admiring-hertz-api-1 node --import tsx/esm \
 *        /app/apps/api/src/migrations/mergeSastFindings.ts
 */

import { createHash } from "crypto";
import prisma from "../db.js";
import { logger } from "../logger.js";

const SEV_RANK: Record<string, number> = { CRITICAL: 0, HIGH: 1, MEDIUM: 2, LOW: 3, INFO: 4 };

function ruleFingerprint(orgId: string, targetId: string, ruleId: string): string {
  return createHash("sha256")
    .update(`${orgId}:sast-rule:${targetId}:SAST:${ruleId}`)
    .digest("hex");
}

function highestSeverity(severities: string[]): string {
  return severities.reduce((best, s) =>
    (SEV_RANK[s] ?? 99) < (SEV_RANK[best] ?? 99) ? s : best, "INFO");
}

async function run() {
  logger.info("[merge-sast] starting SAST finding merge migration");

  const findings = await prisma.finding.findMany({
    where: { scanType: "SAST" },
    orderBy: { firstSeen: "asc" },
  });

  logger.info(`[merge-sast] ${findings.length} SAST findings to process`);

  // Group by (orgId, targetId, ruleId)
  const groups = new Map<string, typeof findings>();
  for (const f of findings) {
    const targetId = f.repositoryId ?? f.containerId ?? f.domainId ?? "unknown";
    const key = [f.orgId, targetId, f.ruleId ?? "unknown"].join("::");
    if (!groups.has(key)) groups.set(key, []);
    groups.get(key)!.push(f);
  }

  let merged = 0;
  let updated = 0;
  let skipped = 0;

  for (const group of groups.values()) {
    const rep      = group[0]!;
    const targetId = rep.repositoryId ?? rep.containerId ?? rep.domainId ?? "unknown";
    const ruleId   = rep.ruleId ?? "unknown";
    const fp       = ruleFingerprint(rep.orgId, targetId, ruleId);

    if (group.length === 1) {
      if (rep.fingerprint === fp) { skipped++; continue; }
      await prisma.finding.update({ where: { id: rep.id }, data: { fingerprint: fp } });
      updated++;
      continue;
    }

    const sortedBySev = [...group].sort(
      (a, b) => (SEV_RANK[a.severity] ?? 99) - (SEV_RANK[b.severity] ?? 99),
    );
    const topSev  = highestSeverity(group.map((f) => f.severity));
    const primary = sortedBySev[0]!;
    const others  = group.filter((f) => f.id !== primary.id);

    // Build locations array
    const locations = sortedBySev.map((f) => {
      const raw   = f.rawOutput as Record<string, unknown> | null ?? {};
      const extra = raw["extra"] as Record<string, unknown> | undefined;
      const snippet =
        (typeof extra?.["lines"] === "string" ? (extra["lines"] as string).trim() : null)
        ?? (f.codeSnippet ?? null);
      return {
        filePath:  f.filePath,
        lineStart: f.lineStart,
        lineEnd:   f.lineEnd,
        severity:  f.severity,
        message:   f.description,
        snippet,
      };
    });

    // Guard: if merged fingerprint already exists (re-run), delete this group entirely
    const existingMerged = await prisma.finding.findUnique({ where: { fingerprint: fp } });
    if (existingMerged && existingMerged.id !== primary.id) {
      await prisma.finding.deleteMany({ where: { id: { in: [primary.id, ...others.map((o) => o.id)] } } });
      merged++;
      continue;
    }

    // Delete duplicates first, then update primary
    await prisma.finding.deleteMany({ where: { id: { in: others.map((o) => o.id) } } });

    await prisma.finding.update({
      where: { id: primary.id },
      data: {
        fingerprint: fp,
        severity:    topSev as "CRITICAL" | "HIGH" | "MEDIUM" | "LOW" | "INFO",
        rawOutput:   {
          merged:    true,
          count:     group.length,
          ruleId,
          locations,
          primary:   primary.rawOutput,
        } as object,
      },
    });

    merged++;
  }

  logger.info(`[merge-sast] done — ${merged} rules merged, ${updated} fingerprints updated, ${skipped} already current`);

  const after = await prisma.finding.count({ where: { scanType: "SAST" } });
  logger.info(`[merge-sast] SAST findings: ${findings.length} → ${after}`);
}

run()
  .then(() => process.exit(0))
  .catch((err) => { console.error(err); process.exit(1); });
