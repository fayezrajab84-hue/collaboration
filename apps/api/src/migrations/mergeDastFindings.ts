/**
 * One-time migration: merge per-URL DAST/PENTEST/PENTEST_FULL findings into one
 * finding per ruleId per target — matching the new mergeDastFindings() logic.
 *
 * Run:
 *   docker exec admiring-hertz-api-1 node --import tsx/esm \
 *     /app/apps/api/src/migrations/mergeDastFindings.ts
 */

import { createHash } from "crypto";
import prisma from "../db.js";
import { logger } from "../logger.js";

const SEV_RANK:  Record<string, number> = { CRITICAL: 0, HIGH: 1, MEDIUM: 2, LOW: 3, INFO: 4 };
const CONF_RANK: Record<string, number> = { POSSIBLE: 0, LIKELY: 1, CONFIRMED: 2 };

function dastFingerprint(orgId: string, targetId: string, scanType: string, ruleId: string): string {
  return createHash("sha256")
    .update(`${orgId}:dast-rule:${targetId}:${scanType}:${ruleId}`)
    .digest("hex");
}

function highestSeverity(severities: string[]): string {
  return severities.reduce((best, s) =>
    (SEV_RANK[s] ?? 99) < (SEV_RANK[best] ?? 99) ? s : best, "INFO");
}

function highestConfidence(confs: (string | null)[]): string {
  return confs.reduce<string>((best, c) => {
    const v = c ?? "POSSIBLE";
    return (CONF_RANK[v] ?? 0) > (CONF_RANK[best] ?? 0) ? v : best;
  }, "POSSIBLE");
}

async function run() {
  logger.info("[merge-dast] starting DAST finding merge migration");

  const findings = await prisma.finding.findMany({
    where: { scanType: { in: ["DAST", "PENTEST", "PENTEST_FULL"] } },
    orderBy: { firstSeen: "asc" },
  });

  logger.info(`[merge-dast] ${findings.length} DAST/PENTEST findings to process`);

  // Group by (orgId, targetId, scanType, ruleId-or-title)
  const groups = new Map<string, typeof findings>();
  for (const f of findings) {
    const targetId = f.repositoryId ?? f.containerId ?? f.domainId ?? "unknown";
    // Mirror mergeDastFindings() key logic: ruleId first, fall back to title
    const ruleKey = f.ruleId ?? f.title ?? "unknown";
    const key = [f.orgId, targetId, f.scanType, ruleKey].join("::");
    if (!groups.has(key)) groups.set(key, []);
    groups.get(key)!.push(f);
  }

  logger.info(`[merge-dast] ${groups.size} rule-groups found`);

  let merged  = 0;
  let updated = 0;
  let skipped = 0;

  for (const group of groups.values()) {
    const rep      = group[0]!;
    const targetId = rep.repositoryId ?? rep.containerId ?? rep.domainId ?? "unknown";
    const ruleKey  = rep.ruleId ?? rep.title ?? "unknown";
    const fp       = dastFingerprint(rep.orgId, targetId, rep.scanType, ruleKey);

    // ── Single occurrence — just update fingerprint if needed ──────────────
    if (group.length === 1) {
      if (rep.fingerprint === fp) { skipped++; continue; }
      await prisma.finding.update({ where: { id: rep.id }, data: { fingerprint: fp } });
      updated++;
      continue;
    }

    // ── Multiple occurrences — build merged finding ────────────────────────
    const sortedBySev = [...group].sort(
      (a, b) => (SEV_RANK[a.severity] ?? 99) - (SEV_RANK[b.severity] ?? 99),
    );
    const topSev  = highestSeverity(group.map((f) => f.severity));
    const topConf = highestConfidence(group.map((f) => f.confidence));
    const primary = sortedBySev[0]!;
    const others  = group.filter((f) => f.id !== primary.id);

    // Build per-occurrence payload consumed by DastSubissuesPanel
    const occurrences = sortedBySev.map((f) => {
      const ev  = (f.evidence  ?? {}) as Record<string, unknown>;
      const raw = (f.rawOutput ?? {}) as Record<string, unknown>;

      // URL: evidence.url → rawOutput.url → filePath
      const url =
        (ev["url"]  as string | null)
        ?? (raw["url"] as string | null)
        ?? (f.filePath ?? "");

      return {
        url,
        param:          (ev["param"]           as string | null) ?? (raw["param"]  as string | null) ?? null,
        severity:        f.severity,
        confidence:      f.confidence ?? "POSSIBLE",
        zapConfidence:  (ev["zap_confidence"]  as string)        ?? (raw["confidence"] as string) ?? "",
        responseStatus: (ev["response_status"] as string | number | null) ?? null,
        evidence:       (ev["evidence"]        as string | null) ?? (raw["evidence"] as string | null) ?? null,
        attack:         (ev["attack"]          as string | null) ?? (raw["attack"]   as string | null) ?? null,
        other:          (ev["other"]           as string | null) ?? (raw["other"]    as string | null) ?? null,
      };
    });

    // Guard: merged fingerprint already exists (re-run safety) → delete this group
    const existingMerged = await prisma.finding.findUnique({ where: { fingerprint: fp } });
    if (existingMerged && existingMerged.id !== primary.id) {
      await prisma.finding.deleteMany({
        where: { id: { in: [primary.id, ...others.map((o) => o.id)] } },
      });
      merged++;
      continue;
    }

    // Delete duplicates first, then update primary
    await prisma.finding.deleteMany({ where: { id: { in: others.map((o) => o.id) } } });

    await prisma.finding.update({
      where: { id: primary.id },
      data: {
        fingerprint: fp,
        severity:    topSev  as "CRITICAL" | "HIGH" | "MEDIUM" | "LOW" | "INFO",
        confidence:  topConf as "CONFIRMED" | "LIKELY" | "POSSIBLE",
        // filePath → URL of most-severe occurrence
        filePath:    occurrences[0]?.url ?? primary.filePath ?? null,
        rawOutput: {
          merged:      true,
          count:       group.length,
          ruleId:      ruleKey,
          scanner:     primary.scanner,
          occurrences,
          primary:     primary.rawOutput,
        } as object,
      },
    });

    merged++;
  }

  logger.info(
    `[merge-dast] done — ${merged} rules merged/collapsed, ` +
    `${updated} fingerprints updated, ${skipped} already current`,
  );

  const after = await prisma.finding.count({
    where: { scanType: { in: ["DAST", "PENTEST", "PENTEST_FULL"] } },
  });
  logger.info(`[merge-dast] DAST/PENTEST findings: ${findings.length} → ${after}`);
  await prisma.$disconnect();
}

run()
  .then(() => process.exit(0))
  .catch((err) => { console.error(err); process.exit(1); });
