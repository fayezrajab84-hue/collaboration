/**
 * One-time migration: merge per-CVE SCA / CONTAINER findings into one
 * finding per package@version per target.
 *
 * Run: docker exec admiring-hertz-api-1 node --import tsx/esm \
 *        /app/apps/api/src/migrations/mergeScaFindings.ts
 *
 * Safe to re-run — findings already at package-level fingerprint are skipped.
 */

import { createHash } from "crypto";
import prisma from "../db.js";
import { logger } from "../logger.js";

const SEV_RANK: Record<string, number> = { CRITICAL: 0, HIGH: 1, MEDIUM: 2, LOW: 3, INFO: 4 };

function packageFingerprint(orgId: string, targetId: string, scanType: string, pkg: string, ver: string): string {
  return createHash("sha256")
    .update(`${orgId}:sca-pkg:${targetId}:${scanType}:${pkg}:${ver}`)
    .digest("hex");
}

function highestSeverity(severities: string[]): string {
  return severities.reduce((best, s) =>
    (SEV_RANK[s] ?? 99) < (SEV_RANK[best] ?? 99) ? s : best, "INFO");
}

async function run() {
  logger.info("[merge-sca] starting SCA/CONTAINER finding merge migration");

  // Fetch all SCA/CONTAINER findings that have package metadata
  const findings = await prisma.finding.findMany({
    where: {
      scanType: { in: ["SCA", "CONTAINER"] },
      packageName: { not: null },
      packageVersion: { not: null },
    },
    orderBy: { firstSeen: "asc" },
  });

  logger.info(`[merge-sca] ${findings.length} findings to process`);

  // Group by (orgId, targetId, scanType, packageName, packageVersion)
  type GroupKey = string;
  const groups = new Map<GroupKey, typeof findings>();

  for (const f of findings) {
    // Resolve targetId from whichever FK is set
    const targetId = f.repositoryId ?? f.containerId ?? f.domainId ?? "unknown";
    const key: GroupKey = [f.orgId, targetId, f.scanType, f.packageName!, f.packageVersion!].join("::");
    if (!groups.has(key)) groups.set(key, []);
    groups.get(key)!.push(f);
  }

  let merged = 0;
  let skipped = 0;
  let updated = 0;

  for (const group of groups.values()) {
    const rep      = group[0]!;
    const targetId = rep.repositoryId ?? rep.containerId ?? rep.domainId ?? "unknown";
    const fp       = packageFingerprint(rep.orgId, targetId, rep.scanType, rep.packageName!, rep.packageVersion!);

    if (group.length === 1) {
      // Single-CVE finding — just update fingerprint if it hasn't been migrated yet
      if (rep.fingerprint === fp) { skipped++; continue; }
      await prisma.finding.update({ where: { id: rep.id }, data: { fingerprint: fp } });
      updated++;
      continue;
    }

    // ── Multiple CVEs: keep best, delete rest ────────────────────────────
    const sortedBySev = [...group].sort(
      (a, b) => (SEV_RANK[a.severity] ?? 99) - (SEV_RANK[b.severity] ?? 99),
    );

    const topSev    = highestSeverity(group.map((f) => f.severity));
    const primary   = sortedBySev[0]!;
    const others    = group.filter((f) => f.id !== primary.id);
    const fixVer    = group.map((f) => f.fixVersion).find(Boolean) ?? null;
    const maxCvss   = group.reduce<number | null>((m, f) =>
      f.cvssScore != null ? Math.max(m ?? 0, f.cvssScore) : m, null);
    const cveIds    = group.map((f) => f.cveId).filter(Boolean) as string[];

    const cveList = sortedBySev
      .map((f) => {
        const cvss = f.cvssScore != null ? `, CVSS ${f.cvssScore}` : "";
        return `• ${f.cveId ?? "N/A"} [${f.severity}${cvss}]`;
      })
      .join("\n");

    const description =
      `${group.length} vulnerabilities found in ${rep.packageName}@${rep.packageVersion}.` +
      (fixVer ? ` Upgrade to ${fixVer} to fix all.` : "") +
      `\n\nCVEs:\n${cveList}`;

    const title = `${rep.packageName} ${rep.packageVersion} — ${group.length} vulnerabilities (${topSev})`;

    // If another finding already holds the new package-level fingerprint,
    // point all tickets/etc. at it and delete the primary too.
    const existingMerged = await prisma.finding.findUnique({ where: { fingerprint: fp } });

    if (existingMerged && existingMerged.id !== primary.id) {
      // Already migrated — just delete duplicates
      await prisma.finding.deleteMany({ where: { id: { in: [primary.id, ...others.map((o) => o.id)] } } });
      merged++;
      continue;
    }

    // Delete duplicates first, then update primary (avoids unique constraint issues)
    await prisma.finding.deleteMany({ where: { id: { in: others.map((o) => o.id) } } });

    await prisma.finding.update({
      where: { id: primary.id },
      data: {
        fingerprint:  fp,
        title,
        description,
        severity:     topSev as "CRITICAL" | "HIGH" | "MEDIUM" | "LOW" | "INFO",
        cvssScore:    maxCvss,
        fixVersion:   fixVer,
        references:   cveIds,
        rawOutput:    { merged: true, count: group.length, cves: group.map((f) => f.rawOutput) } as object,
      },
    });

    merged++;
  }

  logger.info(`[merge-sca] done — ${merged} packages merged, ${updated} fingerprints updated, ${skipped} already current`);

  const afterCount = await prisma.finding.count({ where: { scanType: { in: ["SCA", "CONTAINER"] } } });
  logger.info(`[merge-sca] SCA/CONTAINER findings: ${findings.length} → ${afterCount}`);
}

run()
  .then(() => process.exit(0))
  .catch((err) => { console.error(err); process.exit(1); });
