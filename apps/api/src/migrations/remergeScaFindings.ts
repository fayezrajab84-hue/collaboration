/**
 * One-time migration: transform merged SCA findings from the old
 * rawOutput.cves[] format (raw Trivy objects) to the new structured
 * per-CVE format consumed by ScaSubissuesPanel.
 *
 * Safe to re-run — skips findings already in the new format.
 *
 * Run: docker exec admiring-hertz-api-1 node --import tsx/esm \
 *        /app/apps/api/src/migrations/remergeScaFindings.ts
 */

import prisma from "../db.js";
import { logger } from "../logger.js";

interface TrivyCve {
  VulnerabilityID?: string;
  Severity?:        string;
  FixedVersion?:    string;
  InstalledVersion?: string;
  Title?:           string;
  PrimaryURL?:      string;
  CVSS?:            Record<string, { V3Score?: number; V2Score?: number }>;
}

interface StructuredCve {
  cveId:      string | null;
  severity:   string;
  cvssScore:  number | null;
  fixVersion: string | null;
  filePath:   null;              // not available in old data
  title:      string | null;
  primaryUrl: string | null;
}

function fromTrivy(raw: TrivyCve): StructuredCve {
  let cvssScore: number | null = null;
  if (raw.CVSS) {
    for (const scores of Object.values(raw.CVSS)) {
      const s = scores?.V3Score ?? scores?.V2Score ?? null;
      if (s != null) { cvssScore = s; break; }
    }
  }
  return {
    cveId:      raw.VulnerabilityID ?? null,
    severity:   (raw.Severity ?? "MEDIUM").toUpperCase(),
    cvssScore,
    fixVersion: raw.FixedVersion ?? null,
    filePath:   null,
    title:      raw.Title ?? null,
    primaryUrl: raw.PrimaryURL ?? null,
  };
}

async function run() {
  logger.info("[remergeSca] starting SCA rawOutput migration");

  const findings = await prisma.finding.findMany({
    where: { scanType: { in: ["SCA", "CONTAINER"] } },
  });

  logger.info(`[remergeSca] ${findings.length} SCA/CONTAINER findings to inspect`);

  let updated  = 0;
  let skipped  = 0;

  for (const f of findings) {
    const raw = f.rawOutput as Record<string, unknown> | null;
    if (!raw?.["merged"]) { skipped++; continue; }

    const cves = raw["cves"] as unknown[] | undefined;
    if (!Array.isArray(cves) || cves.length === 0) { skipped++; continue; }

    // Already in new format if first entry has "cveId" key
    if (typeof cves[0] === "object" && cves[0] !== null && "cveId" in cves[0]) {
      skipped++;
      continue;
    }

    // Convert old Trivy raw objects → structured format
    const structuredCves = (cves as TrivyCve[]).map(fromTrivy);

    // Derive top-level fixVersion from the first CVE that has one
    const fixVersion = structuredCves.find((c) => c.fixVersion)?.fixVersion ?? null;

    await prisma.finding.update({
      where: { id: f.id },
      data:  {
        rawOutput: {
          ...raw,
          fixVersion,
          cves: structuredCves,
        } as object,
      },
    });

    updated++;
  }

  logger.info(`[remergeSca] done — ${updated} findings migrated, ${skipped} skipped`);
}

run()
  .then(() => process.exit(0))
  .catch((err) => { console.error(err); process.exit(1); });
