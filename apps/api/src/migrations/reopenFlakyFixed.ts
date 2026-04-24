/**
 * Reopen DAST-family findings that were auto-closed by the single-miss bug.
 *
 * Before the `absenceCount` gate, any OPEN/ACKNOWLEDGED DAST/PENTEST/
 * PENTEST_FULL finding that wasn't re-emitted by the very next scan
 * of its type got marked FIXED. ZAP / nuclei / nikto are flaky enough that
 * this mass-closed legitimate issues on a single unlucky run.
 *
 * This migration reopens every currently-FIXED finding in those 4 types,
 * resets the absenceCount to 0, and writes an AuditEvent trail.
 *
 * Safe to re-run — only acts on FIXED rows. Dry-run by default; set
 * REOPEN_APPLY=1 to actually mutate.
 *
 * Run:
 *   docker compose exec api sh -c \
 *     "node --import tsx/esm /app/apps/api/src/migrations/reopenFlakyFixed.ts"
 *
 *   docker compose exec -e REOPEN_APPLY=1 api sh -c \
 *     "node --import tsx/esm /app/apps/api/src/migrations/reopenFlakyFixed.ts"
 */
import prisma from "../db.js";
import { logger } from "../logger.js";
import type { ScanType } from "@devsecops/types";

const FLAKY_TYPES: ScanType[] = ["DAST", "PENTEST", "PENTEST_FULL"];
const APPLY = process.env["REOPEN_APPLY"] === "1";

async function run() {
  logger.info(`[reopen-flaky] mode=${APPLY ? "APPLY" : "DRY-RUN"} types=${FLAKY_TYPES.join(",")}`);

  const candidates = await prisma.finding.findMany({
    where:  { status: "FIXED", scanType: { in: FLAKY_TYPES } },
    select: { id: true, orgId: true, scanType: true, title: true, resolvedAt: true },
  });

  const byType: Record<string, number> = {};
  for (const f of candidates) byType[f.scanType] = (byType[f.scanType] ?? 0) + 1;

  console.log("\n[reopen-flaky] Candidates:");
  for (const t of FLAKY_TYPES) {
    console.log(`  ${t.padEnd(18)} ${(byType[t] ?? 0).toString().padStart(4)}`);
  }
  console.log(`  ${"TOTAL".padEnd(18)} ${candidates.length.toString().padStart(4)}\n`);

  if (!APPLY) {
    console.log("[reopen-flaky] DRY-RUN — set REOPEN_APPLY=1 to actually reopen.");
    return;
  }
  if (candidates.length === 0) {
    console.log("[reopen-flaky] nothing to do.");
    return;
  }

  const CHUNK = 100;
  let reopened = 0;
  for (let i = 0; i < candidates.length; i += CHUNK) {
    const slice = candidates.slice(i, i + CHUNK);
    const ids   = slice.map((f) => f.id);
    await prisma.$transaction(async (tx) => {
      await tx.finding.updateMany({
        where: { id: { in: ids } },
        data:  { status: "OPEN", resolvedAt: null, absenceCount: 0 },
      });
      await tx.auditEvent.create({
        data: {
          orgId:        slice[0]!.orgId,
          userId:       "system",
          action:       "FINDING_REOPENED_BY_MIGRATION",
          resourceType: "FINDING",
          resourceId:   null,
          metadata: {
            migration: "reopenFlakyFixed",
            chunkSize: slice.length,
            findingIds: ids,
            scanTypes: [...new Set(slice.map((f) => f.scanType))],
            reason: "Closed by single-miss auto-fix before DAST-family absence gate was added",
          },
        },
      });
    });
    reopened += slice.length;
    console.log(`[reopen-flaky] ${reopened}/${candidates.length}`);
  }
  logger.info(`[reopen-flaky] DONE — reopened ${reopened} findings`);
}

run().then(() => process.exit(0)).catch((err) => { console.error(err); process.exit(1); });
