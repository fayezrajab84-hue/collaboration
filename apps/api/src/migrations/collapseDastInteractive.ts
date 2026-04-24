/**
 * One-time migration: collapse DAST_INTERACTIVE rows into DAST.
 *
 * Interactive provenance used to live in the ScanType enum as a dedicated
 * DAST_INTERACTIVE value. We moved that distinction onto ScanJob (read via
 * ScanJob.recordingSessionId), which means the enum can drop the extra value.
 * But existing Finding and ScanJob rows still carry it, so we:
 *
 *   1. Rehash every DAST_INTERACTIVE Finding's fingerprint under scanType=DAST.
 *      - Key change: dastRuleFingerprint uses scanType, so
 *          sha256(orgId:dast-rule:targetId:DAST_INTERACTIVE:ruleId)
 *        becomes
 *          sha256(orgId:dast-rule:targetId:DAST:ruleId).
 *      - If a DAST row already exists under the new fingerprint for the same
 *        logical issue, delete the DAST_INTERACTIVE one (DAST row wins —
 *        it has the longer history). Otherwise update scanType + fingerprint
 *        in place.
 *
 *   2. Replace "DAST_INTERACTIVE" with "DAST" in every ScanJob.scanTypes[] array.
 *
 * Safe to re-run. Dry-run by default. Set MIGRATE_APPLY=1 to mutate.
 *
 * Run:
 *   docker compose exec api sh -c \
 *     "node --import tsx/esm /app/apps/api/src/migrations/collapseDastInteractive.ts"
 *
 *   docker compose exec -e MIGRATE_APPLY=1 api sh -c \
 *     "node --import tsx/esm /app/apps/api/src/migrations/collapseDastInteractive.ts"
 */
import { createHash } from "crypto";
import prisma from "../db.js";
import { logger } from "../logger.js";

const APPLY = process.env["MIGRATE_APPLY"] === "1";

function dastRuleFingerprint(
  orgId: string, targetId: string, scanType: string, ruleId: string,
): string {
  return createHash("sha256")
    .update(`${orgId}:dast-rule:${targetId}:${scanType}:${ruleId}`)
    .digest("hex");
}

async function run() {
  logger.info(`[collapse-dast] mode=${APPLY ? "APPLY" : "DRY-RUN"}`);

  // Raw SQL because the Prisma enum still contains DAST_INTERACTIVE until the
  // next schema push — safer to address rows by string than to chase enum updates.
  const rows = await prisma.$queryRawUnsafe<Array<{
    id: string; orgId: string; repositoryId: string | null;
    containerId: string | null; domainId: string | null;
    ruleId: string | null; title: string | null;
  }>>(`
    SELECT id, "orgId", "repositoryId", "containerId", "domainId",
           "ruleId", title
    FROM "Finding"
    WHERE "scanType" = 'DAST_INTERACTIVE'
  `);

  console.log(`[collapse-dast] ${rows.length} DAST_INTERACTIVE findings found`);

  let inPlace = 0;
  let collided = 0;
  let deleted  = 0;

  for (const f of rows) {
    const targetId = f.repositoryId ?? f.containerId ?? f.domainId ?? "unknown";
    const ruleKey  = f.ruleId ?? f.title ?? "unknown";
    const newFp    = dastRuleFingerprint(f.orgId, targetId, "DAST", ruleKey);

    // Does a DAST row already exist under the new fingerprint?
    const clash = await prisma.finding.findUnique({
      where:  { fingerprint: newFp },
      select: { id: true, scanType: true },
    });

    if (clash && clash.id !== f.id) {
      collided++;
      if (APPLY) {
        // Drop the DAST_INTERACTIVE dupe; the existing DAST row wins
        await prisma.$executeRawUnsafe(
          `DELETE FROM "Finding" WHERE id = $1`, f.id
        );
        deleted++;
      }
    } else {
      inPlace++;
      if (APPLY) {
        // In-place rehash + scanType flip. Raw SQL so we can reference the
        // enum value by string during the transition window.
        await prisma.$executeRawUnsafe(
          `UPDATE "Finding" SET "scanType" = 'DAST'::"ScanType", fingerprint = $1
             WHERE id = $2`,
          newFp, f.id,
        );
      }
    }
  }

  // ScanJob.scanTypes — array-of-enum column. Replace DAST_INTERACTIVE with DAST
  // in-place. array_replace is idempotent: no-op if the value isn't present.
  const jobs = await prisma.$queryRawUnsafe<Array<{ id: string; scanTypes: string[] }>>(
    `SELECT id, "scanTypes"::text[] AS "scanTypes"
       FROM "ScanJob"
       WHERE 'DAST_INTERACTIVE' = ANY("scanTypes"::text[])`,
  );

  console.log(`[collapse-dast] ${jobs.length} ScanJobs reference DAST_INTERACTIVE in scanTypes`);

  if (APPLY && jobs.length > 0) {
    await prisma.$executeRawUnsafe(
      `UPDATE "ScanJob"
          SET "scanTypes" = array_replace("scanTypes"::text[], 'DAST_INTERACTIVE', 'DAST')::"ScanType"[]
          WHERE 'DAST_INTERACTIVE' = ANY("scanTypes"::text[])`,
    );
  }

  console.log("\n[collapse-dast] Summary:");
  console.log(`  Findings rehashed in place:  ${inPlace}`);
  console.log(`  Findings collided w/ DAST:   ${collided}${APPLY ? ` (deleted ${deleted})` : " (would delete)"}`);
  console.log(`  ScanJob rows to fix:         ${jobs.length}`);
  if (!APPLY) {
    console.log("\n[collapse-dast] DRY-RUN — set MIGRATE_APPLY=1 to actually mutate.");
  } else {
    console.log("\n[collapse-dast] DONE.");
  }
}

run().then(() => process.exit(0)).catch((err) => { console.error(err); process.exit(1); });
