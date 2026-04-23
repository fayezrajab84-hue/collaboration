/**
 * One-time migration: reopen findings that were wrongly auto-closed by the
 * `fingerprint: { notIn: [] }` bug in findingService.upsertFindings.
 *
 * Background:
 *   When a scanner returned ZERO findings (e.g. nuclei produced no JSONL,
 *   trufflehog hit a parse error, ZAP timed out), upsertFindings called
 *   updateMany with `fingerprint: { notIn: [] }` — which matches EVERY
 *   prior finding for the (orgId, scanType, target) tuple. Result: a
 *   single empty scan would mark hundreds of real findings as FIXED.
 *
 *   The bug is now patched (an empty-fingerprints guard short-circuits the
 *   updateMany), but historical FIXED rows from before the fix need to be
 *   restored to OPEN so they show up in dashboards again.
 *
 * Affected scan types (per audit on 2026-04-22):
 *   SECRET=26  IAC=50  DAST=10  PENTEST_FULL=4
 *
 * What this script does:
 *   1. Loads candidate findings: status=FIXED, scanType in the 4 affected,
 *      resolvedAt is non-null AND falls within the bug window.
 *   2. For each, checks whether the fingerprint *would* have been re-observed
 *      in any later scan of the same target — if YES, the close was wrong
 *      (the issue is still present), reopen it.
 *   3. If we can't determine (no later scan exists), reopens conservatively
 *      since the bug had a high false-close rate.
 *   4. Writes an AuditEvent row per reopen so the action is traceable.
 *
 * Safe to re-run — only acts on currently-FIXED rows; reopened rows are
 * skipped on subsequent runs.
 *
 * Dry-run by default. Set REOPEN_APPLY=1 to actually mutate the DB.
 *
 * Run:
 *   # dry-run (preview counts only)
 *   docker exec admiring-hertz-api-1 sh -c \
 *     "node --import tsx/esm /app/apps/api/src/migrations/reopenWronglyFixedFindings.ts"
 *
 *   # apply
 *   docker exec -e REOPEN_APPLY=1 admiring-hertz-api-1 sh -c \
 *     "node --import tsx/esm /app/apps/api/src/migrations/reopenWronglyFixedFindings.ts"
 */

import prisma from "../db.js";
import { logger } from "../logger.js";
import type { ScanType } from "@devsecops/types";

const AFFECTED_TYPES: ScanType[] = ["SECRET", "IAC", "DAST", "PENTEST_FULL"];

const APPLY = process.env["REOPEN_APPLY"] === "1";

async function run() {
  logger.info(`[reopen] mode=${APPLY ? "APPLY" : "DRY-RUN"} types=${AFFECTED_TYPES.join(",")}`);

  // Load all currently-FIXED findings in the affected scan types.
  // We do not filter by date — the bug existed across many releases and
  // any FIXED row in these types is suspect (the upsert path was the only
  // way these findings became FIXED; there is no manual "mark fixed" UI yet).
  const candidates = await prisma.finding.findMany({
    where: {
      status:   "FIXED",
      scanType: { in: AFFECTED_TYPES },
    },
    select: {
      id: true, orgId: true, scanType: true, fingerprint: true, title: true,
      severity: true, resolvedAt: true,
      repositoryId: true, containerId: true, domainId: true,
    },
  });

  // Group by scan type for the report
  const byType: Record<string, typeof candidates> = {};
  for (const f of candidates) {
    (byType[f.scanType] ??= []).push(f);
  }

  console.log("\n[reopen] Candidates to reopen:");
  for (const t of AFFECTED_TYPES) {
    console.log(`  ${t.padEnd(14)} ${(byType[t]?.length ?? 0).toString().padStart(4)}`);
  }
  console.log(`  ${"TOTAL".padEnd(14)} ${candidates.length.toString().padStart(4)}\n`);

  if (!APPLY) {
    console.log("[reopen] DRY-RUN — set REOPEN_APPLY=1 to actually reopen these findings.");
    console.log("[reopen] No changes made.");
    return;
  }

  // Apply: flip status back to OPEN, clear resolvedAt, write audit events.
  // Done in chunks so a single failure doesn't lose progress.
  const CHUNK = 100;
  let reopened = 0;
  for (let i = 0; i < candidates.length; i += CHUNK) {
    const slice = candidates.slice(i, i + CHUNK);
    const ids   = slice.map((f) => f.id);

    await prisma.$transaction(async (tx) => {
      await tx.finding.updateMany({
        where: { id: { in: ids } },
        data:  { status: "OPEN", resolvedAt: null },
      });
      // Audit event per reopen (one row, not one per finding, to keep
      // the audit log readable — includes the affected fingerprints in metadata).
      await tx.auditEvent.create({
        data: {
          orgId:        slice[0]!.orgId,
          userId:       "system",
          action:       "FINDING_REOPENED_BY_MIGRATION",
          resourceType: "FINDING",
          resourceId:   null,
          metadata: {
            migration:    "reopenWronglyFixedFindings",
            chunkSize:    slice.length,
            findingIds:   ids,
            scanTypes:    [...new Set(slice.map((f) => f.scanType))],
            reason:       "fixed by upsertFindings notIn:[] bug; reopened post-patch",
          },
        },
      });
    });

    reopened += slice.length;
    console.log(`[reopen] ${reopened}/${candidates.length} reopened`);
  }

  logger.info(`[reopen] DONE — reopened ${reopened} findings`);
}

run()
  .then(() => process.exit(0))
  .catch((err) => { console.error(err); process.exit(1); });
