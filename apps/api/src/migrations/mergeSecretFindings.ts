/**
 * One-time migration: merge per-file SECRET findings into per-detector merged cards.
 *
 * Before this migration, every TruffleHog hit produced a separate Finding row.
 * After it, findings for the same detector on the same target are collapsed into
 * a single merged row — identical to how SAST and DAST findings work.
 *
 * What this script does:
 *  1. Loads all non-merged SECRET findings grouped by (orgId, targetId, ruleId).
 *  2. For groups with >1 finding: creates a new merged finding, transfers the
 *     ticket link if any, and deletes the originals.
 *  3. For single-item groups: re-fingerprints using the secretRuleFingerprint
 *     scheme and updates in-place (no duplicate risk because the unique key
 *     changes but the old row is updated).
 *
 * Safe to re-run — already-merged findings (rawOutput.merged === true) are skipped.
 *
 * Run:
 *   docker exec admiring-hertz-api-1 sh -c \
 *     "node --import tsx/esm /app/apps/api/src/migrations/mergeSecretFindings.ts"
 */

import { createHash } from "crypto";
import prisma from "../db.js";
import { logger } from "../logger.js";

// ── Severity helpers ──────────────────────────────────────────────────────────

const SEV_RANK: Record<string, number> = {
  CRITICAL: 0, HIGH: 1, MEDIUM: 2, LOW: 3, INFO: 4,
};

function highestSeverity(severities: string[]): string {
  return severities.reduce(
    (best, s) => (SEV_RANK[s] ?? 99) < (SEV_RANK[best] ?? 99) ? s : best,
    "INFO",
  );
}

// ── Fingerprint ───────────────────────────────────────────────────────────────

function secretRuleFingerprint(orgId: string, targetId: string, ruleId: string): string {
  return createHash("sha256")
    .update(`${orgId}:secret-rule:${targetId}:${ruleId}`)
    .digest("hex");
}

function targetId(f: {
  repositoryId: string | null;
  containerId:  string | null;
  domainId:     string | null;
}): string {
  return (f.repositoryId ?? f.containerId ?? f.domainId)!;
}

// ── Main ──────────────────────────────────────────────────────────────────────

async function run() {
  logger.info("[merge-secrets] starting SECRET findings merge migration");

  // Load all SECRET findings that haven't been merged yet
  const allFindings = await prisma.finding.findMany({
    where: { scanType: "SECRET" },
    select: {
      id:           true,
      orgId:        true,
      scanJobId:    true,
      targetType:   true,
      repositoryId: true,
      containerId:  true,
      domainId:     true,
      ruleId:       true,
      title:        true,
      description:  true,
      severity:     true,
      filePath:     true,
      lineStart:    true,
      lineEnd:      true,
      codeSnippet:  true,
      scanner:      true,
      fingerprint:  true,
      remediation:  true,
      rawOutput:    true,
      confidence:   true,
      evidence:     true,
      references:   true,
      cveId:        true,
      cweId:        true,
      firstSeen:    true,
      lastSeen:     true,
      status:       true,
      ticket:       { select: { id: true } },
    },
  });

  // Skip already-merged findings
  const unmerged = allFindings.filter((f) => {
    const raw = f.rawOutput as Record<string, unknown> | null;
    return raw?.["merged"] !== true;
  });

  logger.info(`[merge-secrets] ${allFindings.length} total SECRET findings, ${unmerged.length} unmerged`);

  if (unmerged.length === 0) {
    logger.info("[merge-secrets] nothing to do");
    return;
  }

  // Group by (orgId, targetId, ruleId)
  type FindingRow = typeof unmerged[number];
  const groups = new Map<string, FindingRow[]>();
  for (const f of unmerged) {
    const tid = targetId(f);
    const key = `${f.orgId}::${tid}::${f.ruleId ?? f.title ?? "unknown"}`;
    if (!groups.has(key)) groups.set(key, []);
    groups.get(key)!.push(f);
  }

  logger.info(`[merge-secrets] ${groups.size} distinct detector groups`);

  const CONF_RANK: Record<string, number> = { POSSIBLE: 0, LIKELY: 1, CONFIRMED: 2 };

  let mergedCount   = 0;
  let singleCount   = 0;
  let skippedCount  = 0;

  for (const [, group] of groups.entries()) {
    const first    = group[0]!;
    const orgId    = first.orgId;
    const tid      = targetId(first);
    const ruleId   = first.ruleId ?? first.title ?? "unknown";
    const fp       = secretRuleFingerprint(orgId, tid, ruleId);

    if (group.length === 1) {
      // Single occurrence — just re-fingerprint
      try {
        await prisma.finding.update({
          where: { id: first.id },
          data:  { fingerprint: fp },
        });
        singleCount++;
      } catch {
        skippedCount++;
      }
      continue;
    }

    // ── Multiple occurrences → merge ──────────────────────────────────────

    // Sort: verified first, then by severity
    const sorted = [...group].sort((a, b) => {
      const aV = (a.rawOutput as Record<string, unknown>)?.["Verified"] === true ? 0 : 1;
      const bV = (b.rawOutput as Record<string, unknown>)?.["Verified"] === true ? 0 : 1;
      if (aV !== bV) return aV - bV;
      return (SEV_RANK[a.severity] ?? 99) - (SEV_RANK[b.severity] ?? 99);
    });

    const primary  = sorted[0]!;
    const topSev   = highestSeverity(group.map((f) => f.severity));
    const topConf  = group.reduce<string>((best, f) => {
      const c = (f.confidence as string | null) ?? "POSSIBLE";
      return (CONF_RANK[c] ?? 0) > (CONF_RANK[best] ?? 0) ? c : best;
    }, "POSSIBLE");

    const occurrences = sorted.map((f) => ({
      filePath:  f.filePath  ?? null,
      lineStart: f.lineStart ?? null,
      snippet:   f.codeSnippet ?? null,
      verified:  (f.rawOutput as Record<string, unknown>)?.["Verified"] === true,
      severity:  f.severity,
      scanner:   f.scanner,
    }));

    const mergedRawOutput = {
      merged:      true,
      count:       group.length,
      ruleId,
      scanner:     primary.scanner,
      occurrences,
      primary:     primary.rawOutput,
    };

    // Earliest firstSeen across the group
    const firstSeen = group.reduce(
      (min, f) => f.firstSeen < min ? f.firstSeen : min,
      group[0]!.firstSeen,
    );

    // If a ticket exists on any of the originals, we'll re-link it to the merged finding
    const ticketId = group.find((f) => f.ticket)?.ticket?.id ?? null;

    // Check if the merged fingerprint already exists (previous partial run)
    const existing = await prisma.finding.findUnique({ where: { fingerprint: fp } });
    if (existing) {
      // Already merged in a previous run — just delete the originals
      const idsToDelete = group.map((f) => f.id).filter((id) => id !== existing.id);
      if (idsToDelete.length > 0) {
        if (ticketId) {
          await prisma.ticket.update({
            where: { id: ticketId },
            data:  { findingId: existing.id },
          });
        }
        await prisma.finding.deleteMany({ where: { id: { in: idsToDelete } } });
      }
      skippedCount++;
      continue;
    }

    // Use the primary finding's ID slot — update it in place, delete the rest
    try {
      // Re-link ticket to primary before we nuke other rows
      if (ticketId) {
        const ticketFindingId = group.find((f) => f.ticket)!.id;
        if (ticketFindingId !== primary.id) {
          await prisma.ticket.update({
            where: { id: ticketId },
            data:  { findingId: primary.id },
          });
        }
      }

      // Delete non-primary rows first (FK + unique constraint safety)
      const toDelete = group.filter((f) => f.id !== primary.id).map((f) => f.id);
      if (toDelete.length > 0) {
        await prisma.finding.deleteMany({ where: { id: { in: toDelete } } });
      }

      // Update primary to the merged shape
      await prisma.finding.update({
        where: { id: primary.id },
        data: {
          fingerprint: fp,
          severity:    topSev as "CRITICAL" | "HIGH" | "MEDIUM" | "LOW" | "INFO",
          confidence:  topConf as "CONFIRMED" | "LIKELY" | "POSSIBLE",
          rawOutput:   mergedRawOutput as object,
          firstSeen,
          // Clear per-file fields that are now in occurrences[]
          filePath:    null,
          lineStart:   null,
          lineEnd:     null,
          codeSnippet: null,
        },
      });

      mergedCount++;
    } catch (err) {
      logger.error(`[merge-secrets] failed to merge group ruleId=${ruleId}: ${err}`);
      skippedCount++;
    }
  }

  logger.info(
    `[merge-secrets] done — ${mergedCount} groups merged, ${singleCount} re-fingerprinted, ${skippedCount} skipped`,
  );
}

run()
  .then(() => process.exit(0))
  .catch((err) => { console.error(err); process.exit(1); });
