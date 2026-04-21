/**
 * One-time migration: merge per-resource IAC findings into per-rule merged cards.
 *
 * Before this migration, every Checkov failure produced a separate Finding row.
 * After it, all resources failing the same check on the same target are collapsed
 * into a single merged row — matching how SAST, DAST, and SECRET findings work.
 *
 * Safe to re-run — already-merged findings (rawOutput.merged === true) are skipped.
 *
 * Run:
 *   docker exec admiring-hertz-api-1 sh -c \
 *     "node --import tsx/esm /app/apps/api/src/migrations/mergeIacFindings.ts"
 */

import { createHash } from "crypto";
import { Prisma } from "@prisma/client";
import prisma from "../db.js";
import { logger } from "../logger.js";

// ── Helpers ───────────────────────────────────────────────────────────────────

const SEV_RANK: Record<string, number> = {
  CRITICAL: 0, HIGH: 1, MEDIUM: 2, LOW: 3, INFO: 4,
};

function highestSeverity(severities: string[]): string {
  return severities.reduce(
    (best, s) => (SEV_RANK[s] ?? 99) < (SEV_RANK[best] ?? 99) ? s : best,
    "INFO",
  );
}

function iacRuleFingerprint(orgId: string, targetId: string, ruleId: string): string {
  return createHash("sha256")
    .update(`${orgId}:iac-rule:${targetId}:${ruleId}`)
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
  logger.info("[merge-iac] starting IAC findings merge migration");

  const allFindings = await prisma.finding.findMany({
    where: { scanType: "IAC" },
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
      firstSeen:    true,
      lastSeen:     true,
      status:       true,
      ticket:       { select: { id: true } },
    },
  });

  // Skip already-merged
  const unmerged = allFindings.filter((f) => {
    const raw = f.rawOutput as Record<string, unknown> | null;
    return raw?.["merged"] !== true;
  });

  logger.info(`[merge-iac] ${allFindings.length} total IAC findings, ${unmerged.length} unmerged`);

  if (unmerged.length === 0) {
    logger.info("[merge-iac] nothing to do");
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

  logger.info(`[merge-iac] ${groups.size} distinct rule groups`);

  let mergedCount  = 0;
  let singleCount  = 0;
  let skippedCount = 0;

  for (const [, group] of groups.entries()) {
    const first    = group[0]!;
    const orgId    = first.orgId;
    const tid      = targetId(first);
    const ruleId   = first.ruleId ?? first.title ?? "unknown";
    const fp       = iacRuleFingerprint(orgId, tid, ruleId);

    if (group.length === 1) {
      try {
        await prisma.finding.update({ where: { id: first.id }, data: { fingerprint: fp } });
        singleCount++;
      } catch { skippedCount++; }
      continue;
    }

    // ── Multiple failing resources → merge ────────────────────────────────

    const sorted = [...group].sort((a, b) => {
      const sevDiff = (SEV_RANK[a.severity] ?? 99) - (SEV_RANK[b.severity] ?? 99);
      if (sevDiff !== 0) return sevDiff;
      return (a.filePath ?? "").localeCompare(b.filePath ?? "");
    });

    const primary  = sorted[0]!;
    const topSev   = highestSeverity(group.map((f) => f.severity));

    const resources = sorted.map((f) => {
      const raw = (f.rawOutput ?? {}) as Record<string, unknown>;
      return {
        filePath:  f.filePath  ?? null,
        lineStart: f.lineStart ?? null,
        lineEnd:   f.lineEnd   ?? null,
        resource:  (raw["resource"]   as string | null) ?? null,
        snippet:   f.codeSnippet      ?? null,
        severity:  f.severity,
        checkType: (raw["check_type"] as string | null) ?? null,
      };
    });

    const countLabel  = `${group.length} resource${group.length !== 1 ? "s" : ""}`;
    const baseDesc    = primary.description ?? primary.title;
    const cleanDesc   = baseDesc.replace(/\s*—\s*affects \d+ resources?\.?$/, "");
    const description = `${cleanDesc} — affects ${countLabel}.`;

    const mergedRaw = {
      merged:    true,
      count:     group.length,
      ruleId,
      scanner:   primary.scanner,
      resources,
      primary:   primary.rawOutput,
    };

    const firstSeen = group.reduce(
      (min, f) => f.firstSeen < min ? f.firstSeen : min,
      group[0]!.firstSeen,
    );

    const ticketId = group.find((f) => f.ticket)?.ticket?.id ?? null;

    // Check if merged fingerprint already exists (previous partial run)
    const existing = await prisma.finding.findUnique({ where: { fingerprint: fp } });
    if (existing) {
      const idsToDelete = group.map((f) => f.id).filter((id) => id !== existing.id);
      if (idsToDelete.length > 0) {
        if (ticketId) {
          await prisma.ticket.update({ where: { id: ticketId }, data: { findingId: existing.id } });
        }
        await prisma.finding.deleteMany({ where: { id: { in: idsToDelete } } });
      }
      skippedCount++;
      continue;
    }

    try {
      if (ticketId) {
        const ticketFindingId = group.find((f) => f.ticket)!.id;
        if (ticketFindingId !== primary.id) {
          await prisma.ticket.update({ where: { id: ticketId }, data: { findingId: primary.id } });
        }
      }

      const toDelete = group.filter((f) => f.id !== primary.id).map((f) => f.id);
      if (toDelete.length > 0) {
        await prisma.finding.deleteMany({ where: { id: { in: toDelete } } });
      }

      await prisma.finding.update({
        where: { id: primary.id },
        data: {
          fingerprint:  fp,
          severity:     topSev as "CRITICAL" | "HIGH" | "MEDIUM" | "LOW" | "INFO",
          description,
          rawOutput:    mergedRaw as object,
          firstSeen,
          // Clear per-resource fields that are now in resources[]
          filePath:     null,
          lineStart:    null,
          lineEnd:      null,
          codeSnippet:  null,
          // Clear stale AI cache so it regenerates with new merged context
          aiAnalysis:      Prisma.DbNull,   // Json? field requires DbNull sentinel
          aiAnalysedAt:    null,
          aiFixSuggestion: null,
          aiFixSuggestedAt: null,
        },
      });
      mergedCount++;
    } catch (err) {
      logger.error(`[merge-iac] failed ruleId=${ruleId}: ${err}`);
      skippedCount++;
    }
  }

  logger.info(
    `[merge-iac] done — ${mergedCount} groups merged, ${singleCount} re-fingerprinted, ${skippedCount} skipped`,
  );
}

run()
  .then(() => process.exit(0))
  .catch((err) => { console.error(err); process.exit(1); });
