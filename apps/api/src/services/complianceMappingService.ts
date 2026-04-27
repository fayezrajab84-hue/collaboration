/**
 * complianceMappingService — assigns Findings to ComplianceControls
 * (Phase 16 Slice B).
 *
 * Strategy:
 *   1. CWE match (primary): if Finding.cweId is e.g. "CWE-79", look it up
 *      in every control's cweIds[]. Multiple controls can match — XSS hits
 *      OWASP A03:2021 + SOC 2 CC8.1 + PCI Req-6.4.1.
 *   2. Keyword fallback (secondary): for findings without a CWE (common in
 *      DAST output), substring-match each control's keywordTags against
 *      Finding.title (case-insensitive). Marked as matchReason="keyword"
 *      so downstream UI / audit can flag the lower confidence.
 *   3. Persist via the FindingControl join table (idempotent — won't
 *      duplicate if re-run).
 *
 * Performance:
 *   - 26 controls × N findings scan is O(N) per finding (small fixed cost).
 *   - Controls are loaded once into a module-level cache, refreshed on
 *     `invalidateControlsCache()` calls (e.g. after the seed script reruns).
 *   - The wire-into-upsertFindings hook runs for every finding the
 *     scanner emits, so the cache matters.
 *
 * Audit notes:
 *   - matchReason is recorded on each FindingControl row so an auditor
 *     can ask "why does this finding satisfy CC6.1?" and we can answer
 *     "CWE-285 matched the control's CWE list" or "keyword 'IDOR' matched
 *     the control's tag".
 */

import prisma from "../db.js";
import { logger } from "../logger.js";
import type { ComplianceControl } from "@prisma/client";

// ── Controls cache ────────────────────────────────────────────────────────
// 26 controls today, ~150 max even with ISO + NIST seeded. In-memory is
// the right call (vs hitting the DB on every finding upsert).

let cache: ComplianceControl[] | null = null;

async function loadControls(): Promise<ComplianceControl[]> {
  if (cache) return cache;
  cache = await prisma.complianceControl.findMany();
  logger.info("[compliance] controls cache loaded", { count: cache.length });
  return cache;
}

/** Drop the cache so the next call refetches. Call after seed reruns. */
export function invalidateControlsCache(): void {
  cache = null;
}

// ── Matching primitives ───────────────────────────────────────────────────

/**
 * Parse a CWE identifier from any of its observed forms:
 *   "CWE-79"  → 79
 *   "cwe-79"  → 79
 *   "79"      → 79
 *   "Foo-79"  → null (not a CWE)
 *   null      → null
 *
 * Scanners report CWE in different shapes (Trivy emits "CWE-79", Semgrep
 * emits ints in metadata, etc.) so the parser is forgiving.
 */
export function parseCweInt(cweId: string | null | undefined): number | null {
  if (!cweId) return null;
  const m = cweId.match(/^(?:CWE-)?(\d+)$/i);
  if (!m || !m[1]) return null;
  const n = Number.parseInt(m[1], 10);
  return Number.isFinite(n) ? n : null;
}

interface MappableFinding {
  cweId: string | null;
  title: string;
}

interface ControlMatch {
  controlId:   string;
  matchReason: "cwe-match" | "keyword";
}

/**
 * Compute the set of controls a finding satisfies. Pure function over the
 * controls list — no DB writes. Used by both upsert-time mapping and the
 * backfill script.
 */
export function matchControls(
  finding: MappableFinding,
  controls: ComplianceControl[],
): ControlMatch[] {
  const matches = new Map<string, ControlMatch>();  // dedup by controlId

  // 1. CWE-based match (preferred — high confidence)
  const cweInt = parseCweInt(finding.cweId);
  if (cweInt !== null) {
    for (const c of controls) {
      if (c.cweIds.includes(cweInt)) {
        matches.set(c.id, { controlId: c.id, matchReason: "cwe-match" });
      }
    }
  }

  // 2. Keyword fallback (case-insensitive substring on title). Only adds
  //    controls not already matched via CWE — CWE wins on confidence.
  const titleLower = finding.title.toLowerCase();
  for (const c of controls) {
    if (matches.has(c.id)) continue;
    if (c.keywordTags.length === 0) continue;
    const hit = c.keywordTags.some((tag) => titleLower.includes(tag.toLowerCase()));
    if (hit) {
      matches.set(c.id, { controlId: c.id, matchReason: "keyword" });
    }
  }

  return Array.from(matches.values());
}

// ── DB integration ────────────────────────────────────────────────────────

/**
 * Persist control mappings for a single finding. Idempotent — safe to call
 * on re-scan. Uses createMany with skipDuplicates so existing
 * (findingId, controlId) rows are left alone.
 *
 * Called from findingService.upsertFindings after each upsert.
 */
export async function applyMappingsToFinding(opts: {
  findingId: string;
  cweId:     string | null;
  title:     string;
}): Promise<number> {
  const controls = await loadControls();
  const matches = matchControls(opts, controls);

  if (matches.length === 0) return 0;

  const result = await prisma.findingControl.createMany({
    data: matches.map((m) => ({
      findingId:   opts.findingId,
      controlId:   m.controlId,
      matchReason: m.matchReason,
    })),
    skipDuplicates: true,
  });
  return result.count;
}

/**
 * Re-compute mappings for every finding in the org (or every finding
 * across all orgs if orgId is omitted). Used after a seed/data change
 * (new controls added, CWE list adjusted) to re-link existing findings.
 *
 * NOT called during normal scan flow — that's what applyMappingsToFinding
 * is for. This is the "I changed the seed file, now propagate" tool.
 *
 * Returns counts so the caller can log "re-mapped N findings → M control
 * links across K controls".
 */
export async function backfillMappings(opts: {
  orgId?: string;
} = {}): Promise<{ findings: number; mappingsCreated: number; mappingsRemoved: number }> {
  invalidateControlsCache();   // pick up any seed changes
  const controls = await loadControls();
  const where = opts.orgId ? { orgId: opts.orgId } : {};

  const findings = await prisma.finding.findMany({
    where,
    select: { id: true, cweId: true, title: true },
  });

  let createdTotal = 0;
  let removedTotal = 0;

  for (const f of findings) {
    const desired = matchControls(f, controls);
    const desiredIds = new Set(desired.map((m) => m.controlId));

    // Read current state — what we already have linked to this finding.
    const current = await prisma.findingControl.findMany({
      where:  { findingId: f.id },
      select: { id: true, controlId: true },
    });
    const currentIds = new Set(current.map((c) => c.controlId));

    // Diff: add the missing, remove the no-longer-matching.
    const toAdd    = desired.filter((m) => !currentIds.has(m.controlId));
    const toRemove = current.filter((c) => !desiredIds.has(c.controlId));

    if (toAdd.length > 0) {
      const r = await prisma.findingControl.createMany({
        data: toAdd.map((m) => ({
          findingId:   f.id,
          controlId:   m.controlId,
          matchReason: m.matchReason,
        })),
        skipDuplicates: true,
      });
      createdTotal += r.count;
    }
    if (toRemove.length > 0) {
      const r = await prisma.findingControl.deleteMany({
        where: { id: { in: toRemove.map((c) => c.id) } },
      });
      removedTotal += r.count;
    }
  }

  logger.info("[compliance] backfill complete", {
    orgScope:        opts.orgId ?? "all",
    findings:        findings.length,
    mappingsCreated: createdTotal,
    mappingsRemoved: removedTotal,
  });

  return {
    findings:        findings.length,
    mappingsCreated: createdTotal,
    mappingsRemoved: removedTotal,
  };
}
