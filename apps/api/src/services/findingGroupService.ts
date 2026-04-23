/**
 * Finding Group Service (Phase 6 — Smart Deduplication)
 *
 * Algorithmically clusters open findings by:
 *   1. ruleId  — same static-analysis rule fired in multiple places
 *   2. cveId   — same CVE across multiple packages / images
 *   3. normalised title — for findings without a ruleId or cveId
 *
 * AI insight is generated on-demand per group and cached in-process
 * (good enough for a single-instance deployment).
 */

import { AIServiceName } from "@prisma/client";
import prisma from "../db.js";
import { logger } from "../logger.js";
import { invokeAI, AIError } from "./aiClient.js";
import type { FindingGroup } from "@devsecops/types";

// ── In-process cache: groupKey → { insight, cachedAt } ───────────────────────
const insightCache = new Map<string, { insight: string; cachedAt: number }>();
const CACHE_TTL_MS = 60 * 60 * 1000; // 1 hour

// ── Helpers ───────────────────────────────────────────────────────────────────

function targetName(f: {
  repository?: { fullName: string } | null;
  container?:  { imageRef: string }  | null;
  domain?:     { domain: string }    | null;
}): string {
  return f.repository?.fullName ?? f.container?.imageRef ?? f.domain?.domain ?? "unknown";
}

/** Strip version numbers and noise to normalise similar titles into one group key */
function normaliseTitle(title: string): string {
  return title
    .toLowerCase()
    .replace(/\bv?\d+(\.\d+)+\b/g, "")   // strip version numbers
    .replace(/[^a-z0-9 ]/g, " ")
    .replace(/\s+/g, " ")
    .trim()
    .slice(0, 80);
}

// ── Main grouping function ────────────────────────────────────────────────────

export async function getOrgFindingGroups(orgId: string): Promise<FindingGroup[]> {
  // Fetch all open findings with their target names
  const findings = await prisma.finding.findMany({
    where: { orgId, status: { in: ["OPEN", "ACKNOWLEDGED"] } },
    select: {
      id:          true,
      title:       true,
      severity:    true,
      scanType:    true,
      ruleId:      true,
      cveId:       true,
      repository:  { select: { fullName: true } },
      container:   { select: { imageRef: true } },
      domain:      { select: { domain: true } },
    },
  });

  if (findings.length === 0) return [];

  // Group into buckets: key → findings[]
  const buckets = new Map<string, typeof findings>();

  for (const f of findings) {
    let key: string;
    if (f.ruleId) {
      key = `rule:${f.scanType}:${f.ruleId}`;
    } else if (f.cveId) {
      key = `cve:${f.cveId}`;
    } else {
      key = `title:${f.scanType}:${normaliseTitle(f.title)}`;
    }

    if (!buckets.has(key)) buckets.set(key, []);
    buckets.get(key)!.push(f);
  }

  // Build groups — only include buckets with 2+ findings (singletons aren't patterns)
  const groups: FindingGroup[] = [];

  for (const [key, items] of buckets.entries()) {
    if (items.length < 2) continue;

    const sevCounts = { criticalCount: 0, highCount: 0, mediumCount: 0, lowCount: 0 };
    for (const f of items) {
      if (f.severity === "CRITICAL") sevCounts.criticalCount++;
      else if (f.severity === "HIGH") sevCounts.highCount++;
      else if (f.severity === "MEDIUM") sevCounts.mediumCount++;
      else if (f.severity === "LOW") sevCounts.lowCount++;
    }

    const uniqueTargets = [...new Set(items.map(targetName))];

    // Load cached AI insight if present and fresh
    const cached = insightCache.get(key);
    const aiInsight =
      cached && Date.now() - cached.cachedAt < CACHE_TTL_MS
        ? cached.insight
        : null;

    groups.push({
      key,
      label:          items[0]!.title,
      scanType:       items[0]!.scanType,
      count:          items.length,
      ...sevCounts,
      affectedTargets: uniqueTargets.slice(0, 5),
      sampleFindings:  items.slice(0, 3).map((f) => ({
        id:         f.id,
        title:      f.title,
        severity:   f.severity,
        targetName: targetName(f),
      })),
      aiInsight,
    });
  }

  // Sort: most critical first, then by count
  groups.sort((a, b) => {
    const scoreA = a.criticalCount * 8 + a.highCount * 4 + a.mediumCount * 2 + a.lowCount;
    const scoreB = b.criticalCount * 8 + b.highCount * 4 + b.mediumCount * 2 + b.lowCount;
    if (scoreB !== scoreA) return scoreB - scoreA;
    return b.count - a.count;
  });

  return groups;
}

// ── On-demand AI insight ──────────────────────────────────────────────────────

export async function generateGroupInsight(
  orgId: string,
  groupKey: string,
): Promise<string> {
  // Return cached insight if fresh
  const cached = insightCache.get(groupKey);
  if (cached && Date.now() - cached.cachedAt < CACHE_TTL_MS) {
    return cached.insight;
  }

  // Fetch representative findings for this group
  let where: Record<string, unknown> = { orgId, status: { in: ["OPEN", "ACKNOWLEDGED"] } };

  if (groupKey.startsWith("rule:")) {
    const parts = groupKey.slice(5).split(":");
    where["scanType"] = parts[0];
    where["ruleId"]   = parts.slice(1).join(":");
  } else if (groupKey.startsWith("cve:")) {
    where["cveId"] = groupKey.slice(4);
  } else {
    // title-based group — can't easily reconstruct filter; fall back to label search
    const label = groupKey.replace(/^title:[^:]+:/, "");
    where["title"] = { contains: label.slice(0, 30), mode: "insensitive" as const };
  }

  const samples = await prisma.finding.findMany({
    where,
    take: 4,
    orderBy: [{ severity: "asc" }, { firstSeen: "desc" }],
    select: {
      title:       true,
      description: true,
      severity:    true,
      scanType:    true,
      cveId:       true,
      ruleId:      true,
      repository:  { select: { fullName: true } },
      container:   { select: { imageRef: true } },
      domain:      { select: { domain: true } },
    },
  });

  if (samples.length === 0) {
    return "No findings found for this group.";
  }

  const sampleText = samples
    .map((f) => `- [${f.severity}] ${f.title} on ${targetName(f)}${f.cveId ? ` (${f.cveId})` : ""}`)
    .join("\n");

  const SYSTEM = `You are a security expert. Findings shown share a common root cause.
In 3-4 sentences: (1) identify the shared root cause, (2) explain the risk, (3) give one concrete unified fix.
Be concise. Do not use headings.`;
  const prompt = `Findings:
${sampleText}

Analysis:`;

  let insight: string;
  try {
    const result = await invokeAI({
      service:         AIServiceName.GROUP_INSIGHT,
      orgId,
      system:          SYSTEM,
      messages:        [{ role: "user", content: prompt }],
      maxOutputTokens: 250,
      temperature:     0.2,
      timeoutMs:       300_000,
    });
    insight = result.data.trim();
  } catch (err) {
    if (err instanceof AIError) {
      logger.error(`[findingGroups] invokeAI failed for ${groupKey}: ${err.kind} — ${err.message}`);
      if (err.kind === "INVALID_OUTPUT") {
        throw new Error("AI returned an unreadable response — please try again.");
      }
      throw new Error(
        `AI service is unavailable (${err.kind}). Check that the configured provider is reachable. (${err.message})`,
      );
    }
    throw err;
  }
  if (!insight) throw new Error("Empty insight from AI");

  // Cache it
  insightCache.set(groupKey, { insight, cachedAt: Date.now() });
  logger.info(`[findingGroups] insight cached for key ${groupKey}`);

  return insight;
}
