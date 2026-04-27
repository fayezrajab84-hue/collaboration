/**
 * attackPathSummaryService — Phase 27.5.x AI summary for one attack chain.
 *
 * Takes a chain (already loaded via attackPathService.getAttackPath), builds
 * a structured prompt that explains the SAST → DAST → PENTEST → cloud walk
 * in plain language, calls invokeAI through the existing aiClient (so org
 * routing + provider selection + telemetry all work uniformly), persists
 * the result to AttackPathSummary, and returns the cached row on subsequent
 * calls unless the chain's content has changed.
 *
 * Design choices:
 *   - Manual trigger only (operator clicks "Generate"). Auto-summarising
 *     every chain would burn AI budget on chains nobody opens. The button
 *     surfaces the cost honestly.
 *   - Two-field response shape: tldr (1-line, shown in the chain header)
 *     + narrative (2-3 paragraphs, shown in the expanded card / detail).
 *     Forces the model to compress the story rather than dump everything.
 *   - Cache by content hash. When the chain's findings change, the hash
 *     shifts; the UI compares hashes and shows "summary stale, regenerate?"
 *     rather than serving misleading text.
 *   - Best-effort: an AI provider outage does NOT block the rest of the
 *     attack-path UX — caller catches the throw and shows a toast.
 */
import { createHash } from "node:crypto";
import { z } from "zod";
import prisma from "../../db.js";
import { logger } from "../../logger.js";
import { invokeAI, AIError } from "../aiClient.js";
import { getAttackPath, type AttackPathSummary } from "./attackPathService.js";

// ── Public API ───────────────────────────────────────────────────────────

export interface AttackPathSummaryResult {
  groupId:      string;
  tldr:         string;
  narrative:    string;
  providerType: string;
  model:        string;
  contentHash:  string;
  generatedAt:  Date;
  cached:       boolean;
  /** True when the cached row's hash no longer matches the current chain. */
  stale:        boolean;
}

/**
 * Get the cached summary for a chain. Returns null if never generated.
 * Sets `stale: true` when the cached row's hash differs from the chain's
 * current content — the operator's UI then nudges to regenerate.
 */
export async function getCachedSummary(
  orgId: string,
  groupId: string,
): Promise<AttackPathSummaryResult | null> {
  const cached = await prisma.attackPathSummary.findUnique({ where: { correlationGroupId: groupId } });
  if (!cached || cached.orgId !== orgId) return null;

  const path = await getAttackPath(orgId, groupId);
  const stale = path ? computeContentHash(path) !== cached.contentHash : false;

  return {
    groupId,
    tldr:         cached.tldr,
    narrative:    cached.narrative,
    providerType: cached.providerType,
    model:        cached.model,
    contentHash:  cached.contentHash,
    generatedAt:  cached.generatedAt,
    cached:       true,
    stale,
  };
}

/**
 * Generate (or regenerate) the AI summary for a chain. Throws AIError on
 * provider failure so the caller can surface a toast — the rest of the
 * /attack-paths UX keeps working.
 *
 * Returns the freshly-persisted row marked `cached: false`. If the chain's
 * content hash matches an existing summary AND `force` is false, returns
 * that cached row instead of burning a new AI call.
 */
export async function generateSummary(
  orgId: string,
  groupId: string,
  opts: { force?: boolean } = {},
): Promise<AttackPathSummaryResult> {
  const path = await getAttackPath(orgId, groupId);
  if (!path) {
    throw new Error(`Attack path ${groupId} not found in org ${orgId}`);
  }
  const hash = computeContentHash(path);

  // Cache hit unless the operator forced a regen
  if (!opts.force) {
    const cached = await prisma.attackPathSummary.findUnique({ where: { correlationGroupId: groupId } });
    if (cached && cached.contentHash === hash && cached.orgId === orgId) {
      return {
        groupId,
        tldr:         cached.tldr,
        narrative:    cached.narrative,
        providerType: cached.providerType,
        model:        cached.model,
        contentHash:  cached.contentHash,
        generatedAt:  cached.generatedAt,
        cached:       true,
        stale:        false,
      };
    }
  }

  // ── Build the prompt ────────────────────────────────────────────────
  const prompt = buildPrompt(path);

  // ── Call AI with structured-output schema ───────────────────────────
  const schema = z.object({
    tldr:      z.string().min(8).max(280),
    narrative: z.string().min(40).max(2000),
  });

  let result;
  try {
    result = await invokeAI({
      service: "ATTACK_PATH_SUMMARY",
      orgId,
      system:  SYSTEM_PROMPT,
      messages: [{ role: "user", content: prompt }],
      schema,
      maxOutputTokens: 800,
      temperature:     0.2,
      timeoutMs:       60_000,
    });
  } catch (err) {
    if (err instanceof AIError) {
      logger.warn(`[attack-path-summary] AI call failed for chain ${groupId}: ${err.code} ${err.message}`);
    } else {
      logger.error(`[attack-path-summary] unexpected error for chain ${groupId}: ${(err as Error).message}`);
    }
    throw err;
  }

  // ── Persist + return ────────────────────────────────────────────────
  const persisted = await prisma.attackPathSummary.upsert({
    where:  { correlationGroupId: groupId },
    create: {
      orgId,
      correlationGroupId: groupId,
      tldr:         result.data.tldr,
      narrative:    result.data.narrative,
      providerType: result.providerType,
      model:        result.model,
      contentHash:  hash,
    },
    update: {
      tldr:         result.data.tldr,
      narrative:    result.data.narrative,
      providerType: result.providerType,
      model:        result.model,
      contentHash:  hash,
      generatedAt:  new Date(),
    },
  });

  return {
    groupId,
    tldr:         persisted.tldr,
    narrative:    persisted.narrative,
    providerType: persisted.providerType,
    model:        persisted.model,
    contentHash:  persisted.contentHash,
    generatedAt:  persisted.generatedAt,
    cached:       false,
    stale:        false,
  };
}

// ── Prompt construction ──────────────────────────────────────────────────

const SYSTEM_PROMPT = `You are a senior application-security engineer writing a concise, factual narrative for an attack-path correlation chain produced by a DevSecOps platform.

Your job: explain the chain in two parts, returned as JSON {tldr, narrative}.

GUIDELINES
- tldr: ONE sentence (max 280 chars) — the headline a CISO would read first.
  Lead with the impact, then the root cause. Example: "SQL injection in the
  authenticated user-edit endpoint chains to a container with a known RCE,
  enabling full DB takeover from a single login form."
- narrative: 2-3 short paragraphs (max 2000 chars total) — what the chain
  is, why these findings link, and the realistic exploit path. Use specific
  artifacts (URLs, file paths, CVEs, scan types) so the operator can verify
  your reasoning. Avoid generic security advice — the operator already
  knows what XSS is.
- NEVER overclaim: if confidence is POSSIBLE, say "likely" not "confirmed".
  Only say "confirmed" or "verified" when at least one node has confidence=
  CONFIRMED. Never invent CVEs or CVSS scores; only mention what's in the
  data you were given.
- Do NOT include any markdown code fences in your response. The schema
  expects plain text strings.
- Keep it sober: this is a security report, not marketing copy. No
  exclamation marks. No "we" or "I" — write in the third person.

Return STRICT JSON matching {tldr: string, narrative: string} — no preamble,
no postamble, no nested objects.`;

function buildPrompt(path: AttackPathSummary): string {
  const lines: string[] = [];
  lines.push(`# Attack-path chain to summarise`);
  lines.push(``);
  lines.push(`- Score: ${path.score}`);
  lines.push(`- Length: ${path.length} hops`);
  lines.push(`- Max severity: ${path.maxSeverity}`);
  lines.push(`- Confirmed exploit in chain: ${path.hasConfirmed ? "yes" : "no"}`);
  lines.push(`- External entry reach multiplier: ${path.externalReach}`);
  lines.push(``);
  lines.push(`## Nodes (in entry → deepest order)`);
  for (const [i, node] of path.nodes.entries()) {
    lines.push(`${i + 1}. [${node.scanType}] [${node.severity}] [${node.confidence}] ${node.title}`);
    if (node.targetName) lines.push(`   - target: ${node.targetType} \`${node.targetName}\``);
    if (node.filePath)   lines.push(`   - file:   \`${node.filePath}\``);
    // Pull the most useful 1-2 evidence keys without dumping everything.
    if (node.evidence) {
      const ev = node.evidence as Record<string, unknown>;
      if (ev["url"])           lines.push(`   - url:    ${truncate(String(ev["url"]), 200)}`);
      if (ev["payload"])       lines.push(`   - payload: ${truncate(String(ev["payload"]), 120)}`);
      if (ev["curl_command"])  lines.push(`   - curl:   (proof-of-exploit reproducer attached)`);
    }
  }
  lines.push(``);
  lines.push(`## Bridges (why the engine linked these findings)`);
  if (path.edges.length === 0) {
    lines.push(`(no edge metadata present)`);
  } else {
    for (const e of path.edges.slice(0, 25)) {
      lines.push(`- [${e.bridgeType}] [${e.confidence}] ${e.reason}`);
    }
    if (path.edges.length > 25) lines.push(`- … ${path.edges.length - 25} more bridges omitted`);
  }
  lines.push(``);
  lines.push(`Now produce the JSON {tldr, narrative}.`);
  return lines.join("\n");
}

function truncate(s: string, n: number): string {
  return s.length > n ? `${s.slice(0, n)}…` : s;
}

// ── Content hash ─────────────────────────────────────────────────────────
// Stable across runs as long as the chain's member set + scoring stays the
// same. Used to detect "summary is stale, regenerate?" without doing any
// per-finding diffing — just compare hashes.

function computeContentHash(path: AttackPathSummary): string {
  // Sort node + edge IDs so the hash is order-independent.
  const nodeIds = path.nodes.map((n) => n.findingId).sort().join("|");
  const edgeIds = path.edges
    .map((e) => `${[e.fromFindingId, e.toFindingId].sort().join("-")}:${e.bridgeType}`)
    .sort()
    .join("|");
  const inputs = [
    path.groupId,
    path.length.toString(),
    path.maxSeverity,
    path.hasConfirmed ? "1" : "0",
    nodeIds,
    edgeIds,
  ].join("\n");
  return createHash("sha256").update(inputs).digest("hex");
}

// Test-only re-exports
export const _testing = { computeContentHash, buildPrompt };
