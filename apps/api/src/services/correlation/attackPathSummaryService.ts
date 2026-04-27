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
  /** Phase 27.5.x — short headline (~6 words) for the chain card title.
   *  Generated alongside tldr+narrative; null only on legacy rows from
   *  before this field existed (will refill on next regenerate). */
  title:        string | null;
  tldr:         string;
  narrative:    string;
  /** Phase 27.5.x — AI verification of the chain. Bundled into the same
   *  AI call as the summary so it costs ~$0.001 extra per chain on cloud
   *  models. Null on legacy rows (will populate on next regenerate). */
  verdict:           "LIKELY_REAL" | "MIXED_SIGNAL" | "LIKELY_NOISE" | null;
  verdictConfidence: number | null;  // 0-100
  verdictReasoning:  string | null;
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
    title:             cached.title,
    tldr:              cached.tldr,
    narrative:         cached.narrative,
    verdict:           toVerdict(cached.verdict),
    verdictConfidence: cached.verdictConfidence,
    verdictReasoning:  cached.verdictReasoning,
    providerType:      cached.providerType,
    model:             cached.model,
    contentHash:       cached.contentHash,
    generatedAt:       cached.generatedAt,
    cached:            true,
    stale,
  };
}

function toVerdict(raw: string | null): "LIKELY_REAL" | "MIXED_SIGNAL" | "LIKELY_NOISE" | null {
  if (raw === "LIKELY_REAL" || raw === "MIXED_SIGNAL" || raw === "LIKELY_NOISE") return raw;
  return null;
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
        title:             cached.title,
        tldr:              cached.tldr,
        narrative:         cached.narrative,
        verdict:           toVerdict(cached.verdict),
        verdictConfidence: cached.verdictConfidence,
        verdictReasoning:  cached.verdictReasoning,
        providerType:      cached.providerType,
        model:             cached.model,
        contentHash:       cached.contentHash,
        generatedAt:       cached.generatedAt,
        cached:            true,
        stale:             false,
      };
    }
  }

  // ── Build the prompt ────────────────────────────────────────────────
  const prompt = buildPrompt(path);

  // ── Call AI with structured-output schema ───────────────────────────
  // Length contract: enforce MIN to catch empty AI responses, but don't
  // hard-fail on MAX overshoot — providers regularly produce slightly
  // longer text than asked. Instead transform overlong fields by clipping
  // at the last sentence/word boundary that fits.
  //
  // Tight by design (operator feedback: "summary is too big to read"):
  //   tldr      → ~200 chars (one short sentence)
  //   narrative → ~600 chars (3-5 brief bullet lines, not paragraphs)
  //   verdictReasoning → ~300 chars (1-2 sentences)
  // Together a single chain summary fits in one screen of the card.
  const schema = z.object({
    title:             z.string().min(3).transform((s) => clipText(s, 80)),
    tldr:              z.string().min(8).transform((s) => clipText(s, 200)),
    narrative:         z.string().min(20).transform((s) => clipText(s, 600)),
    verdict:           z.enum(["LIKELY_REAL", "MIXED_SIGNAL", "LIKELY_NOISE"]),
    verdictConfidence: z.number().int().min(0).max(100),
    verdictReasoning:  z.string().min(8).transform((s) => clipText(s, 300)),
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
      title:             result.data.title,
      tldr:              result.data.tldr,
      narrative:         result.data.narrative,
      verdict:           result.data.verdict,
      verdictConfidence: result.data.verdictConfidence,
      verdictReasoning:  result.data.verdictReasoning,
      providerType:      result.providerType,
      model:             result.model,
      contentHash:       hash,
    },
    update: {
      title:             result.data.title,
      tldr:              result.data.tldr,
      narrative:         result.data.narrative,
      verdict:           result.data.verdict,
      verdictConfidence: result.data.verdictConfidence,
      verdictReasoning:  result.data.verdictReasoning,
      providerType:      result.providerType,
      model:             result.model,
      contentHash:       hash,
      generatedAt:       new Date(),
    },
  });

  return {
    groupId,
    title:             persisted.title,
    tldr:              persisted.tldr,
    narrative:         persisted.narrative,
    verdict:           toVerdict(persisted.verdict),
    verdictConfidence: persisted.verdictConfidence,
    verdictReasoning:  persisted.verdictReasoning,
    providerType:      persisted.providerType,
    model:             persisted.model,
    contentHash:       persisted.contentHash,
    generatedAt:       persisted.generatedAt,
    cached:            false,
    stale:             false,
  };
}

// ── Prompt construction ──────────────────────────────────────────────────

const SYSTEM_PROMPT = `You are a senior application-security engineer writing a concise, factual narrative for an attack-path correlation chain produced by a DevSecOps platform.

Your job: explain AND verify the chain, returned as JSON
{title, tldr, narrative, verdict, verdictConfidence, verdictReasoning}.

NARRATIVE GUIDELINES — BE TIGHT. The operator skims dozens of chains per
day. Every word costs them attention. Each field has a strict budget;
anything you write past it is wasted.

- title: 3-8 words (max 80 chars). The chain card's HEADLINE. Concrete,
  specific, lead with the vulnerability + asset. Examples:
    "SQL injection in DVWA login form"
    "RCE via libxml2 CVE-2022-2309 in API container"
    "XSS reflected on /vulnerabilities/xss_r/"
  No generic phrases like "security issues found". No trailing period.

- tldr: ONE short sentence (max 200 chars). The impact summary a CISO
  would read first. Lead with impact, then root cause. Example:
  "SQL injection in the user-edit endpoint enables full DB takeover via
  the login form."

- narrative: 3-5 BULLET POINTS (max 600 chars total — that's ~120 chars
  per bullet, ~16 words each). Format: each bullet on its own line,
  prefixed with "• " (bullet character + space). NO paragraphs. NO
  intros. NO concluding sentences. Each bullet states ONE fact:
    • Source: SAST flagged unsanitized $_GET in login.php:6
    • Reach: DAST confirmed reflection at /login.php
    • Container: libapache2 has CVE-2021-44790 (RCE)
    • Asset link: container serves the dvwa domain
    • Exploit: PENTEST extracted DB schema via this URL
  Use specific artifacts (URLs, file paths, CVEs, line numbers). NO
  generic security advice. NO "the chain shows" / "this represents".
  Just facts.

VERIFICATION (you are the second-opinion sanity check on the engine's chain)
- verdict: pick exactly one of:
    "LIKELY_REAL"   — the bridge edges are semantically sound; this chain
                       describes a plausible attack path an attacker could
                       walk. The findings genuinely relate.
    "MIXED_SIGNAL"  — some edges are real, some are coincidental token
                       matches; the chain is a starting point for triage
                       but shouldn't be treated as a single attack path.
    "LIKELY_NOISE"  — the bridges that linked these findings are mostly
                       coincidence (e.g. shared common path tokens); the
                       chain doesn't describe a meaningful attack flow.
- verdictConfidence: integer 0-100. Your self-reported certainty in the
  verdict. Sub-50 means "I'm guessing"; 80+ means "I'd stake my reputation".
- verdictReasoning: 1-2 short sentences (max 300 chars). Cite the
  specific bridge edges and why they're (or aren't) real. Example:
  "SAST exec.php and DAST /vulnerabilities/exec/ share both endpoint and
  rule class — real chain. Container glibc CVE is blast-radius noise."

CONFIDENCE DISCIPLINE
- NEVER overclaim: if a node's confidence is POSSIBLE, say "likely" not
  "confirmed". Only say "confirmed" or "verified" when at least one node
  has confidence=CONFIRMED.
- Never invent CVEs, CVSS scores, line numbers, or package versions —
  only mention what's in the data you were given.

FORMATTING
- Do NOT include any markdown code fences. The schema expects plain text
  strings.
- Keep it sober: this is a security report, not marketing copy. No
  exclamation marks. No "we" or "I" — write in the third person.

Return STRICT JSON matching the six required fields above — no preamble,
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

/**
 * Smart text clipping for AI-produced strings that overshoot the budget.
 *
 * Tries to find a clean break point in this priority order:
 *   1. Last sentence-ending punctuation (. ! ?) within the budget
 *   2. Last whitespace within the budget
 *   3. Hard cut at the budget with an ellipsis
 *
 * The minimum acceptable break point is 60% of the budget — below that
 * we'd be discarding too much content, so we hard-cut instead. This avoids
 * the case where the only sentence break is at char 5 of a 400-char budget.
 */
function clipText(raw: string, max: number): string {
  const s = raw.trim();
  if (s.length <= max) return s;

  const minAcceptable = Math.floor(max * 0.6);

  // Look for the last sentence-ending punctuation in [minAcceptable, max].
  // Slice once to bound the search, then walk back from the end.
  const window = s.slice(0, max);
  for (let i = window.length - 1; i >= minAcceptable; i--) {
    const c = window[i];
    if (c === "." || c === "!" || c === "?") return window.slice(0, i + 1);
  }
  // Fall back to the last whitespace in the same window.
  for (let i = window.length - 1; i >= minAcceptable; i--) {
    if (/\s/.test(window[i] ?? "")) return `${window.slice(0, i).trimEnd()}…`;
  }
  // Hard cut.
  return `${window.trimEnd()}…`;
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
export const _testing = { computeContentHash, buildPrompt, clipText };
