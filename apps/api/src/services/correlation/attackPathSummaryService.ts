/**
 * attackPathSummaryService — Phase 27.5.x AI summary for one attack chain.
 *
 * Takes a chain (already loaded via attackPathService.getAttackPath), builds
 * a structured prompt that explains the SAST → CONTAINER → DAST → PENTEST →
 * RUNTIME walk in plain language, calls invokeAI through the existing
 * aiClient (so org routing + provider selection + telemetry all work
 * uniformly), persists the result to AttackPathSummary, and returns the
 * cached row on subsequent calls unless the chain's content has changed.
 *
 * Phase 28 update: the system prompt now teaches the model that RUNTIME
 * findings come from a Wazuh agent on the live workload — so the narrative
 * can complete the "did this attack actually happen?" question with
 * runtime evidence, not just static + dynamic test findings.
 *
 * Phase 27.5.y update: the AI call now also produces a structured
 * `workflow` — an ordered list of 2-6 attack steps, each citing the
 * specific finding IDs that prove it. This powers the AttackPathWorkflow
 * UI: a step-by-step walk through the kill-chain (source → image →
 * surface → runtime) grounded in real evidence rather than narrative
 * prose. The model is forbidden from inventing IDs — the schema's
 * evidenceFindingIds transform filters out any ID that doesn't exist
 * in the chain's node set, so hallucinated citations get dropped before
 * persistence.
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
import type { WorkflowStep } from "@devsecops/types";
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
  /** Phase 27.5.y — ordered attack workflow. Null on legacy rows
   *  generated before this field existed; populates on next regenerate. */
  workflow:          WorkflowStep[] | null;
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
    workflow:          parseWorkflow(cached.workflow),
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

  // Cache hit unless the operator forced a regen.
  // Phase 27.5.y: legacy rows missing `workflow` should regenerate even
  // when their hash still matches — otherwise the workflow panel never
  // populates without an explicit force=true. Treating null-workflow as
  // a synthetic miss keeps the operator's "Generate" → workflow visible
  // experience predictable.
  if (!opts.force) {
    const cached = await prisma.attackPathSummary.findUnique({ where: { correlationGroupId: groupId } });
    const workflow = cached ? parseWorkflow(cached.workflow) : null;
    if (cached && cached.contentHash === hash && cached.orgId === orgId && workflow !== null) {
      return {
        groupId,
        title:             cached.title,
        tldr:              cached.tldr,
        narrative:         cached.narrative,
        verdict:           toVerdict(cached.verdict),
        verdictConfidence: cached.verdictConfidence,
        verdictReasoning:  cached.verdictReasoning,
        workflow,
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
  const validFindingIds = new Set(path.nodes.map((n) => n.findingId));

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
  //
  // Phase 27.5.y — workflow is an ordered list of 3-6 attack steps. The
  // AI must cite finding IDs that actually exist in the chain (we filter
  // hallucinated IDs in a transform — never trust the model's set
  // membership claim against an external set). Total budget: 6 steps × 4
  // IDs × 30 chars + 6 × ~320 chars text ≈ ~2.7KB raw, well within
  // structured-output limits.
  const stepSchema = z.object({
    stepNumber:         z.number().int().min(1),
    phase:              z.enum(["source", "image", "surface", "runtime"]),
    // Phase 27.5.y refinement: tightened from 80 → 60 chars after operator
    // feedback that titles were wrapping awkwardly inside the 18rem step
    // card. 60 chars × 13px font fits a single tight line; longer titles
    // get clipped at the last sentence/word boundary by clipText.
    title:              z.string().min(3).transform((s) => clipText(s, 60)),
    description:        z.string().min(8).transform((s) => clipText(s, 180)),
    evidenceFindingIds: z.array(z.string())
                          .transform((ids) => ids.filter((id) => validFindingIds.has(id)).slice(0, 4))
                          .pipe(z.array(z.string()).min(1).max(4)),
    // Tolerant of model output: trim, validate against the MITRE pattern,
    // and DROP if invalid rather than rejecting the whole workflow. The
    // model occasionally returns "T1213.001 (description)" or "T2156" or
    // free-text — better to lose that one badge than fail the entire
    // regenerate. The Zod chain returns `undefined` for invalid input,
    // which `.optional()` accepts.
    technique:          z.preprocess(
                          (v) => {
                            if (typeof v !== "string") return v;
                            const trimmed = v.trim();
                            return /^T\d{4}(\.\d{3})?$/.test(trimmed) ? trimmed : undefined;
                          },
                          z.string().regex(/^T\d{4}(\.\d{3})?$/).optional(),
                        ),
  });
  const schema = z.object({
    title:             z.string().min(3).transform((s) => clipText(s, 80)),
    tldr:              z.string().min(8).transform((s) => clipText(s, 200)),
    narrative:         z.string().min(20).transform((s) => clipText(s, 600)),
    verdict:           z.enum(["LIKELY_REAL", "MIXED_SIGNAL", "LIKELY_NOISE"]),
    verdictConfidence: z.number().int().min(0).max(100),
    verdictReasoning:  z.string().min(8).transform((s) => clipText(s, 300)),
    // Phase 27.5.y — 3-6 ordered steps walking the kill-chain.
    workflow:          z.array(stepSchema).min(2).max(6)
                          .transform((steps) => steps.map((s, i) => ({ ...s, stepNumber: i + 1 }))),
  });

  let result;
  try {
    result = await invokeAI({
      service: "ATTACK_PATH_SUMMARY",
      orgId,
      system:  SYSTEM_PROMPT,
      messages: [{ role: "user", content: prompt }],
      schema,
      // Bumped from 800 → 2400: workflow adds ~3-6 step objects (~150
      // tokens each) on top of title+tldr+narrative+verdict. The DVWA
      // 81-node chain reproduced "model returned non-JSON: \\\`\\\`\\\`json {..."
      // truncation at 1400 — the model was emitting valid fenced JSON
      // but the output was getting cut off mid-string before the
      // closing fence. 2400 leaves comfortable headroom for the largest
      // chains we've seen. Cost impact ~$0.01 per regenerate on
      // claude-sonnet, still under the per-call budget.
      maxOutputTokens: 2400,
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
  // workflow is JSON in Postgres — Prisma accepts an array directly.
  const workflowJson = result.data.workflow as unknown as Parameters<typeof prisma.attackPathSummary.upsert>[0]["create"]["workflow"];
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
      workflow:          workflowJson,
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
      workflow:          workflowJson,
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
    workflow:          parseWorkflow(persisted.workflow),
    providerType:      persisted.providerType,
    model:             persisted.model,
    contentHash:       persisted.contentHash,
    generatedAt:       persisted.generatedAt,
    cached:            false,
    stale:             false,
  };
}

/**
 * Parse a stored workflow JSON column back into a typed array.
 * Returns null on legacy rows (column never written) or on any shape
 * that doesn't pass a minimal sanity check. Defensive: if Prisma
 * returned a string somehow, JSON.parse it; if it returned a non-array,
 * drop to null. Better to hide the panel than render a broken list.
 */
function parseWorkflow(raw: unknown): WorkflowStep[] | null {
  if (raw == null) return null;
  let arr: unknown = raw;
  if (typeof arr === "string") {
    try { arr = JSON.parse(arr); } catch { return null; }
  }
  if (!Array.isArray(arr) || arr.length === 0) return null;
  // Trust the schema validation that wrote this row — we only check the
  // top-level shape. Bad data here means somebody wrote past the schema.
  const isStep = (s: unknown): s is WorkflowStep =>
    typeof s === "object" && s != null
    && "stepNumber" in s && "phase" in s && "title" in s
    && "description" in s && "evidenceFindingIds" in s;
  return arr.every(isStep) ? (arr as WorkflowStep[]) : null;
}

// ── Prompt construction ──────────────────────────────────────────────────

const SYSTEM_PROMPT = `You are a senior application-security engineer writing a concise, factual narrative for an attack-path correlation chain produced by a DevSecOps platform.

Your job: explain AND verify the chain, returned as JSON
{title, tldr, narrative, verdict, verdictConfidence, verdictReasoning, workflow}.

SCAN TYPES YOU WILL SEE (in entry → deepest order):
  SAST          — static analysis flagged a vulnerable code path in the
                   source repository.
  SCA           — third-party dependency CVE in the source.
  SECRET        — leaked credential / token in source.
  IAC           — infrastructure-as-code misconfiguration.
  CONTAINER     — image-layer CVE in the deployed container image.
  DAST          — black-box scanner (ZAP) reproduced the issue against
                   the running web application.
  PENTEST_FULL  — active exploit (sqlmap, xsstrike, dalfox, commix,
                   nuclei, etc.) confirmed the vulnerability with a
                   reproducer payload.
  RUNTIME       — Wazuh agent on the LIVE workload host emitted a
                   security alert (file integrity, audit, network,
                   command execution). RUNTIME = "this attack is
                   happening or has happened on the production host",
                   not just "could happen". Treat RUNTIME as the
                   strongest signal in the chain when present — it
                   collapses the gap between "vulnerability exists"
                   and "vulnerability is being exploited".

NARRATIVE GUIDELINES — BE TIGHT. The operator skims dozens of chains per
day. Every word costs them attention. Each field has a strict budget;
anything you write past it is wasted.

- title: 3-8 words (max 80 chars). The chain card's HEADLINE. Concrete,
  specific, lead with the vulnerability + asset. Examples:
    "SQL injection in DVWA login form"
    "RCE via libxml2 CVE-2022-2309 in API container"
    "XSS reflected on /vulnerabilities/xss_r/"
    "Live RCE on dvwa-host — CVE chain matches Wazuh alerts"
  No generic phrases like "security issues found". No trailing period.

- tldr: ONE short sentence (max 200 chars). The impact summary a CISO
  would read first. Lead with impact, then root cause. When RUNTIME
  alerts are present, lead with that — it's the difference between a
  potential and an active incident. Example:
  "Wazuh fired 8 high-severity audit alerts on dvwa-host matching the
  same SQLi endpoint a PENTEST exploit reproduced — likely active
  exploitation in production."

- narrative: 3-5 BULLET POINTS (max 600 chars total — that's ~120 chars
  per bullet, ~16 words each). Format: each bullet on its own line,
  prefixed with "• " (bullet character + space). NO paragraphs. NO
  intros. NO concluding sentences. When RUNTIME nodes are present in
  the chain, ALWAYS include a runtime bullet — its omission is a bug.
  Each bullet states ONE fact:
    • Source: SAST flagged unsanitized $_GET in login.php:6
    • Reach: DAST confirmed reflection at /login.php
    • Container: libapache2 has CVE-2021-44790 (RCE)
    • Asset link: container serves the dvwa domain
    • Exploit: PENTEST extracted DB schema via this URL
    • Runtime: Wazuh fired 9 audit alerts on dvwa-host matching this URL
  Use specific artifacts (URLs, file paths, CVEs, line numbers, Wazuh
  rule IDs, agent names). NO generic security advice. NO "the chain
  shows" / "this represents". Just facts.

VERIFICATION (you are the second-opinion sanity check on the engine's chain)
- verdict: pick exactly one of:
    "LIKELY_REAL"   — the bridge edges are semantically sound; this chain
                       describes a plausible attack path an attacker could
                       walk. The findings genuinely relate. RUNTIME
                       alerts on the same workload as a CONFIRMED exploit
                       finding push strongly toward LIKELY_REAL — that's
                       production telemetry, not just test findings.
    "MIXED_SIGNAL"  — some edges are real, some are coincidental token
                       matches; the chain is a starting point for triage
                       but shouldn't be treated as a single attack path.
    "LIKELY_NOISE"  — the bridges that linked these findings are mostly
                       coincidence (e.g. shared common path tokens); the
                       chain doesn't describe a meaningful attack flow.
- verdictConfidence: integer 0-100. Your self-reported certainty in the
  verdict. Sub-50 means "I'm guessing"; 80+ means "I'd stake my reputation".
  When RUNTIME nodes corroborate a CONFIRMED PENTEST/DAST node on the same
  workload, raise confidence — these are independent observations from
  different telemetry pipelines converging on the same conclusion.
- verdictReasoning: 1-2 short sentences (max 300 chars). Cite the
  specific bridge edges and why they're (or aren't) real. Example:
  "SAST exec.php and DAST /vulnerabilities/exec/ share both endpoint and
  rule class — real chain. Wazuh runtime alerts on dvwa-host independently
  corroborate the PENTEST exploit; this is happening in production."

WORKFLOW (the ordered attack walk-through)
The workflow is what an attacker would actually DO with this chain, in
order. Produce 2-6 steps that walk the chain from outer entry point to
deepest impact, following this canonical kill-chain order:

  source  →  image  →  surface  →  pentest/exploit  →  runtime

Phase mapping (use exactly these phase strings in JSON):
  "source"  — SAST / IAC / SECRET findings (what's wrong in the code)
  "image"   — SCA / CONTAINER findings (what's wrong in dependencies/image)
  "surface" — DAST / PENTEST_FULL findings (what an external scanner saw or
              actively exploited against the running app)
  "runtime" — RUNTIME findings (what the live workload host is reporting)

Step contract (per step):
- stepNumber: 1, 2, 3, ... (you provide them; they will be re-numbered).
- phase: one of "source" | "image" | "surface" | "runtime".
- title: 4-8 words, MAX 60 CHARS. The action — a human-readable verb.
  Lead with the verb, drop filler words like "in source" / "on host" /
  "in container" — those are redundant with the phase chip. Examples:
    "Locate unsanitized $_GET in login.php"
    "Confirm CVE-2022-2309 in libxml2 layer"
    "Reproduce SQL injection via /login.php"
    "Detect post-exploit shell"
- description: 1-2 sentences (MAX 180 CHARS). What the step DOES, citing
  the specific evidence (CVE / URL / payload / Wazuh rule). NEVER
  generic ("the attacker exploits the vulnerability"). Be concrete.
  Drop preamble like "The attacker..." / "Attackers can..." — start
  with the verb-phrase directly ("Reproduces SQL injection at...",
  "Detects file-integrity violation on...").
- evidenceFindingIds: 1-4 finding IDs from the chain that PROVE this
  step. CRITICAL: these IDs MUST come from the # Nodes section of the
  user prompt. Do NOT invent IDs. The system filters out unknown IDs
  and rejects the response if a step ends up with zero valid evidence.
- technique: OPTIONAL MITRE ATT&CK technique. PHASE-APPROPRIATE
  TECHNIQUES — pick from these or OMIT the field. Do NOT guess.
  Earlier regenerations produced T1498 (Network DoS) for an OpenSSL
  CVE in a container layer — that's wrong. The list below is the
  authoritative one; if NONE fit, leave the field blank.

    SOURCE phase (SAST / IAC / SECRET):
      T1059          Command and Scripting Interpreter
                       — when SAST flags command injection / unsafe exec
      T1552          Unsecured Credentials in Files
                       — when SECRET finds a leaked token / password
      T1078          Valid Accounts
                       — when leaked credentials map to a real account
      omit if the SAST finding is just code-quality without a clear TTP

    IMAGE phase (SCA / CONTAINER):
      T1190          Exploit Public-Facing Application
                       — CVE in a publicly-served library
      T1525          Implant Internal Image
                       — vulnerable / outdated base image
      T1505          Server Software Component
                       — vulnerable framework / web server module
      omit for general SCA findings without a known exploit path

    SURFACE phase (DAST / PENTEST_FULL):
      T1190          Exploit Public-Facing Application (most common)
      T1059          Command and Scripting Interpreter (RCE / cmd-i)
      T1212          Exploitation for Credential Access (auth bypass)
      T1187          Forced Authentication
      omit for unverified scanner alerts

    RUNTIME phase (Wazuh):
      T1059.004      Unix Shell — shell command alerts
      T1548          Abuse Elevation Control — sudo / privesc
      T1098          Account Manipulation — user/account changes
      T1565          Data Manipulation — FIM on critical files
                       (e.g. /etc/passwd, /etc/shadow rule 550/553)
      T1078          Valid Accounts — successful auth from new source
      omit for generic process / network alerts

  Skip the technique field entirely when none of the phase-appropriate
  techniques fit. Better to omit than misclassify — the operator
  trusts the badge to mean what it says.

Workflow guidelines:
- Follow the canonical phase order. NEVER reorder backwards (a
  "runtime" step cannot precede a "surface" step that explains it).
- Skip phases that have no evidence — a 3-step workflow with only
  source + surface + runtime is fine if image has nothing relevant.
- DO NOT produce one step per finding. Group related findings under
  one step (e.g. "Exploit CONFIRMED via 3 different XSS payloads" cites
  three finding IDs, one step). Keep total step count to 2-6.
- A step with a CONFIRMED-confidence evidence finding should make the
  certainty visible in its description ("PENTEST exploit reproduced
  with payload <SCRIPT>..."). A step with only POSSIBLE/LIKELY
  evidence should hedge ("DAST signature suggests reflected XSS
  reachable, not yet reproduced").
- The LAST step should describe the impact / what the attacker
  achieves, grounded in the deepest-evidence node (usually runtime if
  present, else exploit, else surface).

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
  lines.push(`Each node is prefixed with its FINDING ID — when you fill the`);
  lines.push(`workflow field, you MUST cite these exact IDs in evidenceFindingIds.`);
  lines.push(``);
  for (const [i, node] of path.nodes.entries()) {
    lines.push(`${i + 1}. id=\`${node.findingId}\` [${node.scanType}] [${node.severity}] [${node.confidence}] ${node.title}`);
    if (node.targetName) lines.push(`   - target: ${node.targetType} \`${node.targetName}\``);
    if (node.filePath)   lines.push(`   - file:   \`${node.filePath}\``);
    if (node.cveId)      lines.push(`   - cve:    ${node.cveId}`);
    if (node.packageName) lines.push(`   - pkg:    ${node.packageName}${node.packageVersion ? `@${node.packageVersion}` : ""}`);
    if (node.ruleId)     lines.push(`   - rule:   ${node.ruleId}`);
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
  lines.push(`Now produce the JSON {title, tldr, narrative, verdict,`);
  lines.push(`verdictConfidence, verdictReasoning, workflow}. The workflow`);
  lines.push(`is an ordered array of 2-6 attack steps (source → image → surface`);
  lines.push(`→ runtime kill-chain order); each step's evidenceFindingIds MUST`);
  lines.push(`reference IDs from the Nodes section above.`);
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
