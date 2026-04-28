/**
 * findingTags — server-side predicate vocabulary for "tags" on findings.
 *
 * Each tag is a NAMED predicate. The same name is used by:
 *   - GET /findings?tag=<name>          (filter the list)
 *   - GET /findings/summary/stats?tag=  (count under that name)
 *   - Dashboard cards (display the count)
 *   - Click-through navigation          (`?tab=runtime&tag=<name>`)
 *
 * Single source of truth means card-number ≡ destination-number — no
 * predicate drift possible. The earlier approach (cards filter by
 * `wasExploitSuccessful` client-side, navigation reconstructs an
 * approximate URL with `severity=...`) was the source of the
 * mismatch bug; this module replaces it.
 *
 * Vocabulary:
 *   - runtime-exploit   — Wazuh detected attack succeeded (HTTP 2xx, audit
 *                         success, post-compromise tactic, success-language).
 *   - runtime-attack    — Wazuh detected attack but no success signal.
 *   - confirmed-exploit — scanner-confirmed Proof of Exploit. confidence=
 *                         CONFIRMED + evidence.url + evidence.attack. Cross-
 *                         tier (DAST / PENTEST / RUNTIME). This is the
 *                         badge-eligible "we have a working reproducer"
 *                         population.
 *   - ai-suppressed     — AI false-positive detector flagged the finding
 *                         as LIKELY_FP at HIGH or MEDIUM confidence. Useful
 *                         for the "what is the AI hiding from me?" view.
 *
 * Implementation note: Prisma JSON queries can express array_contains
 * but not regex / numeric-coerce on JSON paths, so tag evaluation is a
 * two-stage filter:
 *   1. Cheap server-side WHERE narrows to candidates (scanType,
 *      severity floor, status, confidence) using indexed columns.
 *   2. JS predicate evaluates the JSON evidence + title/description
 *      regex against those candidates.
 * For the org sizes we target (low thousands of findings per tag) the
 * JS pass is sub-100ms and stays cache-warm via React Query refetch.
 */
import type { Finding } from "@prisma/client";

export type TagName =
  | "runtime-exploit"
  | "runtime-attack"
  | "confirmed-exploit"
  | "ai-suppressed";

export const ALL_TAGS: TagName[] = [
  "runtime-exploit",
  "runtime-attack",
  "confirmed-exploit",
  "ai-suppressed",
];

export function isKnownTag(name: string): name is TagName {
  return (ALL_TAGS as string[]).includes(name);
}

// ── Tag predicates (JS-side, evaluated against fetched Finding rows) ──

const ATTACK_GROUP_TAGS = new Set([
  "attack", "exploit", "intrusion", "web_attack",
]);
const OFFENSIVE_TACTICS = new Set([
  "Initial Access", "Execution", "Persistence", "Privilege Escalation",
  "Defense Evasion", "Credential Access", "Lateral Movement",
  "Collection", "Command and Control", "Exfiltration", "Impact",
]);
const SUCCESS_TACTICS = new Set([
  "Impact", "Exfiltration", "Collection", "Command and Control",
]);
const SUCCESS_TEXT_RE = /\b(successful|compromised?|backdoor[ -](installed|created|opened)|privilege[s]?[ -]escalat(?:ion|ed)|rce|remote[ -]code[ -]execution|root[ -]shell|root[ -]access|gained?[ -]root|data[ -]exfiltrat(ion|ed)|breached)\b/i;

interface FindingForTagging {
  scanType:     string;
  severity:     string;
  confidence:   string;     // "CONFIRMED" | "LIKELY" | "POSSIBLE"
  evidence:     unknown;
  aiFpAnalysis: unknown;
  title:        string | null;
  description:  string | null;
}

function isAiSuppressed(f: FindingForTagging): boolean {
  const ai = f.aiFpAnalysis as { verdict?: string; confidence?: string } | null;
  if (!ai) return false;
  if (ai.verdict !== "LIKELY_FP") return false;
  return ai.confidence === "HIGH" || ai.confidence === "MEDIUM";
}

function hasActiveAttack(f: FindingForTagging): boolean {
  if (f.scanType !== "RUNTIME") return false;
  if (isAiSuppressed(f)) return false;

  const ev = f.evidence as Record<string, unknown> | null;
  if (ev) {
    const det = ev["detection"] as { groups?: string[] } | undefined;
    const groups = det?.groups ?? (ev["ruleGroups"] as string[] | undefined) ?? [];
    if (groups.some((g) => ATTACK_GROUP_TAGS.has(g))) return true;

    const mitre = ev["mitre"] as { tactics?: string[] } | null;
    const tactics = mitre?.tactics ?? [];
    if (tactics.some((t) => OFFENSIVE_TACTICS.has(t))) return true;
  }
  // Title fallback (e.g. "Successful sudo to root by 'www-data' …")
  const blob = `${f.title ?? ""} ${f.description ?? ""}`;
  return /\b(attack|exploit|injection|xss|malware|backdoor|intrusion|brute[- ]force|reverse[- ]shell|webshell|privilege[s]?[ -]escalat(?:ion|ed)|sudo[ -]to[ -]root|root[ -]shell|credential[ -](theft|dump)|command[ -]execution|suspicious|anomal(?:y|ous))\b/i.test(blob);
}

function isExploit(f: FindingForTagging): boolean {
  if (!hasActiveAttack(f)) return false;
  const ev = f.evidence as Record<string, unknown> | null;
  if (ev) {
    // 1. HTTP 2xx/3xx on an attack-tagged rule
    const http = ev["http"] as { statusCode?: string | number } | null;
    if (http?.statusCode !== undefined && http.statusCode !== null) {
      const code = typeof http.statusCode === "number"
        ? http.statusCode
        : parseInt(String(http.statusCode), 10);
      if (Number.isFinite(code) && code >= 200 && code < 400) return true;
    }
    // 2. audit.success
    const audit = ev["audit"] as { success?: string | boolean } | null;
    if (audit?.success === true || audit?.success === "yes" || audit?.success === "success") return true;
    // 3. Post-compromise tactic
    const mitre = ev["mitre"] as { tactics?: string[] } | null;
    if ((mitre?.tactics ?? []).some((t) => SUCCESS_TACTICS.has(t))) return true;
    // 4. File integrity event
    if (typeof ev["fileEvent"] === "string" && (ev["fileEvent"] as string).length > 0) return true;
  }
  // 5. Success-language in title/description
  const blob = `${f.title ?? ""} ${f.description ?? ""}`;
  return SUCCESS_TEXT_RE.test(blob);
}

const PREDICATES: Record<TagName, (f: FindingForTagging) => boolean> = {
  // Runtime exploit: attack-tagged + success signal + severity floor.
  // Severity floor (MEDIUM+) is encoded here and ALSO in the candidate
  // narrow below — keeps the predicate self-contained for re-use.
  "runtime-exploit": (f) => {
    if (f.scanType !== "RUNTIME") return false;
    if (!["CRITICAL","HIGH","MEDIUM"].includes(f.severity)) return false;
    return isExploit(f);
  },
  // Runtime attack: attack-tagged but not landed.
  "runtime-attack":  (f) => {
    if (f.scanType !== "RUNTIME") return false;
    if (!["CRITICAL","HIGH","MEDIUM"].includes(f.severity)) return false;
    return hasActiveAttack(f) && !isExploit(f);
  },
  // Confirmed exploit (cross-tier): scanner-confirmed Proof of Exploit.
  // Same contract the badge UI uses — confidence=CONFIRMED + evidence
  // contains a reproducible url + attack vector. AI-suppressed findings
  // are excluded so the count matches what the user actually sees on
  // the list (the badge is hidden when AI says LIKELY_FP HIGH/MED).
  "confirmed-exploit": (f) => {
    if (f.confidence !== "CONFIRMED") return false;
    if (isAiSuppressed(f)) return false;
    const ev = f.evidence as Record<string, unknown> | null;
    if (!ev) return false;
    return typeof ev["url"] === "string" && typeof ev["attack"] === "string";
  },
  // AI-suppressed: AI verdict hides this finding from default views.
  // Useful as the "show me what the AI is filtering" tag.
  "ai-suppressed": (f) => isAiSuppressed(f),
};

/** Predicate evaluator — used by both list and stats endpoints. */
export function findingMatchesTag(f: FindingForTagging, tag: TagName): boolean {
  return PREDICATES[tag](f);
}

/**
 * Cheap candidate narrow — returns the Prisma `where` extension that
 * pre-filters with indexed columns before the JS predicate runs. Keeps
 * the JS pass fast even on large datasets.
 *
 * We intentionally don't try to express the JSON-evidence parts of the
 * predicate in Prisma JSON queries — Prisma's expressiveness there is
 * limited (no regex, no numeric coerce) and the predicate definitions
 * would split across two languages, defeating the single-source-of-
 * truth goal. JS evaluation against the narrow candidate set is the
 * pragmatic answer.
 */
export function tagCandidateWhere(tag: TagName): Record<string, unknown> {
  switch (tag) {
    case "runtime-exploit":
    case "runtime-attack":
      return {
        scanType: "RUNTIME",
        severity: { in: ["CRITICAL", "HIGH", "MEDIUM"] },
        status:   { not: "FALSE_POSITIVE" },
      };
    case "confirmed-exploit":
      // confidence is indexed implicitly via finding lookups; cheap narrow
      // dramatically reduces the JS pass since CONFIRMED is rare.
      return {
        confidence: "CONFIRMED",
        status:     { not: "FALSE_POSITIVE" },
      };
    case "ai-suppressed":
      // No good cheap narrow on JSON path — Prisma can't index aiFpAnalysis
      // verdict — but `aiFpAnalysis: { not: null }` cuts the candidate set
      // to findings the FP detector has actually scored.
      return {
        aiFpAnalysis: { not: null as unknown as undefined },
      };
  }
}

/**
 * Select fields needed by the predicate evaluator. Used by stats counts
 * so we don't fetch the full Finding row when we only need to count.
 */
export const TAG_PREDICATE_SELECT = {
  scanType:     true,
  severity:     true,
  confidence:   true,
  evidence:     true,
  aiFpAnalysis: true,
  title:        true,
  description:  true,
} as const;

/** Re-evaluate against an arbitrary list — convenience for stats counting. */
export function countByTag(
  findings: FindingForTagging[],
  tag: TagName,
): number {
  return findings.filter((f) => findingMatchesTag(f, tag)).length;
}

// Type alias kept just to make the call sites in the routers read clean.
export type { Finding };
