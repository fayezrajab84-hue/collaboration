/**
 * CWE → MITRE ATT&CK classifier.
 *
 * Replaces the heuristic keyword-based MITRE synthesizer (previously
 * inlined in wazuhIngestService.vulnToMitre). Uses a curated CWE → ATT&CK
 * lookup table for authoritative per-finding classification, with the
 * existing keyword heuristic as a fallback when no CWE is available.
 *
 * Why CWE-driven beats keyword-driven:
 *   - The keyword heuristic mapped EVERY high-CVSS CVE to T1190 by
 *     default — burying the long tail of memory-corruption / privesc /
 *     credential-access CVEs under a single "Initial Access" tactic.
 *     Operators couldn't filter by tactic meaningfully because half
 *     of runtime VD findings shared the same one.
 *   - CWE → ATT&CK is published and curated by MITRE (Center for Threat-
 *     Informed Defense's `attack_to_cwe` project). Each mapping has a
 *     documented rationale; the operator can audit "why was this CVE
 *     classified as T1068?" by walking the CWE.
 *   - The classifier output now includes a `cweId` provenance field
 *     so the audit trail is intact ("classified as T1068 because the
 *     CVE description contained CWE-269 (Improper Privilege Mgmt)").
 *
 * Coverage scope:
 *   - ~45 CWEs covering OWASP Top 10 + common runtime CVE patterns.
 *   - Memory-corruption / privesc / credential-access / authz / DoS
 *     all get distinct tactics rather than the heuristic's
 *     T1190-or-T1499 binary.
 *   - The long tail (rare CWEs, no CWE in source data) falls through
 *     to the keyword heuristic — same coverage as before, plus the
 *     CWE-driven layer on top.
 *
 * Source: MITRE Center for Threat-Informed Defense
 *   https://github.com/center-for-threat-informed-defense/attack_to_cwe
 *
 * Refresh cadence: the CWE → ATT&CK mapping changes rarely (last
 * substantive update was 2023). Bake-in is the right call for ~150 LOC.
 * If MITRE publishes a major revision, update CWE_TO_ATTACK below.
 */

// ── Types ────────────────────────────────────────────────────────────────

/**
 * One technique/tactic pair. A CWE may map to multiple of these — e.g.
 * CWE-89 (SQL injection) cleanly maps to a single T1190 (Exploit Public-
 * Facing Application), while CWE-787 (out-of-bounds write) genuinely
 * maps to both T1203 (Execution) and T1499 (Impact) depending on
 * exploitation path.
 */
interface AttackMapping {
  technique: string;        // T-code, e.g. "T1190"
  tactic:    string;        // human-readable tactic, e.g. "Initial Access"
  reason:    string;        // why this CWE → this technique (audit trail)
}

/**
 * The shape we return + persist in Finding.evidence.mitre. Keeps the
 * existing `tactics[] / techniques[] / synthesized: true / basis`
 * contract from wazuhIngestService — the UI's hasActiveAttack() reader
 * keeps working without a migration.
 *
 * Adds `cweId` (provenance) so the audit trail records which CWE drove
 * the classification when CWE-driven; null when the heuristic fallback
 * fired.
 */
export interface MitreClassification {
  tactics:     string[];
  techniques:  string[];
  synthesized: true;
  basis:       string;
  cweId:       string | null;
}

// ── CWE → ATT&CK lookup table ────────────────────────────────────────────
// Numeric keys (no "CWE-" prefix) so we can normalise input formats —
// scanners populate cweId variously as "CWE-89", "89", "cwe-89" etc.

const CWE_TO_ATTACK: Record<string, AttackMapping[]> = {
  // ── Web injection class — Initial Access / Execution ────────────────
  "22":   [{ technique: "T1083",     tactic: "Discovery",            reason: "Path traversal — file/directory discovery" }],
  "78":   [{ technique: "T1059",     tactic: "Execution",            reason: "OS command injection" }],
  "79":   [{ technique: "T1059.007", tactic: "Execution",            reason: "XSS — JS execution in client" }],
  "89":   [{ technique: "T1190",     tactic: "Initial Access",       reason: "SQL injection in public-facing app" }],
  "94":   [{ technique: "T1059",     tactic: "Execution",            reason: "Code injection" }],
  "352":  [{ technique: "T1190",     tactic: "Initial Access",       reason: "CSRF — exploit public-facing app" }],
  "434":  [{ technique: "T1190",     tactic: "Initial Access",       reason: "Unrestricted file upload" }],
  "502":  [{ technique: "T1190",     tactic: "Initial Access",       reason: "Unsafe deserialization" }],
  "601":  [{ technique: "T1204",     tactic: "Execution",            reason: "Open redirect — user-driven execution" }],
  "611":  [{ technique: "T1190",     tactic: "Initial Access",       reason: "XXE — XML external entity" }],
  "915":  [{ technique: "T1190",     tactic: "Initial Access",       reason: "Mass assignment / improperly controlled mod" }],
  "918":  [{ technique: "T1190",     tactic: "Initial Access",       reason: "SSRF — server-side request forgery" }],

  // ── Memory corruption — Execution + Impact ──────────────────────────
  "119":  [{ technique: "T1499",     tactic: "Impact",               reason: "Buffer overflow — DoS / crash" }],
  "120":  [{ technique: "T1203",     tactic: "Execution",            reason: "Buffer copy — exploitation for code execution" }],
  "125":  [{ technique: "T1213",     tactic: "Collection",           reason: "Out-of-bounds read — data disclosure" }],
  "190":  [{ technique: "T1499",     tactic: "Impact",               reason: "Integer overflow — DoS / crash" }],
  "416":  [{ technique: "T1499",     tactic: "Impact",               reason: "Use-after-free — memory corruption" }],
  "476":  [{ technique: "T1499",     tactic: "Impact",               reason: "Null pointer dereference — DoS" }],
  "787":  [
    { technique: "T1203",     tactic: "Execution",            reason: "Out-of-bounds write — exploitation for code execution" },
    { technique: "T1499",     tactic: "Impact",               reason: "Out-of-bounds write — DoS / crash" },
  ],

  // ── Privilege & access control — Privilege Escalation / Initial Access
  "269":  [{ technique: "T1068",     tactic: "Privilege Escalation", reason: "Improper privilege management" }],
  "276":  [{ technique: "T1222",     tactic: "Defense Evasion",      reason: "Incorrect default permissions" }],
  "284":  [{ technique: "T1078",     tactic: "Initial Access",       reason: "Improper access control" }],
  "285":  [{ technique: "T1078",     tactic: "Initial Access",       reason: "Improper authorization" }],
  "287":  [{ technique: "T1078",     tactic: "Initial Access",       reason: "Improper authentication" }],
  "306":  [{ technique: "T1078",     tactic: "Initial Access",       reason: "Missing authentication for critical function" }],
  "639":  [{ technique: "T1078",     tactic: "Initial Access",       reason: "Authorization bypass via user-controlled key" }],
  "732":  [{ technique: "T1222",     tactic: "Defense Evasion",      reason: "Incorrect permission assignment" }],
  "862":  [{ technique: "T1078",     tactic: "Initial Access",       reason: "Missing authorization" }],
  "863":  [{ technique: "T1078",     tactic: "Initial Access",       reason: "Incorrect authorization" }],

  // ── Credential access ───────────────────────────────────────────────
  "295":  [{ technique: "T1557",     tactic: "Credential Access",    reason: "Improper certificate validation — MitM" }],
  "307":  [{ technique: "T1110",     tactic: "Credential Access",    reason: "No brute-force protection" }],
  "521":  [{ technique: "T1110",     tactic: "Credential Access",    reason: "Weak password requirements" }],
  "522":  [{ technique: "T1552",     tactic: "Credential Access",    reason: "Insufficiently protected credentials" }],
  "798":  [{ technique: "T1552.001", tactic: "Credential Access",    reason: "Hardcoded credentials in files" }],

  // ── Information disclosure / collection ─────────────────────────────
  "200":  [{ technique: "T1213",     tactic: "Collection",           reason: "Information exposure" }],
  "209":  [{ technique: "T1213",     tactic: "Collection",           reason: "Error message information disclosure" }],
  "552":  [{ technique: "T1213",     tactic: "Collection",           reason: "File / directory accessible to external parties" }],

  // ── Resource consumption — Impact ───────────────────────────────────
  "362":  [{ technique: "T1499",     tactic: "Impact",               reason: "Race condition — DoS / corruption" }],
  "400":  [{ technique: "T1499",     tactic: "Impact",               reason: "Resource exhaustion" }],
  "770":  [{ technique: "T1499",     tactic: "Impact",               reason: "Allocation without limits" }],
  "1333": [{ technique: "T1499",     tactic: "Impact",               reason: "Inefficient regex (ReDoS)" }],

  // ── Misc commonly-seen ──────────────────────────────────────────────
  "1188": [{ technique: "T1078",     tactic: "Initial Access",       reason: "Insecure default initialisation of resource" }],
  "1236": [{ technique: "T1059",     tactic: "Execution",            reason: "CSV / formula injection" }],
};

// ── Public API ───────────────────────────────────────────────────────────

/**
 * Normalise CWE id strings. Accepts "CWE-89", "cwe-89", "89".
 * Returns the bare numeric id ("89") or null if the input doesn't match.
 */
function normalizeCweId(raw: string): string | null {
  const m = raw.trim().match(/^(?:cwe-)?(\d+)$/i);
  return m ? m[1]! : null;
}

/**
 * Look up CWE ids in the curated table. Returns the first match (we
 * don't merge across CWEs because the basis field needs single-source
 * provenance — operators want "this finding was classified because
 * CWE-269", not a smashed-together rationale across multiple CWEs).
 *
 * Multiple-mapping CWEs (e.g. CWE-787 → T1203 + T1499) yield deduped
 * tactic + technique arrays in the result.
 */
export function classifyByCwe(cweIds: string[]): MitreClassification | null {
  for (const raw of cweIds) {
    const id = normalizeCweId(raw);
    if (!id) continue;
    const entries = CWE_TO_ATTACK[id];
    if (!entries || entries.length === 0) continue;
    return {
      tactics:     [...new Set(entries.map((e) => e.tactic))],
      techniques:  [...new Set(entries.map((e) => e.technique))],
      synthesized: true,
      basis:       `CWE-${id} → ${entries.map((e) => e.technique).join("/")} (${entries[0]!.reason})`,
      cweId:       `CWE-${id}`,
    };
  }
  return null;
}

/**
 * Extract CWE ids from free-text. NVD-sourced CVE descriptions and Wazuh
 * VD docs sometimes embed `CWE-XXX` patterns inline (e.g. "[CWE-269]" or
 * "(CWE-89: SQL Injection)"). Returns deduped numeric ids; empty array
 * when no CWE found.
 */
export function extractCwesFromText(text: string): string[] {
  if (!text) return [];
  const re = /\bCWE-(\d+)\b/gi;
  const out = new Set<string>();
  for (const m of text.matchAll(re)) {
    if (m[1]) out.add(m[1]);
  }
  return [...out];
}

/**
 * Heuristic fallback — ported verbatim from the original
 * wazuhIngestService.vulnToMitre(). Triggers when no CWE is available
 * via direct input or description extraction. Identical behaviour to
 * before this module landed; preserves the previous coverage floor.
 */
function classifyByHeuristic(description: string, cvssScore: number): MitreClassification | null {
  const desc  = (description ?? "").toLowerCase();
  const score = typeof cvssScore === "number" ? cvssScore : 0;

  if (/\b(remote\s+code\s+execution|rce|arbitrary\s+code|attacker[ -]?controlled\s+code|command\s+injection)\b/i.test(desc)) {
    return { tactics: ["Execution", "Initial Access"], techniques: ["T1203", "T1190"], synthesized: true, basis: "RCE keyword in description (heuristic)", cweId: null };
  }
  if (/\bprivilege[ -]?escalat(?:ion|ed|e)|local\s+privilege|privesc\b/i.test(desc)) {
    return { tactics: ["Privilege Escalation"], techniques: ["T1068"], synthesized: true, basis: "Privilege escalation in description (heuristic)", cweId: null };
  }
  if (/\b(authentication\s+bypass|auth(?:n|z)?[ -]?bypass|credential[s]?\s+(?:disclosure|theft|leak)|password\s+(?:disclosure|recovery)|hardcoded\s+credential)\b/i.test(desc)) {
    return { tactics: ["Credential Access"], techniques: ["T1078"], synthesized: true, basis: "Credential / auth-bypass in description (heuristic)", cweId: null };
  }
  if (/\b(ssrf|server[ -]?side\s+request|sql\s+injection|sqli|cross[ -]?site\s+scripting|xss|idor|insecure\s+direct\s+object|path\s+traversal|directory\s+traversal|deserialization|unsafe\s+deserialization|xxe|xml\s+external\s+entity)\b/i.test(desc)) {
    return { tactics: ["Initial Access"], techniques: ["T1190"], synthesized: true, basis: "Web-vector class in description (heuristic)", cweId: null };
  }
  if (/\b(denial[ -]?of[ -]?service|\bdos\b|crash|hang|infinite\s+loop)\b/i.test(desc)) {
    return { tactics: ["Impact"], techniques: ["T1499"], synthesized: true, basis: "DoS / crash in description (heuristic)", cweId: null };
  }
  if (score >= 7.0) {
    return { tactics: ["Initial Access"], techniques: ["T1190"], synthesized: true, basis: `High CVSS (${score.toFixed(1)}) — default Initial Access (heuristic)`, cweId: null };
  }
  return null;
}

/**
 * Unified vulnerability classifier — the single entry point.
 * Tries in priority order:
 *   1. Direct CWE input (most authoritative — scanner-supplied)
 *   2. CWE extraction from description text (Wazuh VD / NVD prose)
 *   3. Keyword + CVSS heuristic (long-tail coverage)
 * Returns null when nothing matches — honest "we don't know" beats
 * a false-precise label.
 */
export function classifyVulnerability(input: {
  cveId?:       string | null;
  cweIds?:      string[];
  description?: string;
  cvssScore?:   number;
}): MitreClassification | null {
  if (input.cweIds && input.cweIds.length > 0) {
    const direct = classifyByCwe(input.cweIds);
    if (direct) return direct;
  }
  if (input.description) {
    const extracted = extractCwesFromText(input.description);
    if (extracted.length > 0) {
      const fromText = classifyByCwe(extracted);
      if (fromText) return fromText;
    }
  }
  return classifyByHeuristic(input.description ?? "", input.cvssScore ?? 0);
}

// ── Test-only re-exports ─────────────────────────────────────────────────
export const _testing = { CWE_TO_ATTACK, normalizeCweId, classifyByHeuristic };
