import type { Finding, FpAnalysis } from "@devsecops/types";

/**
 * AI false-positive override.
 *
 * When the AI false-positive check has examined a finding and confidently
 * verdict'd it as LIKELY_FP, the attack/exploit badges should suppress —
 * the AI sees the full evidence (title, description, threat-hunt fields,
 * occurrence count, IP geolocation, user-agent) and makes a holistic
 * call the regex/group-tag predicates can't match.
 *
 * Example that drove this: a "High amount of POST requests" rule with
 * HTTP 302 responses from an internal Docker IP fired EXPLOIT because
 * (1) rule.groups contained "attack" and (2) HTTP 302 is in the 2xx/3xx
 * "success" range. The AI correctly flagged it as a bulk-form-submission
 * pattern from a legitimate Chrome user-agent on an RFC1918 IP. Without
 * this override the operator sees a false EXPLOIT chip.
 *
 * Confidence gate: only HIGH/MEDIUM-confidence LIKELY_FP verdicts
 * suppress. LOW-confidence FP verdicts leave the badges visible — when
 * the AI itself is uncertain, the deterministic signal still wins.
 */
function isAiFalsePositive(
  finding: Pick<Finding, "aiFpAnalysis">,
): boolean {
  const ai = finding.aiFpAnalysis as FpAnalysis | null | undefined;
  if (!ai) return false;
  if (ai.verdict !== "LIKELY_FP") return false;
  return ai.confidence === "HIGH" || ai.confidence === "MEDIUM";
}

/**
 * Proof-of-Exploit predicate.
 *
 * A finding qualifies for the badge when the scanner reproduced the
 * vulnerability (CONFIRMED) AND the parser captured the two pieces of
 * evidence needed for a developer to reproduce the exploit themselves:
 * the URL that was hit and the attack payload that triggered it.
 *
 * Mirrors the SQL predicate documented in CLAUDE.md and used by
 * /finding-evidence:
 *
 *   confidence='CONFIRMED' AND evidence ? 'url' AND evidence ? 'attack'
 *
 * Both call sites (FindingDetailDrawer + FindingsPage table) MUST go
 * through this helper so the rule can't drift between them.
 */
export function hasProofOfExploit(
  finding: Pick<Finding, "confidence" | "evidence" | "scanner">,
): boolean {
  if (finding.confidence !== "CONFIRMED") return false;
  // Wazuh-VD findings are STATE — even at CONFIRMED confidence (we
  // currently ingest them as LIKELY, but the predicate stays guarded
  // for future-proofing) they describe a vulnerability inventory entry,
  // not a scanner-reproduced exploit. The badge is reserved for things
  // the platform can WALK an operator through reproducing.
  if (finding.scanner === "wazuh-vd") return false;
  const ev = finding.evidence;
  if (!ev || typeof ev !== "object") return false;
  return typeof ev["url"] === "string" && typeof ev["attack"] === "string";
}

/**
 * Active-Attack predicate.
 *
 * Runtime equivalent of Proof-of-Exploit. A RUNTIME finding (Wazuh
 * alert) qualifies when the rule's groups OR MITRE tactic indicate the
 * IDS observed offensive activity — not just a scanner running tests
 * but an actual attack pattern firing on a production host. Operators
 * should treat this with the same urgency as Proof-of-Exploit: it
 * means "investigate now, this is happening".
 *
 * Signals (any of):
 *   1. rule.groups[] contains "attack", "exploit", or "intrusion"
 *      (Wazuh's tag for rules that detect offensive behaviour)
 *   2. MITRE tactic falls in the offensive-stage set (Initial Access
 *      → Impact, skipping Reconnaissance/Resource-Dev which are
 *      pre-attack)
 */
const OFFENSIVE_TACTICS = new Set([
  "Initial Access",
  "Execution",
  "Persistence",
  "Privilege Escalation",
  "Defense Evasion",
  "Credential Access",
  "Lateral Movement",
  "Collection",
  "Command and Control",
  "Exfiltration",
  "Impact",
]);

const ATTACK_GROUP_TAGS = new Set(["attack", "exploit", "intrusion", "web_attack"]);

// Keyword-based fallback for findings whose `evidence` is missing or
// sparse (e.g. legacy rows ingested before the evidence extractor
// shipped, or rules whose decoder doesn't tag groups/MITRE). Title +
// description text often makes the attack pattern obvious without
// structured fields. Matched case-insensitively as whole words to
// avoid partial-token false positives ("attacker" in "attacker IP"
// is fine; "attack" inside "attached" is not).
const ATTACK_TITLE_PATTERNS = [
  /\battack\b/i,
  /\bexploit/i,                      // exploits, exploited, exploitation
  /\binjection\b/i,                  // SQL injection / command injection
  /\bxss\b/i,
  /\bmalware\b/i,
  /\bbackdoor\b/i,
  /\bintrusion\b/i,
  /\bbrute[- ]force\b/i,
  /\bunauthori[sz]ed\b/i,
  /\breverse[- ]shell\b/i,
  /\bwebshell\b/i,
  /\bprivilege[s]?[ -]escalat(?:ion|ed)\b/i,   // T1548 family — sudo abuse, setuid, etc.
  /\bsudo[- ]to[- ]root\b/i,                    // Wazuh's literal phrasing
  /\broot[- ]shell\b/i,
  /\bcredential[ -](theft|dump|harvest)\b/i,
  /\bcommand[ -]execution\b/i,                  // RCE-adjacent
  /\bsuspicious\b/i,                            // catches "suspicious activity", "suspicious process"
  /\banomal(?:y|ous)\b/i,
];

function matchesAttackText(text: string | null | undefined): boolean {
  if (!text) return false;
  return ATTACK_TITLE_PATTERNS.some((re) => re.test(text));
}

export function hasActiveAttack(
  finding: Pick<Finding, "scanType" | "scanner" | "evidence" | "title" | "description" | "aiFpAnalysis">,
): boolean {
  if (finding.scanType !== "RUNTIME") return false;
  // Wazuh-VD findings are STATE (a CVE in an installed package), not
  // EVENT (an attack happened). Without this guard:
  //   • The synthesized MITRE classifier (Phase 3) tags VD findings
  //     with offensive tactics (Initial Access, Execution, Impact) so
  //     the dashboard MITRE chart sees them — but those tactics also
  //     match the OFFENSIVE_TACTICS set below, false-firing ATTACK.
  //   • CVE descriptions routinely contain words like "attacker",
  //     "exploit", "code execution" so even the title/description
  //     regex fallback at the bottom of this function would match.
  // Either path made every wazuh-vd row render an ATTACK pill, and
  // the 11 DoS-class CVEs (synthesised tactic "Impact" — in
  // SUCCESS_TACTICS) further earned the EXPLOIT pill via
  // wasExploitSuccessful. Mirrors the server-side guard in
  // services/findingTags.ts:hasActiveAttack and the dashboard
  // route's activeAttacks24h count.
  if (finding.scanner === "wazuh-vd") return false;
  // AI override — confidently-FP findings drop their badges so the
  // table doesn't scream EXPLOIT at a known-benign Wazuh alert.
  if (isAiFalsePositive(finding)) return false;
  const ev = finding.evidence as Record<string, unknown> | null;

  // ── Evidence path (preferred) ────────────────────────────────────
  if (ev) {
    const det = ev["detection"] as { groups?: string[] } | undefined;
    const groups = det?.groups ?? (ev["ruleGroups"] as string[] | undefined) ?? [];
    if (groups.some((g) => ATTACK_GROUP_TAGS.has(g))) return true;

    const mitre = ev["mitre"] as { tactics?: string[] } | null;
    const tactics = mitre?.tactics ?? [];
    if (tactics.some((t) => OFFENSIVE_TACTICS.has(t))) return true;
  }

  // ── Text fallback (legacy + sparse-evidence rows) ────────────────
  // Run on title + description so we catch both
  // "Successful sudo to root by 'www-data' — privilege escalation"
  // (description-style) and shorter rule descriptions in the title.
  if (matchesAttackText(finding.title) || matchesAttackText(finding.description)) {
    return true;
  }

  return false;
}

/**
 * Exploit-Success predicate — answers "did the attack actually land?".
 *
 * `hasActiveAttack` says "an attack pattern fired"; this predicate adds
 * the second-stage check: do the response signals indicate the attempt
 * succeeded (got through the WAF, hit the app, modified state)? This
 * is the difference between "blocked attempt" and "active compromise"
 * and drives an entirely different incident-response workflow.
 *
 * Success signals (any of, ANDed with hasActiveAttack):
 *   1. HTTP 2xx/3xx status code on a web-attack rule. 4xx/5xx mean the
 *      app rejected it; 2xx/3xx mean the request reached the handler.
 *   2. audit.success === "yes" / "success" — the kernel audit
 *      subsystem confirmed the syscall succeeded.
 *   3. MITRE tactic ∈ {Impact, Exfiltration, Collection, Command and
 *      Control}. These are post-compromise stages — the attacker got
 *      past initial access and is achieving their goal. Alerts in
 *      these tactics IS the success.
 *   4. A file-integrity event (modified/added/deleted) co-fired —
 *      indirect proof that something on the host changed.
 *
 * Shape of "success" varies by source: an HTTP 200 on the SQL-injection
 * URL doesn't necessarily mean the SQL extracted data, but it DOES
 * mean the attacker's payload was processed. That's enough to flag.
 * The badge tooltip explains the signal so the operator knows what
 * tier of confirmation they're looking at.
 */
const SUCCESS_TACTICS = new Set([
  "Impact",
  "Exfiltration",
  "Collection",
  "Command and Control",
]);

// Title/description keyword fallback for "the attack landed". Wazuh's
// own rule descriptions often spell it out: "Successful login from",
// "Backdoor installed", "Privilege escalation to root", "RCE via …".
// These are the strongest signals when structured evidence is absent.
const SUCCESS_TITLE_PATTERNS = [
  /\bsuccessful\b/i,                                  // catches "Successful sudo to root", "Successful login"
  /\bcompromised?\b/i,
  /\bbackdoor[ -](installed|created|opened)\b/i,
  /\bprivilege[s]?[ -]escalat(?:ion|ed)\b/i,
  /\brce\b/i,                                          // remote code execution
  /\bremote[ -]code[ -]execution\b/i,
  /\broot[ -]shell\b/i,
  /\broot[ -]access\b/i,
  /\bgained?[ -]root\b/i,
  /\bdata[ -]exfiltrat(ion|ed)\b/i,
  /\bbreached\b/i,
];

function matchesSuccessText(text: string | null | undefined): boolean {
  if (!text) return false;
  return SUCCESS_TITLE_PATTERNS.some((re) => re.test(text));
}

export function wasExploitSuccessful(
  finding: Pick<Finding, "scanType" | "scanner" | "evidence" | "title" | "description" | "aiFpAnalysis" | "confidence">,
): boolean {
  // Defense in depth — the runtime path below calls hasActiveAttack
  // which already guards on scanner=wazuh-vd, but adding the guard
  // here too means any future change that bypasses hasActiveAttack
  // (e.g. a refactor of the proof-of-exploit branch) can't accidentally
  // earn a VD finding the EXPLOIT badge. State ≠ event.
  if (finding.scanner === "wazuh-vd") return false;
  // ── Scanner-proven exploit (CHECK FIRST, before AI override) ────
  // Concrete proof outranks AI heuristics. When the scanner ran a
  // payload (xsstrike/sqlmap/dalfox/lfi-probe) and CONFIRMED reflection
  // with evidence.url + evidence.attack, the proof is materially
  // stronger than the AI's "looks like FP" guess. We saw this regress
  // when two confirmed XSS findings (xsstrike + dalfox, both with
  // CONFIRMED confidence + recorded payloads) got their EXPLOIT pill
  // hidden because the AI false-positive check returned LIKELY_FP /
  // HIGH on the surface text — the AI didn't have the scanner's
  // actual reproducer in front of it.
  if (finding.scanType !== "RUNTIME" && hasProofOfExploit(finding)) {
    return true;
  }

  // ── Runtime "attack landed" path ────────────────────────────────
  // For RUNTIME findings the AI override applies — Wazuh rules are
  // heuristic and the AI's holistic view (geo, UA, occurrence
  // density) genuinely adds information the deterministic predicate
  // can't see.
  if (isAiFalsePositive(finding)) return false;

  // Must first be an attack — a benign 200 response isn't "success".
  // hasActiveAttack itself respects the AI false-positive override, so
  // a confidently-FP verdict propagates here automatically.
  if (!hasActiveAttack(finding)) return false;

  const ev = finding.evidence as Record<string, unknown> | null;

  // ── Evidence path (preferred) ────────────────────────────────────
  //
  // Note on HTTP 2xx/3xx as a success signal: it stays here. We
  // briefly removed it because high-volume POST/bot rules with HTTP
  // 200 responses inflated the EXPLOIT count, but those were ALL
  // already AI-FP-suppressed upstream (hasActiveAttack short-circuits
  // on isAiFalsePositive). The legitimate cases — SQL injection /
  // XSS / LFI rules where the request reached the handler with a
  // 200/302 — are real exploit signals the AI doesn't suppress, and
  // they DO need this criterion to qualify (their MITRE tactics are
  // offensive but not post-compromise, so without this they'd
  // downgrade to ATTACK-only).
  if (ev) {
    // 1. HTTP 2xx/3xx on an attack-tagged rule = request reached the
    //    handler. Combined with hasActiveAttack's pre-check, this
    //    means an attack pattern fired AND the response wasn't blocked.
    const http = ev["http"] as { statusCode?: string | number } | null;
    if (http?.statusCode !== undefined && http.statusCode !== null) {
      const code = typeof http.statusCode === "number"
        ? http.statusCode
        : parseInt(String(http.statusCode), 10);
      if (Number.isFinite(code) && code >= 200 && code < 400) return true;
    }

    // 2. Audit subsystem confirmed the syscall succeeded.
    const audit = ev["audit"] as { success?: string | boolean } | null;
    const auditSuccess = audit?.success;
    if (auditSuccess === true || auditSuccess === "yes" || auditSuccess === "success") {
      return true;
    }

    // 3. Post-compromise MITRE tactic — Impact/Exfiltration/Collection/C2
    //    are the tactics that ARE the success.
    const mitre = ev["mitre"] as { tactics?: string[] } | null;
    const tactics = mitre?.tactics ?? [];
    if (tactics.some((t) => SUCCESS_TACTICS.has(t))) return true;

    // 4. File integrity event co-fired — something on disk changed.
    const fileEvent = ev["fileEvent"];
    if (typeof fileEvent === "string" && fileEvent.length > 0) return true;
  }

  // ── Text fallback (legacy + sparse-evidence rows) ────────────────
  // Wazuh rule descriptions like "Successful sudo to root by 'www-data'
  // — privilege escalation" embed the success outcome in plain text.
  // These keyword patterns catch what evidence-driven checks miss.
  if (matchesSuccessText(finding.title) || matchesSuccessText(finding.description)) {
    return true;
  }

  return false;
}
