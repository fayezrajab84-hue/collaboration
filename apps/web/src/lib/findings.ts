import type { Finding } from "@devsecops/types";

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
  finding: Pick<Finding, "confidence" | "evidence">,
): boolean {
  if (finding.confidence !== "CONFIRMED") return false;
  const ev = finding.evidence;
  if (!ev || typeof ev !== "object") return false;
  return typeof ev["url"] === "string" && typeof ev["attack"] === "string";
}
