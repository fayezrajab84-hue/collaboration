/**
 * routeBridge — Phase 27 Slice B.
 *
 * Links a DAST/PENTEST URL-based finding to a SAST source-line finding when
 * the URL path looks like it would resolve to that source file. Today this
 * is a heuristic (path → file basename match); a future slice can replace
 * the matcher with rule-id-aware mapping (e.g. "DVWA's vulnerabilities/sqli/
 * URL pattern always maps to vulnerabilities/sqli/source/*.php").
 *
 * The killshot pattern this catches:
 *   SAST  → low.php:6 has injectable $_GET concatenation
 *   DAST  → /vulnerabilities/sqli/?id=1 reflects ' OR '1'='1
 *   PENTEST CONFIRMED → sqlmap dumped DB schema using the same URL
 *   ↳ all three become one chain via this bridge.
 */
import type { Finding } from "@prisma/client";
import type { Bridge, BridgeMatch, BridgeContext } from "./bridgeInterface.js";

const URL_FROM_EVIDENCE_KEYS = ["url", "request_url", "target_url", "endpoint"];

export const routeBridge: Bridge = {
  id: "route",
  match(a: Finding, b: Finding): BridgeMatch | null {
    if (a.orgId !== b.orgId) return null;

    // Need exactly one URL-bearing finding and one source-file-bearing finding
    const sourceSide = isSourceFinding(a) ? a : isSourceFinding(b) ? b : null;
    const urlSide    = isUrlFinding(a)    ? a : isUrlFinding(b)    ? b : null;
    if (!sourceSide || !urlSide || sourceSide === urlSide) return null;

    const url      = extractUrl(urlSide);
    const filePath = sourceSide.filePath;
    if (!url || !filePath) return null;

    if (!urlContainsFileToken(url, filePath)) return null;

    return {
      bridgeType: "route",
      confidence: "POSSIBLE",
      reason: `URL ${url} appears to resolve to ${filePath}`,
    };
  },
};

function isSourceFinding(f: Finding): boolean {
  return f.scanType === "SAST" || f.scanType === "SECRET" || f.scanType === "IAC";
}

function isUrlFinding(f: Finding): boolean {
  return f.scanType === "DAST" || f.scanType === "PENTEST" || f.scanType === "PENTEST_FULL";
}

function extractUrl(f: Finding): string | null {
  // evidence.url is the canonical place; fall back to other plausible keys.
  const ev = (f.evidence ?? {}) as Record<string, unknown>;
  for (const k of URL_FROM_EVIDENCE_KEYS) {
    const v = ev[k];
    if (typeof v === "string" && v.length > 0) return v;
  }
  // Some scanners stash the URL in rawOutput.url
  const raw = (f.rawOutput ?? {}) as Record<string, unknown>;
  if (typeof raw["url"] === "string") return raw["url"] as string;
  return null;
}

/**
 * Heuristic: extract path segments from the URL (ignoring query string +
 * common prefixes like "vulnerabilities") and check whether any of them
 * appear in the SAST file path. Cheap, false-positive-tolerant — bridge
 * confidence stays POSSIBLE so the operator can validate via the UI.
 */
function urlContainsFileToken(url: string, filePath: string): boolean {
  // Strip protocol + query, keep path.
  const path = url.replace(/^https?:\/\/[^/]+/, "").split("?")[0] ?? url;
  const segments = path.split("/").map((s) => s.trim()).filter((s) => s.length > 1);
  if (segments.length === 0) return false;

  const fileTokens = filePath
    .replace(/\.[^.]+$/, "")  // strip extension
    .split(/[/\\.]/)
    .filter((s) => s.length > 1);
  if (fileTokens.length === 0) return false;

  // Match if any non-trivial segment from the URL appears as a token in the
  // file path. Skip the most common framework prefix names so we don't
  // false-positive on every single web app. Deliberately keep semantic
  // route nouns ("users", "admin") in scope because they often DO map back
  // to source files of the same name — that's the signal we want.
  const COMMON_NOISE = new Set([
    "api", "v1", "v2", "v3", "static", "assets", "src",
    "app", "public", "vendor", "node_modules",
  ]);
  for (const seg of segments) {
    if (COMMON_NOISE.has(seg.toLowerCase())) continue;
    for (const tok of fileTokens) {
      if (tok.toLowerCase() === seg.toLowerCase()) return true;
    }
  }
  return false;
}

// Re-exported for tests so bridge logic stays unit-testable in isolation.
export const _testing = { urlContainsFileToken };
