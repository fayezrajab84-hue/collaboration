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
 * Heuristic: extract path segments from the URL and check whether any of them
 * appear in the SAST file path AT MIN_TOKEN_LENGTH characters. Cheap, false-
 * positive-tolerant — bridge confidence stays POSSIBLE so the operator can
 * validate via the UI.
 *
 * Phase 27.5.x tightening: previously a single 2+ char token match was
 * enough, which caused DVWA's `/vulnerabilities/<type>/` URL family to all
 * collapse into ONE chain via the shared `vulnerabilities` token. We now:
 *   1. Require MIN_TOKEN_LENGTH=3 chars (kills 2-char noise like "id"/"go"/
 *      "do" that appear in every code path, but keeps real vuln-type tokens
 *      like "csp", "bac", "xss" that DVWA uses for category names).
 *   2. Skip a much broader noise list of common framework dirs + category-
 *      prefix words ("vulnerabilities", "source", "pages", "controllers"…)
 *      that show up in MOST file paths and so don't discriminate.
 *
 * The DVWA-specific outcome: instead of one 42-node mega-chain, we get many
 * smaller chains keyed on the actual vulnerability-type token (`sqli`,
 * `xss_r`, `csrf`, `upload`, etc.) which IS the signal that matters.
 */
const MIN_TOKEN_LENGTH = 3;

const COMMON_NOISE = new Set([
  // Versioning + API prefixes — appear in most modern URLs without telling you anything
  "api", "apis", "v1", "v2", "v3", "v4",
  // Static asset roots
  "static", "assets", "public", "media", "images", "img", "css", "js",
  // Source organisation conventions
  "src", "source", "sources", "lib", "libs", "internal", "core",
  // Framework / monorepo dirs
  "app", "apps", "packages", "modules", "vendor", "node_modules",
  // Build outputs
  "dist", "build", "out", "target", "bin",
  // Testing
  "test", "tests", "spec", "specs", "__tests__",
  // Generic groupings
  "config", "configs", "settings", "common", "shared", "utils", "helpers",
  // Routing groupings
  "pages", "routes", "controllers", "views", "models", "services", "components",
  // Documentation
  "docs", "doc", "readme",
  // Category prefix words — they GROUP many sub-features and so produce
  // false-positive cross-feature links. DVWA's `vulnerabilities/sqli` and
  // `vulnerabilities/xss_r` should NOT chain just because they share
  // "vulnerabilities" — that's the bug Phase 27.5.x fixes.
  "vulnerabilities", "vulnerability", "vulns", "challenges",
  "examples", "example", "demo", "demos", "samples", "sample",
]);

function urlContainsFileToken(url: string, filePath: string): boolean {
  // Strip protocol + query, keep path.
  const path = url.replace(/^https?:\/\/[^/]+/, "").split("?")[0] ?? url;
  const segments = path
    .split("/")
    .map((s) => s.trim())
    // Symmetric with filePath handling — strip a trailing extension so
    // URL `/login.php` produces token `login` (not `login.php`), allowing
    // it to match SAST `login.php` whose token is `login`. Without this
    // strip, every classic LAMP URL bypasses the chain.
    .map((s) => s.replace(/\.[a-z0-9]{1,5}$/i, ""))
    .filter((s) => s.length >= MIN_TOKEN_LENGTH);
  if (segments.length === 0) return false;

  const fileTokens = filePath
    .replace(/\.[^.]+$/, "")  // strip extension
    .split(/[/\\.]/)
    .filter((s) => s.length >= MIN_TOKEN_LENGTH);
  if (fileTokens.length === 0) return false;

  for (const seg of segments) {
    if (COMMON_NOISE.has(seg.toLowerCase())) continue;
    for (const tok of fileTokens) {
      if (COMMON_NOISE.has(tok.toLowerCase())) continue;
      if (tok.toLowerCase() === seg.toLowerCase()) return true;
    }
  }
  return false;
}

// Re-exported for tests so bridge logic stays unit-testable in isolation.
export const _testing = { urlContainsFileToken, COMMON_NOISE, MIN_TOKEN_LENGTH };
