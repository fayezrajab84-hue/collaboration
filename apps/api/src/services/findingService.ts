import { createHash } from "crypto";
import prisma from "../db.js";
import { logger } from "../logger.js";
import type { NormalizedFinding, ScanType, TargetType } from "@devsecops/types";
import { applyMappingsToFinding } from "./complianceMappingService.js";
import { classifyVulnerability } from "./mitre/cweToAttack.js";

// ── JSON sanitizer ────────────────────────────────────────────────────────────
//
// Postgres rejects NUL bytes (\u0000) inside jsonb columns (SQLSTATE 22P05).
// ZAP alerts can embed raw bytes in request/response bodies when the target
// returns binary content or mis-decoded text. Walk any rawOutput/evidence
// payload recursively and strip them from every string leaf before upsert.
function stripNulBytes<T>(value: T): T {
  if (value === null || value === undefined) return value;
  if (typeof value === "string") {
    return (value.includes("\u0000") ? value.replace(/\u0000/g, "") : value) as T;
  }
  if (Array.isArray(value)) {
    return value.map(stripNulBytes) as T;
  }
  if (typeof value === "object") {
    const out: Record<string, unknown> = {};
    for (const [k, v] of Object.entries(value as Record<string, unknown>)) {
      out[k] = stripNulBytes(v);
    }
    return out as T;
  }
  return value;
}

// ── Severity helpers ──────────────────────────────────────────────────────────

const SEV_RANK: Record<string, number> = { CRITICAL: 0, HIGH: 1, MEDIUM: 2, LOW: 3, INFO: 4 };

function highestSeverity(severities: string[]): string {
  return severities.reduce((best, s) => (SEV_RANK[s] ?? 99) < (SEV_RANK[best] ?? 99) ? s : best, "INFO");
}

// ── Package-level fingerprint ─────────────────────────────────────────────────

/**
 * Deterministic fingerprint keyed to package identity, not individual CVE.
 * Scoped to org + target so the same package in different repos stays separate.
 */
function packageFingerprint(
  orgId:    string,
  targetId: string,
  scanType: string,
  pkg:      string,
  ver:      string,
): string {
  return createHash("sha256")
    .update(`${orgId}:sca-pkg:${targetId}:${scanType}:${pkg}:${ver}`)
    .digest("hex");
}

// ── SCA / CONTAINER merge ─────────────────────────────────────────────────────

/**
 * Collapse all CVE-level findings for the same package@version into a single
 * merged finding. The scanner still emits one finding per CVE; this function
 * reduces the noise before anything hits the database.
 *
 * Rules:
 *  - Severity  → highest across all CVEs
 *  - cveId     → the CVE driving the highest severity
 *  - cvssScore → highest across all CVEs
 *  - fixVersion→ first non-null value (Trivy returns the same patched version
 *                for every CVE of a given package)
 *  - description → rebuilt to list every CVE with its severity + CVSS
 *  - references  → all CVE IDs
 *  - rawOutput   → { merged: true, count, cves: [...] }
 *  - Findings without packageName/packageVersion are passed through unchanged.
 */
function mergePackageFindings(
  findings: NormalizedFinding[],
  orgId:    string,
  targetId: string,
  scanType: string,
): NormalizedFinding[] {
  // Separate findings that can be merged (have pkg metadata) from those that cannot
  const mergeable    = findings.filter((f) => f.packageName && f.packageVersion);
  const nonMergeable = findings.filter((f) => !(f.packageName && f.packageVersion));

  // Group mergeable findings by package identity
  const groups = new Map<string, NormalizedFinding[]>();
  for (const f of mergeable) {
    const key = `${f.packageName}::${f.packageVersion}`;
    if (!groups.has(key)) groups.set(key, []);
    groups.get(key)!.push(f);
  }

  const result: NormalizedFinding[] = [...nonMergeable];

  for (const group of groups.values()) {
    const pkg    = group[0]!.packageName!;
    const ver    = group[0]!.packageVersion!;
    const fp     = packageFingerprint(orgId, targetId, scanType, pkg, ver);

    if (group.length === 1) {
      // Still switch to package-level fingerprint for consistency
      result.push({ ...group[0]!, fingerprint: fp });
      continue;
    }

    // ── Multiple CVEs → build merged finding ─────────────────────────────
    const sortedBySev = [...group].sort(
      (a, b) => (SEV_RANK[a.severity] ?? 99) - (SEV_RANK[b.severity] ?? 99),
    );

    const topSev    = highestSeverity(group.map((f) => f.severity));
    const primary   = sortedBySev[0]!; // highest severity entry — always defined (group.length > 1)
    const fixVer    = group.map((f) => f.fixVersion).find(Boolean) ?? undefined;
    const maxCvss   = group.reduce<number | undefined>((m, f) =>
      f.cvssScore !== undefined && f.cvssScore !== null
        ? Math.max(m ?? 0, f.cvssScore)
        : m,
      undefined,
    );
    const cveIds    = group.map((f) => f.cveId).filter(Boolean) as string[];

    // Derive a human-friendly package name:
    //  1. Try the CVE Title field — e.g. "Apache Tomcat: HTTP/2 issue" → "Apache Tomcat"
    //  2. Strip Maven groupId — "org.apache.tomcat.embed:tomcat-embed-core" → "tomcat-embed-core"
    //  3. Fall back to the raw package name
    const firstTitle = (primary.rawOutput as Record<string, unknown>)?.["Title"] as string | undefined;
    const humanName = (() => {
      if (firstTitle) {
        const colonIdx = firstTitle.indexOf(":");
        if (colonIdx > 0 && colonIdx < 50) return firstTitle.slice(0, colonIdx).trim();
      }
      // Maven artifact: take the part after ":"
      if (pkg.includes(":")) return pkg.split(":").pop()!;
      return pkg;
    })();

    // Description: concise upgrade prompt only — CVEs are listed in the Subissues panel
    const description =
      `${group.length} vulnerabilities found in ${humanName} ${ver}.` +
      (fixVer ? ` Upgrade to ${fixVer} to fix all.` : "");

    result.push({
      ...primary,
      fingerprint: fp,
      title:       `${humanName} ${ver} — ${group.length} vulnerabilities (${topSev})`,
      description,
      severity:    topSev as NormalizedFinding["severity"],
      cvssScore:   maxCvss,
      fixVersion:  fixVer,
      cveId:       primary.cveId,
      references:  cveIds,
      rawOutput:   {
        merged:           true,
        count:            group.length,
        installedVersion: ver,
        fixVersion:       fixVer ?? null,
        // Structured per-CVE list consumed by ScaSubissuesPanel in the frontend
        cves: sortedBySev.map((f) => ({
          cveId:      f.cveId      ?? null,
          severity:   f.severity,
          cvssScore:  f.cvssScore  ?? null,
          fixVersion: f.fixVersion ?? null,
          filePath:   f.filePath   ?? null,
          title:      (f.rawOutput as Record<string, unknown>)?.["Title"]      as string ?? null,
          primaryUrl: (f.rawOutput as Record<string, unknown>)?.["PrimaryURL"] as string ?? null,
        })),
      },
    });
  }

  return result;
}

// ── IAC rule-level merge ──────────────────────────────────────────────────────

/**
 * One failing resource for a given Checkov rule.
 * Stored inside rawOutput.resources[] of the merged finding.
 */
interface IacResource {
  filePath:  string | null;
  lineStart: number | null;
  lineEnd:   number | null;
  resource:  string | null;   // e.g. "aws_s3_bucket.my_bucket"
  snippet:   string | null;
  severity:  string;
  checkType: string | null;   // e.g. "terraform", "kubernetes"
}

/**
 * Deterministic fingerprint keyed to Checkov rule identity within a repo target.
 */
function iacRuleFingerprint(orgId: string, targetId: string, ruleId: string): string {
  return createHash("sha256")
    .update(`${orgId}:iac-rule:${targetId}:${ruleId}`)
    .digest("hex");
}

/**
 * Collapse per-resource IAC findings for the same Checkov rule into one merged
 * finding. Each failing resource becomes an entry in rawOutput.resources[].
 *
 * Rules:
 *  - Severity   → highest across all failing resources
 *  - title      → unchanged (the Checkov check_name)
 *  - description → updated to reflect count ("…affects N resources")
 *  - rawOutput  → { merged: true, count, ruleId, scanner, resources: [...] }
 */
function mergeIacFindings(
  findings: NormalizedFinding[],
  orgId:    string,
  targetId: string,
): NormalizedFinding[] {
  const groups = new Map<string, NormalizedFinding[]>();
  for (const f of findings) {
    const key = f.ruleId ?? f.title ?? "unknown";
    if (!groups.has(key)) groups.set(key, []);
    groups.get(key)!.push(f);
  }

  const result: NormalizedFinding[] = [];

  for (const [ruleId, group] of groups.entries()) {
    const fp = iacRuleFingerprint(orgId, targetId, ruleId);

    if (group.length === 1) {
      result.push({ ...group[0]!, fingerprint: fp });
      continue;
    }

    // ── Multiple failing resources → build merged finding ─────────────────
    const topSev = highestSeverity(group.map((f) => f.severity));

    // Sort by severity (worst first), then by file path for stable ordering
    const sorted = [...group].sort((a, b) => {
      const sevDiff = (SEV_RANK[a.severity] ?? 99) - (SEV_RANK[b.severity] ?? 99);
      if (sevDiff !== 0) return sevDiff;
      return (a.filePath ?? "").localeCompare(b.filePath ?? "");
    });

    const primary = sorted[0]!;

    const resources: IacResource[] = sorted.map((f) => {
      const raw = (f.rawOutput ?? {}) as Record<string, unknown>;
      return {
        filePath:  f.filePath  ?? null,
        lineStart: f.lineStart ?? null,
        lineEnd:   f.lineEnd   ?? null,
        resource:  (raw["resource"]    as string | null) ?? null,
        snippet:   f.codeSnippet       ?? null,
        severity:  f.severity,
        checkType: (raw["check_type"]  as string | null) ?? null,
      };
    });

    // Update description to mention the count
    const countLabel = `${group.length} resource${group.length !== 1 ? "s" : ""}`;
    const baseDesc   = primary.description ?? primary.title;
    // Strip any old "affects N resources" suffix before appending a fresh one
    const cleanDesc  = baseDesc.replace(/\s*—\s*affects \d+ resources?\.?$/, "");
    const description = `${cleanDesc} — affects ${countLabel}.`;

    result.push({
      ...primary,
      fingerprint: fp,
      severity:    topSev as NormalizedFinding["severity"],
      description,
      rawOutput: {
        merged:    true,
        count:     group.length,
        ruleId,
        scanner:   primary.scanner,
        resources,
        primary:   primary.rawOutput,
      },
    });
  }

  return result;
}

// ── SECRET rule-level merge ───────────────────────────────────────────────────

/**
 * One occurrence of a secret type found in a different file/line.
 * Stored inside rawOutput.occurrences[] of the merged finding.
 */
interface SecretOccurrence {
  filePath:  string | null;
  lineStart: number | null;
  snippet:   string | null;
  verified:  boolean;
  severity:  string;
  scanner:   string;
}

/**
 * Deterministic fingerprint keyed to detector identity within a repo target.
 */
function secretRuleFingerprint(orgId: string, targetId: string, ruleId: string): string {
  return createHash("sha256")
    .update(`${orgId}:secret-rule:${targetId}:${ruleId}`)
    .digest("hex");
}

/**
 * Collapse all per-file SECRET findings for the same detector/ruleId into one
 * merged finding. Each file occurrence becomes an entry in rawOutput.occurrences[].
 *
 * Rules:
 *  - Severity   → highest (CRITICAL if any verified, else HIGH)
 *  - Confidence → highest across occurrences
 *  - title      → unchanged (detector name)
 *  - rawOutput  → { merged: true, count, ruleId, scanner, occurrences: [...] }
 */
function mergeSecretFindings(
  findings: NormalizedFinding[],
  orgId:    string,
  targetId: string,
): NormalizedFinding[] {
  const groups = new Map<string, NormalizedFinding[]>();
  for (const f of findings) {
    const key = f.ruleId ?? f.title ?? "unknown";
    if (!groups.has(key)) groups.set(key, []);
    groups.get(key)!.push(f);
  }

  const result: NormalizedFinding[] = [];

  for (const [ruleId, group] of groups.entries()) {
    const fp = secretRuleFingerprint(orgId, targetId, ruleId);

    if (group.length === 1) {
      result.push({ ...group[0]!, fingerprint: fp });
      continue;
    }

    // ── Multiple occurrences → build merged finding ───────────────────────
    const topSev  = highestSeverity(group.map((f) => f.severity));
    const topConf = group.reduce<string>((best, f) => {
      const c = f.confidence ?? "POSSIBLE";
      const CONF_RANK: Record<string, number> = { POSSIBLE: 0, LIKELY: 1, CONFIRMED: 2 };
      return (CONF_RANK[c] ?? 0) > (CONF_RANK[best] ?? 0) ? c : best;
    }, "POSSIBLE");

    // Sort: verified first, then by severity
    const sorted = [...group].sort((a, b) => {
      const aVerified = (a.rawOutput as Record<string, unknown>)?.["Verified"] === true ? 0 : 1;
      const bVerified = (b.rawOutput as Record<string, unknown>)?.["Verified"] === true ? 0 : 1;
      if (aVerified !== bVerified) return aVerified - bVerified;
      return (SEV_RANK[a.severity] ?? 99) - (SEV_RANK[b.severity] ?? 99);
    });

    const primary = sorted[0]!;

    const occurrences: SecretOccurrence[] = sorted.map((f) => ({
      filePath:  f.filePath  ?? null,
      lineStart: f.lineStart ?? null,
      snippet:   f.codeSnippet ?? null,
      verified:  (f.rawOutput as Record<string, unknown>)?.["Verified"] === true,
      severity:  f.severity,
      scanner:   f.scanner,
    }));

    result.push({
      ...primary,
      fingerprint: fp,
      severity:    topSev as NormalizedFinding["severity"],
      confidence:  topConf as NormalizedFinding["confidence"],
      rawOutput: {
        merged:      true,
        count:       group.length,
        ruleId,
        scanner:     primary.scanner,
        occurrences,
        primary:     primary.rawOutput,
      },
    });
  }

  return result;
}

// ── SAST rule-level merge ─────────────────────────────────────────────────────

/**
 * Location entry stored inside rawOutput.locations for merged SAST findings.
 * Consumed by the frontend SubissuesPanel.
 */
interface SastLocation {
  filePath:  string | null;
  lineStart: number | null;
  lineEnd:   number | null;
  severity:  string;
  message:   string;
  snippet:   string | null;  // actual lines of code from Semgrep extra.lines
}

/** Deterministic fingerprint keyed to rule identity within a target. */
function ruleFingerprint(orgId: string, targetId: string, ruleId: string): string {
  return createHash("sha256")
    .update(`${orgId}:sast-rule:${targetId}:SAST:${ruleId}`)
    .digest("hex");
}

/**
 * Collapse all location-level SAST findings for the same ruleId into one
 * merged finding. The scanner emits one finding per match; this reduces noise
 * to one card per vulnerability type per target.
 *
 * The merged rawOutput stores:
 *   { merged: true, count: N, ruleId, locations: SastLocation[], primary: <semgrep item> }
 *
 * filePath/lineStart/lineEnd/codeSnippet on the merged finding point at the
 * most-severe location so the fix suggestion service has a concrete anchor.
 */
function mergeSastFindings(
  findings: NormalizedFinding[],
  orgId:    string,
  targetId: string,
): NormalizedFinding[] {
  // Group by ruleId
  const groups = new Map<string, NormalizedFinding[]>();
  for (const f of findings) {
    const key = f.ruleId ?? "unknown";
    if (!groups.has(key)) groups.set(key, []);
    groups.get(key)!.push(f);
  }

  const result: NormalizedFinding[] = [];

  for (const [ruleId, group] of groups.entries()) {
    const fp = ruleFingerprint(orgId, targetId, ruleId);

    if (group.length === 1) {
      // Single occurrence — still switch to rule-level fingerprint for consistency
      result.push({ ...group[0]!, fingerprint: fp, ruleId });
      continue;
    }

    // ── Multiple locations → build merged finding ──────────────────────
    const sortedBySev = [...group].sort(
      (a, b) => (SEV_RANK[a.severity] ?? 99) - (SEV_RANK[b.severity] ?? 99),
    );

    const topSev  = highestSeverity(group.map((f) => f.severity));
    const primary = sortedBySev[0]!; // most severe occurrence — always defined (group.length > 1)

    // Build per-location data for the Subissues panel
    const locations: SastLocation[] = sortedBySev.map((f) => {
      // Semgrep stores the matched lines in extra.lines inside rawOutput.
      // "requires login" is a Semgrep Pro paywall placeholder — discard it.
      const raw = f.rawOutput as Record<string, unknown> | undefined;
      const extra = raw?.["extra"] as Record<string, unknown> | undefined;
      const rawLines = typeof extra?.["lines"] === "string" ? (extra["lines"] as string).trim() : null;
      const snippet =
        (rawLines && !/^requires?\s+login$/i.test(rawLines) ? rawLines : null)
        ?? f.codeSnippet
        ?? null;
      return {
        filePath:  f.filePath  ?? null,
        lineStart: f.lineStart ?? null,
        lineEnd:   f.lineEnd   ?? null,
        severity:  f.severity,
        message:   f.description,
        snippet,
      };
    });

    result.push({
      ...primary,
      fingerprint:  fp,
      ruleId,
      title:        primary.title,
      severity:     topSev as NormalizedFinding["severity"],
      // Primary location fields — used by fix suggestion GitHub fetch
      filePath:     primary.filePath,
      lineStart:    primary.lineStart,
      lineEnd:      primary.lineEnd,
      codeSnippet:  primary.codeSnippet,
      rawOutput: {
        merged:    true,
        count:     group.length,
        ruleId,
        locations,
        // Keep primary raw output intact so fix suggestion service can read
        // extra.lines, check_id, etc. from the most critical occurrence
        primary: primary.rawOutput,
      },
    });
  }

  return result;
}

// ── DAST / Pentest rule-level merge ──────────────────────────────────────────

/**
 * One occurrence of the same vulnerability type hitting a different URL/parameter.
 * Stored inside rawOutput.occurrences[] of the merged finding.
 */
interface DastHttpExchange {
  request_header:  string | null;
  request_body:    string | null;
  response_header: string | null;
  response_body:   string | null;
}

interface DastOccurrence {
  url:                  string;
  param:                string | null;
  severity:             string;
  confidence:           string;
  zapConfidence:        string;
  responseStatus:       string | number | null;
  evidence:             string | null;
  attack:               string | null;
  other:                string | null;
  httpExchange:         DastHttpExchange | null;   // attack exchange
  httpBaselineExchange: DastHttpExchange | null;   // baseline probe for diff view
}

/**
 * Deterministic fingerprint keyed to rule identity within a domain target.
 * Scoped to org + target so the same rule on different domains stays separate.
 */
function dastRuleFingerprint(
  orgId:    string,
  targetId: string,
  scanType: string,
  ruleId:   string,
): string {
  return createHash("sha256")
    .update(`${orgId}:dast-rule:${targetId}:${scanType}:${ruleId}`)
    .digest("hex");
}

/**
 * Collapse all URL-level DAST/Pentest findings for the same ruleId into one
 * merged finding.  The scanner emits one finding per alert instance; this
 * reduces noise so "SQL Injection detected on 8 URLs" becomes a single card
 * with an expandable Affected URLs list — exactly like SAST Subissues.
 *
 * Rules:
 *  - Severity    → highest across all occurrences
 *  - Confidence  → highest across all occurrences
 *  - title       → unchanged (the ZAP/Nuclei rule name)
 *  - description → first non-empty description (typically the same for all)
 *  - rawOutput   → { merged: true, count, ruleId, scanner, occurrences: [...] }
 *  - filePath    → URL of the most-severe occurrence (for reference)
 *
 * Single-occurrence findings still get the rule-level fingerprint for
 * consistency (so re-scans finding more instances merge cleanly).
 */
function mergeDastFindings(
  findings: NormalizedFinding[],
  orgId:    string,
  targetId: string,
  scanType: string,
): NormalizedFinding[] {
  // Group by ruleId (ZAP alertRef / Nuclei template-id)
  const groups = new Map<string, NormalizedFinding[]>();
  for (const f of findings) {
    // Fallback: normalise title so "SQL Injection" from different sub-scanners
    // (ZAP vs Nuclei) merges when the ruleId differs but the title is the same.
    const key = f.ruleId ?? f.title ?? "unknown";
    if (!groups.has(key)) groups.set(key, []);
    groups.get(key)!.push(f);
  }

  const CONF_RANK: Record<string, number> = { POSSIBLE: 0, LIKELY: 1, CONFIRMED: 2 };

  const result: NormalizedFinding[] = [];

  for (const [ruleId, group] of groups.entries()) {
    const fp = dastRuleFingerprint(orgId, targetId, scanType, ruleId);

    // Always emit the merged structure, even for single hits — keeps the
    // drawer's rendering path uniform (Affected URLs panel + HTTP Exchange
    // viewer appear whether a rule fires 1× or 50×).
    const sortedBySev = [...group].sort(
      (a, b) => (SEV_RANK[a.severity] ?? 99) - (SEV_RANK[b.severity] ?? 99),
    );

    const topSev  = highestSeverity(group.map((f) => f.severity));
    const primary = sortedBySev[0]!;  // most severe occurrence — always defined

    // Highest confidence across all occurrences
    const topConf = group.reduce<string>((best, f) => {
      const c = f.confidence ?? "POSSIBLE";
      return (CONF_RANK[c] ?? 0) > (CONF_RANK[best] ?? 0) ? c : best;
    }, "POSSIBLE");

    // Build per-occurrence payload consumed by DastSubissuesPanel
    const occurrences: DastOccurrence[] = sortedBySev.map((f) => {
      const ev = (f.evidence ?? {}) as Record<string, unknown>;
      return {
        url:            (ev["url"]              as string)         ?? f.filePath ?? "",
        param:          (ev["param"]            as string | null)  ?? null,
        severity:        f.severity,
        confidence:      f.confidence ?? "POSSIBLE",
        zapConfidence:  (ev["zap_confidence"]   as string)         ?? "",
        responseStatus: (ev["response_status"]  as string | number | null) ?? null,
        evidence:       (ev["evidence"]         as string | null)  ?? null,
        attack:         (ev["attack"]           as string | null)  ?? null,
        other:          (ev["other"]            as string | null)  ?? null,
        httpExchange:         (ev["http_exchange"]          as DastHttpExchange | null) ?? null,
        httpBaselineExchange: (ev["http_baseline_exchange"] as DastHttpExchange | null) ?? null,
      };
    });

    result.push({
      ...primary,
      fingerprint: fp,
      severity:    topSev as NormalizedFinding["severity"],
      confidence:  topConf as NormalizedFinding["confidence"],
      // filePath on the parent → URL of the highest-severity hit (handy for display)
      filePath: occurrences[0]?.url ?? primary.filePath ?? undefined,
      rawOutput: {
        merged:      true,
        count:       group.length,
        ruleId,
        scanner:     primary.scanner,
        occurrences,
        // Preserve primary raw so AI analysis / remediation context is intact
        primary:     primary.rawOutput,
      },
    });
  }

  return result;
}

// ── Upsert ────────────────────────────────────────────────────────────────────

interface UpsertOptions {
  scanJobId:  string;
  orgId:      string;
  targetType: TargetType;
  targetId:   string;
  scanType:   ScanType;
  findings:   NormalizedFinding[];
}

export interface NewFindingRef {
  id:       string;
  scanType: string;
  severity: string;
}

export async function upsertFindings(opts: UpsertOptions): Promise<{ newCount: number; totalCount: number; fixedCount: number; confirmedCount: number; newFindings: NewFindingRef[] }> {
  const { scanJobId, orgId, targetType, targetId, scanType, findings: rawFindings } = opts;

  if (rawFindings.length === 0) return { newCount: 0, totalCount: 0, fixedCount: 0, confirmedCount: 0, newFindings: [] };

  // Merge per-CVE SCA/CONTAINER findings → one per package+version
  // Merge per-location SAST findings       → one per rule per target
  // Merge per-URL DAST/Pentest findings    → one per rule/alert-type per target
  //
  // NOTE: Semgrep (scanType=SAST) can emit IAC and SECRET findings too.
  //       Only true SAST findings go through mergeSastFindings; the others
  //       pass through directly so they get the correct scanType + fingerprint.
  let findings: NormalizedFinding[];
  if (scanType === "SCA" || scanType === "CONTAINER") {
    findings = mergePackageFindings(rawFindings, orgId, targetId, scanType);
  } else if (scanType === "SAST") {
    // Semgrep emits a mix of SAST / IAC / SECRET findings in one run. Route each
    // sub-type through its own merger so SECRET / IAC findings don't end up as
    // one row per file/line (they previously bypassed merging entirely).
    const trueSast = rawFindings.filter((f) => !f.scanType || f.scanType === "SAST");
    const secret   = rawFindings.filter((f) => f.scanType === "SECRET");
    const iac      = rawFindings.filter((f) => f.scanType === "IAC");
    const other    = rawFindings.filter((f) =>
      f.scanType && !["SAST", "SECRET", "IAC"].includes(f.scanType),
    );
    findings = [
      ...mergeSastFindings(trueSast, orgId, targetId),
      ...(secret.length ? mergeSecretFindings(secret, orgId, targetId) : []),
      ...(iac.length    ? mergeIacFindings(iac,       orgId, targetId) : []),
      ...other,
    ];
  } else if (scanType === "DAST" || scanType === "PENTEST" || scanType === "PENTEST_FULL") {
    findings = mergeDastFindings(rawFindings, orgId, targetId, scanType);
  } else if (scanType === "SECRET") {
    findings = mergeSecretFindings(rawFindings, orgId, targetId);
  } else if (scanType === "IAC") {
    findings = mergeIacFindings(rawFindings, orgId, targetId);
  } else {
    findings = rawFindings;
  }

  // Pre-fetch existing findings — need fingerprint for new-count tracking, and
  // rawOutput so we can preserve backfilled location snippets on re-scan.
  const fingerprints = findings.map((f) => f.fingerprint);
  const existing = await prisma.finding.findMany({
    where:  { fingerprint: { in: fingerprints } },
    select: { fingerprint: true, rawOutput: true, status: true },
  });
  const existingMap = new Map(existing.map((e: { fingerprint: string; rawOutput: unknown; status: string }) => [e.fingerprint, e]));
  const existingSet = new Set(existing.map((e: { fingerprint: string }) => e.fingerprint));

  const now = new Date();

  let reopenedCount = 0;
  for (const rawF of findings) {
    // Scrub NUL bytes from all string fields — Postgres jsonb rejects them.
    const f = stripNulBytes(rawF);

    // ── Re-observation reopen ─────────────────────────────────────────────
    // If the scanner sees a fingerprint that is currently FIXED, the issue
    // is demonstrably still present (auto-fix or a user's "mark fixed" was
    // premature) — reopen it. Leave FALSE_POSITIVE / IGNORED alone because
    // those statuses are user-curated judgments about the finding, not
    // about remediation.
    const prev = existingMap.get(f.fingerprint);
    const shouldReopen = prev?.status === "FIXED";
    if (shouldReopen) reopenedCount += 1;

    // Phase 14 — pull reachability classification out of evidence so it
    // lands on the proper schema column. The scanner sets one of
    // REACHABLE / NOT_REACHABLE for SCA findings; for non-SCA scan types
    // (DAST/SAST/SECRET/IAC etc) the concept doesn't apply, so default
    // to NOT_APPLICABLE. SCA findings whose scanner didn't classify (old
    // images, or scanner failure) stay UNKNOWN — better than a wrong
    // NOT_REACHABLE.
    const ev = (f.evidence ?? {}) as Record<string, unknown>;
    const evReach = ev["reachability"];
    let reachability: "REACHABLE" | "NOT_REACHABLE" | "UNKNOWN" | "NOT_APPLICABLE";
    if (f.scanType === "SCA" || f.scanType === "CONTAINER") {
      reachability = (evReach === "REACHABLE" || evReach === "NOT_REACHABLE")
        ? evReach
        : "UNKNOWN";
    } else {
      reachability = "NOT_APPLICABLE";
    }
    const reachabilityEvidence = ev["reachability_evidence"];

    // Phase 29-prep MITRE upgrade: classify SCA / CONTAINER / SAST findings
    // via CWE → ATT&CK when the scanner supplied a CWE but didn't emit
    // its own MITRE classification. Wazuh ingest does its own classify
    // call (see wazuhIngestService.vulnToMitre) so we don't duplicate the
    // work here for RUNTIME findings — we only fill the gap on
    // upstream-scanner findings whose evidence lacks `mitre.*`.
    const hasCweInput = (f.cweId && f.cweId.length > 0) || (f.cveId && f.cveId.length > 0);
    if (hasCweInput && !ev["mitre"]) {
      const classification = classifyVulnerability({
        cveId:       f.cveId,
        cweIds:      f.cweId ? [f.cweId] : [],
        description: f.description ?? "",
        cvssScore:   f.cvssScore ?? 0,
      });
      if (classification) {
        // Mutate the in-memory evidence so the upsert below picks it up.
        // Also append T-codes to references[] so the FindingDetailDrawer
        // surfaces them as clickable links — same pattern Wazuh ingest
        // uses.
        f.evidence = { ...ev, mitre: classification };
        const refs = [...(f.references ?? [])];
        for (const t of classification.techniques) {
          const ref = `MITRE ATT&CK ${t}`;
          if (!refs.includes(ref)) refs.push(ref);
        }
        f.references = refs;
      }
    }

    const upserted = await prisma.finding.upsert({
      where: { fingerprint: f.fingerprint },
      create: {
        orgId,
        scanJobId,
        targetType,
        repositoryId: targetType === "REPOSITORY" ? targetId : null,
        containerId:  targetType === "CONTAINER"  ? targetId : null,
        domainId:     targetType === "DOMAIN"     ? targetId : null,
        scanType:     f.scanType,
        title:        f.title,
        description:  f.description,
        severity:     f.severity,
        status:       "OPEN",
        filePath:     f.filePath     ?? null,
        lineStart:    f.lineStart    ?? null,
        lineEnd:      f.lineEnd      ?? null,
        codeSnippet:  f.codeSnippet  ?? null,
        cveId:        f.cveId        ?? null,
        cweId:        f.cweId        ?? null,
        packageName:  f.packageName  ?? null,
        packageVersion: f.packageVersion ?? null,
        fixVersion:   f.fixVersion   ?? null,
        cvssScore:    f.cvssScore    ?? null,
        scanner:      f.scanner,
        ruleId:       f.ruleId       ?? null,
        fingerprint:  f.fingerprint,
        remediation:  f.remediation  ?? null,
        references:   f.references   ?? [],
        rawOutput:    (f.rawOutput   ?? {}) as object,
        firstSeen:    now,
        lastSeen:     now,
        confidence:   (f.confidence  ?? "POSSIBLE") as "CONFIRMED" | "LIKELY" | "POSSIBLE",
        evidence:     f.evidence ? (f.evidence as object) : undefined,
        reachability,
        reachabilityEvidence: reachabilityEvidence ? (reachabilityEvidence as object) : undefined,
      },
      update: {
        lastSeen:     now,
        // Re-observed fingerprints that were wrongly marked FIXED get reopened.
        // `undefined` means "don't touch" so manual FALSE_POSITIVE / IGNORED
        // and still-OPEN / ACKNOWLEDGED rows are preserved as-is.
        ...(shouldReopen ? { status: "OPEN" as const, resolvedAt: null } : {}),
        // Reset the absence counter every time the fingerprint is re-observed —
        // even a single hit means the scanner still sees the issue, so any
        // past near-misses should not count toward auto-close.
        absenceCount: 0,
        // Always refresh these so re-scans reflect updated CVE data
        title:        f.title,
        description:  f.description,
        severity:     f.severity,
        cvssScore:    f.cvssScore    ?? null,
        fixVersion:   f.fixVersion   ?? null,
        remediation:  f.remediation  ?? null,
        references:   f.references   ?? [],
        // Phase 14 — re-classify reachability on every re-scan. A package
        // that was REACHABLE last week may have been removed since
        // (NOT_REACHABLE), or vice versa. Don't preserve stale verdicts.
        reachability,
        reachabilityEvidence: reachabilityEvidence ? (reachabilityEvidence as object) : null,
        // Refresh location + snippet so re-scans backfill any previously-empty
        // values (e.g. older Semgrep IAC findings that were stored without a
        // code_snippet before the scanner started emitting "N: code" prefixes).
        filePath:     f.filePath     ?? null,
        lineStart:    f.lineStart    ?? null,
        lineEnd:      f.lineEnd      ?? null,
        codeSnippet:  f.codeSnippet  ?? null,
        rawOutput:    (() => {
          const newRaw = (f.rawOutput ?? {}) as Record<string, unknown>;
          const prevRaw = existingMap.get(f.fingerprint)?.rawOutput as Record<string, unknown> | undefined;

          // Preserve backfilled location snippets in merged SAST findings:
          // the scanner always returns null snippets (Semgrep Pro paywall) so a
          // re-scan must not overwrite snippets that were fetched from GitHub.
          if (newRaw["merged"] === true && Array.isArray(newRaw["locations"])) {
            const prevLocs = prevRaw?.["locations"] as Array<Record<string, unknown>> | undefined;
            if (prevLocs) {
              const newLocs = (newRaw["locations"] as Array<Record<string, unknown>>).map((loc, i) => {
                const prevSnippet = prevLocs[i]?.["snippet"] as string | null | undefined;
                const hasSnippet  = typeof loc["snippet"] === "string" && (loc["snippet"] as string).trim().length > 0;
                return hasSnippet ? loc : { ...loc, snippet: prevSnippet ?? null };
              });
              return { ...newRaw, locations: newLocs } as object;
            }
          }

          // Preserve per-resource snippets in merged IAC findings:
          // Checkov emits code_block in the raw JSON which is always present, but
          // we re-read it from rawOutput on re-scan. Preserve old snippets just in case.
          if (newRaw["merged"] === true && Array.isArray(newRaw["resources"])) {
            const prevResources = prevRaw?.["resources"] as Array<Record<string, unknown>> | undefined;
            if (prevResources) {
              const newResources = (newRaw["resources"] as Array<Record<string, unknown>>).map((res, i) => {
                const prevSnippet = prevResources[i]?.["snippet"] as string | null | undefined;
                const hasSnippet  = typeof res["snippet"] === "string" && (res["snippet"] as string).trim().length > 0;
                return hasSnippet ? res : { ...res, snippet: prevSnippet ?? null };
              });
              return { ...newRaw, resources: newResources } as object;
            }
          }

          // Preserve per-occurrence snippets in merged SECRET findings:
          // TruffleHog only provides snippets when the file is readable on disk at
          // scan time; on re-scans the snippets may be missing — keep previous ones.
          if (newRaw["merged"] === true && Array.isArray(newRaw["occurrences"])) {
            const prevOccs = prevRaw?.["occurrences"] as Array<Record<string, unknown>> | undefined;
            if (prevOccs) {
              const newOccs = (newRaw["occurrences"] as Array<Record<string, unknown>>).map((occ, i) => {
                const prevSnippet = prevOccs[i]?.["snippet"] as string | null | undefined;
                const hasSnippet  = typeof occ["snippet"] === "string" && (occ["snippet"] as string).trim().length > 0;
                return hasSnippet ? occ : { ...occ, snippet: prevSnippet ?? null };
              });
              return { ...newRaw, occurrences: newOccs } as object;
            }
          }

          return newRaw as object;
        })(),
        confidence:   (f.confidence  ?? "POSSIBLE") as "CONFIRMED" | "LIKELY" | "POSSIBLE",
        ...(f.evidence ? { evidence: f.evidence as object } : {}),
        // NOT updated on re-scan:
        //   status    — preserves ACKNOWLEDGED / FALSE_POSITIVE set by the user
        //   firstSeen — stays as the original discovery date
        //   scanJobId — stays linked to the scan job that first found it
      },
    });

    // Phase 16: link the finding to compliance controls (CWE match +
    // keyword fallback). Idempotent — re-scans don't duplicate. Awaited
    // so a mapping failure surfaces as a scan error rather than being
    // silently lost; if perf becomes an issue with 500+ findings per
    // scan, batch this into a single createMany at the end of the loop.
    try {
      await applyMappingsToFinding({
        findingId: upserted.id,
        cweId:     f.cweId ?? null,
        title:     f.title,
      });
    } catch (err) {
      // Don't let a mapping failure abort the scan — the finding is
      // saved, the dashboards just won't show it under any control
      // until the next backfill runs. Log loudly so we notice.
      logger.warn("[compliance] failed to map finding to controls", {
        findingId: upserted.id,
        error:     (err as Error).message,
      });
    }

    existingSet.add(f.fingerprint);
  }

  const newFingerprints = new Set(
    fingerprints.filter((fp) => !existing.some((e: { fingerprint: string }) => e.fingerprint === fp))
  );
  const newCount = newFingerprints.size;

  // ── Auto-fix resolved findings ───────────────────────────────────────────
  // Any OPEN/ACKNOWLEDGED finding for this target+scanType absent from this
  // scan is now fixed. FALSE_POSITIVE / IGNORED are left alone.
  //
  // SAFETY GUARD: do NOT mass-fix when the incoming fingerprint list is
  // empty.  A zero-finding response from the scanner is indistinguishable
  // from a silent failure (TruffleHog rate-limited by verification APIs,
  // empty branch clone, detector miss, etc).  Under the naive rule
  // `fingerprint: { notIn: [] }` matches EVERY prior finding — one bad scan
  // would mass-close the entire backlog.  Require at least one live
  // fingerprint before trusting absence as proof of remediation.
  const targetFilter =
    targetType === "REPOSITORY" ? { repositoryId: targetId }
    : targetType === "CONTAINER" ? { containerId: targetId }
    : { domainId: targetId };

  // DAST-family scanners (ZAP, nuclei, nikto, testssl, sqlmap) have genuine
  // between-run variance from crawl-depth differences, rate-limits, expired
  // auth tokens, plugin updates, network flakiness, etc. A single absent
  // scan is NOT reliable proof of remediation. For these types we increment
  // an absence counter and only mark FIXED after `ABSENCE_THRESHOLD`
  // consecutive misses. Deterministic scanners (SAST/SCA/SECRET/IAC/
  // CONTAINER) keep the original single-miss behaviour.
  const DAST_FAMILY = new Set<ScanType>([
    "DAST", "PENTEST", "PENTEST_FULL",
  ]);
  const ABSENCE_THRESHOLD = 2;
  const isFlaky = DAST_FAMILY.has(scanType);

  let fixedCount = 0;
  if (fingerprints.length === 0) {
    logger.warn(
      "[findings] skipping auto-fix: scanner returned zero findings — treating " +
      "as unreliable signal, previous findings left OPEN",
      { orgId, scanType, targetType, targetId },
    );
  } else if (isFlaky) {
    // Step 1: bump absenceCount on every OPEN/ACKNOWLEDGED finding in scope
    // that's missing from this run. Uses atomic increment so concurrent
    // re-scans can't race.
    await prisma.finding.updateMany({
      where: {
        orgId,
        scanType,
        ...targetFilter,
        status:      { in: ["OPEN", "ACKNOWLEDGED"] },
        fingerprint: { notIn: fingerprints },
      },
      data: { absenceCount: { increment: 1 } },
    });

    // Step 2: close only those that have now reached the threshold.
    const res = await prisma.finding.updateMany({
      where: {
        orgId,
        scanType,
        ...targetFilter,
        status:       { in: ["OPEN", "ACKNOWLEDGED"] },
        fingerprint:  { notIn: fingerprints },
        absenceCount: { gte: ABSENCE_THRESHOLD },
      },
      data: {
        status:     "FIXED",
        resolvedAt: new Date(),
      },
    });
    fixedCount = res.count;

    logger.info("[findings] DAST-family auto-fix gated by absence counter", {
      scanType, closed: fixedCount, threshold: ABSENCE_THRESHOLD,
    });
  } else {
    const res = await prisma.finding.updateMany({
      where: {
        orgId,
        scanType,
        ...targetFilter,
        status:      { in: ["OPEN", "ACKNOWLEDGED"] },
        fingerprint: { notIn: fingerprints },
      },
      data: {
        status:     "FIXED",
        resolvedAt: new Date(),
      },
    });
    fixedCount = res.count;
  }

  // Fetch IDs for newly created findings so the scan worker can enqueue AI triage
  let newFindings: NewFindingRef[] = [];
  if (newFingerprints.size > 0) {
    newFindings = await prisma.finding.findMany({
      where:  { fingerprint: { in: [...newFingerprints] } },
      select: { id: true, scanType: true, severity: true },
    });
  }

  // ── Confirmed count ──────────────────────────────────────────────────────
  // Findings that already existed AND were seen again in this scan run.
  // Useful for the UI to distinguish "scan found nothing new" from "scan
  // re-confirmed N known issues still present" — a critical signal for
  // operators tracking remediation progress.
  const confirmedCount = fingerprints.length - newCount;

  if (reopenedCount > 0) {
    logger.info(
      `[findings] reopened ${reopenedCount} previously-FIXED finding(s) re-observed in this scan`,
      { orgId, scanType, targetType, targetId },
    );
  }

  // Phase 27 Slice B — fire-and-forget correlation refresh for this org.
  // Newly upserted findings get correlationGroupId/edges populated within
  // a few seconds; the hourly recurring sweep in correlationWorker.ts also
  // catches drift. Errors are logged + swallowed — correlation is best-
  // effort and never blocks scan completion.
  try {
    const { runCorrelationForOrg } = await import("./correlation/correlationService.js");
    runCorrelationForOrg(orgId).catch((err) => {
      logger.warn(`[correlation] inline refresh failed for org ${orgId}: ${err.message}`);
    });
  } catch (err) {
    logger.warn(`[correlation] failed to enqueue inline refresh: ${(err as Error).message}`);
  }

  return { newCount, totalCount: findings.length, fixedCount, confirmedCount, newFindings };
}

export function countBySeverity(findings: NormalizedFinding[]): Record<string, number> {
  const counts: Record<string, number> = { CRITICAL: 0, HIGH: 0, MEDIUM: 0, LOW: 0, INFO: 0 };
  for (const f of findings) counts[f.severity] = (counts[f.severity] ?? 0) + 1;
  return counts;
}
