/**
 * sarifExport — Phase A1 CI integration.
 *
 * Converts BreachLens findings to SARIF 2.1.0 (OASIS standard) so CI
 * dashboards (GitHub Code Scanning, GitLab, Bitbucket, Azure DevOps)
 * can ingest BreachLens results without bespoke parsers. Schema:
 *
 *   https://docs.oasis-open.org/sarif/sarif/v2.1.0/sarif-v2.1.0.html
 *
 * Two-level structure:
 *   - run.tool.driver.rules[]   — the catalogue of rule definitions
 *     (one entry per unique ruleId, with name + description + helpUri).
 *     SARIF consumers display these as the "rule" the finding violates.
 *   - run.results[]             — the findings themselves, each
 *     referencing a ruleId + carrying the location + level (severity).
 *
 * Severity mapping (BreachLens → SARIF level):
 *   CRITICAL, HIGH → "error"     (CI gate fails the build by default)
 *   MEDIUM         → "warning"
 *   LOW            → "note"
 *   INFO           → "none"
 *
 * Properties bag extension — SARIF lets tools attach any JSON to a
 * result via `properties`. We surface the BreachLens-specific axes
 * (cveId, packageName, fixVersion, cvssScore, scanType, confidence,
 * fingerprint) so downstream automation can filter on them without
 * needing to re-fetch from the API.
 *
 * CI usage pattern (validates against the GitHub Code Scanning
 * uploader requirements):
 *   curl -H "Cookie: $BREACHLENS_SESSION" \
 *        https://breachlens.local/api/scans/$SCAN_ID/export.sarif \
 *        > breachlens.sarif
 *   gh code-scanning upload-sarif --sarif-id breachlens-$SCAN_ID \
 *                                  --file breachlens.sarif
 */
import type { Finding, ScanJob } from "@prisma/client";

// SARIF 2.1.0 minimal type definitions — we only emit what we use.
// Full schema is sprawling; the subset below is what GitHub Code
// Scanning + GitLab + Bitbucket all accept.
export interface SarifLog {
  $schema: string;
  version: "2.1.0";
  runs:    SarifRun[];
}

interface SarifRun {
  tool: {
    driver: {
      name:           string;
      version:        string;
      informationUri: string;
      rules:          SarifRule[];
    };
  };
  invocations?: Array<{
    executionSuccessful: boolean;
    startTimeUtc?:       string;
    endTimeUtc?:         string;
  }>;
  results: SarifResult[];
}

interface SarifRule {
  id:               string;
  name:             string;
  shortDescription: { text: string };
  fullDescription?: { text: string };
  helpUri?:         string;
  properties?: {
    tags?:           string[];
    severity?:       string;
    "security-severity"?: string; // GitHub Code Scanning interprets this
                                  // as CVSS-like score for rule prioritisation
  };
}

interface SarifResult {
  ruleId:    string;
  level:     "error" | "warning" | "note" | "none";
  message:   { text: string };
  locations: SarifLocation[];
  /**
   * Stable identifier that GitHub Code Scanning uses to dedupe findings
   * across uploads. We use BreachLens's own fingerprint so the same
   * vuln re-uploaded after a fix doesn't re-open under a new ID.
   */
  partialFingerprints?: { breachlensFingerprint: string };
  properties?: Record<string, unknown>;
}

interface SarifLocation {
  physicalLocation: {
    artifactLocation: { uri: string };
    region?: {
      startLine?:   number;
      endLine?:     number;
      snippet?:     { text: string };
    };
  };
}

// ── Severity mapping ─────────────────────────────────────────────────────

function severityToSarifLevel(sev: string): SarifResult["level"] {
  switch (sev) {
    case "CRITICAL":
    case "HIGH":     return "error";
    case "MEDIUM":   return "warning";
    case "LOW":      return "note";
    default:         return "none";
  }
}

/**
 * GitHub Code Scanning uses `security-severity` (a 0.0-10.0 CVSS-like
 * score) to rank rules in the security overview. Map BreachLens
 * severity to a representative score so the CI surface ranks correctly
 * even when the underlying CVSS isn't populated (SAST findings, etc.).
 */
function severityToScore(sev: string, cvssScore: number | null): string {
  if (cvssScore !== null && cvssScore >= 0 && cvssScore <= 10) {
    return cvssScore.toFixed(1);
  }
  switch (sev) {
    case "CRITICAL": return "9.5";
    case "HIGH":     return "7.5";
    case "MEDIUM":   return "5.0";
    case "LOW":      return "3.0";
    default:         return "1.0";
  }
}

// ── Location synthesis ───────────────────────────────────────────────────
//
// SARIF requires every result to have at least one location. For
// findings without a file path (DAST URLs, container CVEs, runtime
// alerts), we synthesise a location URI that's still meaningful in the
// CI surface — e.g. `container://nginx:1.25` or `https://example.com/login`
// — so the GitHub Security tab shows something other than "(missing)".

function buildLocations(f: Finding): SarifLocation[] {
  // Prefer the typed file location when present (SAST/SCA/IaC/SECRET).
  if (f.filePath) {
    return [{
      physicalLocation: {
        // SARIF expects a URI; bare paths are treated as relative to
        // srcRoot, which matches GitHub Code Scanning's expectation.
        artifactLocation: { uri: f.filePath },
        ...(f.lineStart != null
          ? {
              region: {
                startLine: f.lineStart,
                ...(f.lineEnd != null ? { endLine: f.lineEnd } : {}),
                ...(f.codeSnippet ? { snippet: { text: f.codeSnippet } } : {}),
              },
            }
          : {}),
      },
    }];
  }

  // DAST/PENTEST findings — pull URL from evidence. Same shape as
  // recordingless DAST: the URL IS the location.
  const ev = (f.evidence as Record<string, unknown> | null) ?? {};
  const url = ev["url"] as string | undefined;
  if (url) {
    return [{ physicalLocation: { artifactLocation: { uri: url } } }];
  }

  // CONTAINER findings — synthesise container://imageRef path so the
  // CI surface groups CVEs by image.
  if (f.targetType === "CONTAINER") {
    const containerRef = (f.rawOutput as { container?: string } | null)?.container
                       ?? `container://${f.containerId ?? "unknown"}`;
    const path = f.packageName
      ? `${containerRef}#${f.packageName}${f.packageVersion ? "@" + f.packageVersion : ""}`
      : containerRef;
    return [{ physicalLocation: { artifactLocation: { uri: path } } }];
  }

  // RUNTIME findings (Wazuh) — synthesise wazuh-agent://<id>/<rule>
  if (f.scanType === "RUNTIME") {
    const agentName = (ev["agentName"] as string | undefined) ?? "unknown";
    const ruleId    = f.ruleId ?? "unknown";
    return [{ physicalLocation: { artifactLocation: { uri: `wazuh-agent://${agentName}/${ruleId}` } } }];
  }

  // Fallback — every result MUST have a location. Use an opaque marker
  // so the CI surface at least renders something parseable.
  return [{ physicalLocation: { artifactLocation: { uri: `breachlens://finding/${f.id}` } } }];
}

// ── Rule de-duplication ──────────────────────────────────────────────────
//
// SARIF's two-tier model expects each unique ruleId to appear ONCE in
// run.tool.driver.rules[]. Multiple results can reference the same
// rule. We coalesce findings by (scanType, ruleId|cveId|fingerprint-prefix)
// since BreachLens doesn't always have a clean ruleId (e.g. SECRET
// findings may use a hash; CONTAINER findings use the CVE ID).

interface RuleAccumulator {
  id:           string;
  name:         string;
  description:  string;
  helpUri:      string | null;
  scanType:     string;
  maxSeverity:  string;
  cvssScore:    number | null;
}

function ruleKeyForFinding(f: Finding): string {
  // Order of preference: explicit ruleId → CVE → scanner+title hash.
  if (f.ruleId)   return `${f.scanType}/${f.ruleId}`;
  if (f.cveId)    return `${f.scanType}/${f.cveId}`;
  // Last-resort: stable per-(scanner, title) so the Security tab groups
  // related findings sensibly even without a real ruleId.
  return `${f.scanType}/${f.scanner}/${f.title.slice(0, 80)}`;
}

function severityRank(sev: string): number {
  switch (sev) {
    case "CRITICAL": return 4;
    case "HIGH":     return 3;
    case "MEDIUM":   return 2;
    case "LOW":      return 1;
    default:         return 0;
  }
}

// ── Main exporter ────────────────────────────────────────────────────────

export interface ScanContext {
  scan: ScanJob;
  apiBaseUrl: string;     // for helpUri construction (links back to the
                          // BreachLens UI from the GitHub Security tab)
  toolVersion?: string;   // optional, defaults to "0.1.0"
}

export function findingsToSarif(
  findings: Finding[],
  ctx:      ScanContext,
): SarifLog {
  // 1. Build the rule catalogue by unique key. Highest-severity finding
  //    in each rule group wins for the rule's representative severity.
  const ruleAcc = new Map<string, RuleAccumulator>();
  for (const f of findings) {
    const key = ruleKeyForFinding(f);
    const existing = ruleAcc.get(key);
    if (existing) {
      if (severityRank(f.severity) > severityRank(existing.maxSeverity)) {
        existing.maxSeverity = f.severity;
      }
      if (f.cvssScore != null && (existing.cvssScore == null || f.cvssScore > existing.cvssScore)) {
        existing.cvssScore = f.cvssScore;
      }
    } else {
      ruleAcc.set(key, {
        id:          key,
        name:        f.ruleId ?? f.cveId ?? `${f.scanner}-${f.scanType}`,
        description: f.title,
        helpUri:     `${ctx.apiBaseUrl}/findings?id=${f.id}`,
        scanType:    f.scanType,
        maxSeverity: f.severity,
        cvssScore:   f.cvssScore ?? null,
      });
    }
  }

  const rules: SarifRule[] = Array.from(ruleAcc.values()).map((r) => ({
    id:               r.id,
    name:             r.name,
    shortDescription: { text: r.description.slice(0, 256) },
    fullDescription:  { text: r.description },
    ...(r.helpUri ? { helpUri: r.helpUri } : {}),
    properties: {
      tags:                ["breachlens", r.scanType.toLowerCase()],
      severity:            r.maxSeverity,
      // GitHub Code Scanning uses this to rank in the security overview.
      "security-severity": severityToScore(r.maxSeverity, r.cvssScore),
    },
  }));

  // 2. Build the results.
  const results: SarifResult[] = findings.map((f) => ({
    ruleId:  ruleKeyForFinding(f),
    level:   severityToSarifLevel(f.severity),
    message: {
      text: f.description.length > 0
        ? f.description.slice(0, 1024)
        : f.title,
    },
    locations: buildLocations(f),
    partialFingerprints: { breachlensFingerprint: f.fingerprint },
    properties: {
      severity:       f.severity,
      scanType:       f.scanType,
      scanner:        f.scanner,
      confidence:     f.confidence,
      status:         f.status,
      ...(f.cveId          ? { cveId:          f.cveId }          : {}),
      ...(f.cweId          ? { cweId:          f.cweId }          : {}),
      ...(f.packageName    ? { packageName:    f.packageName }    : {}),
      ...(f.packageVersion ? { packageVersion: f.packageVersion } : {}),
      ...(f.fixVersion     ? { fixVersion:     f.fixVersion }     : {}),
      ...(f.cvssScore != null ? { cvssScore:   f.cvssScore }      : {}),
      breachlensId:   f.id,
      breachlensUrl:  `${ctx.apiBaseUrl}/findings?id=${f.id}`,
    },
  }));

  return {
    $schema: "https://json.schemastore.org/sarif-2.1.0.json",
    version: "2.1.0",
    runs: [
      {
        tool: {
          driver: {
            name:           "BreachLens",
            version:        ctx.toolVersion ?? "0.1.0",
            informationUri: ctx.apiBaseUrl,
            rules,
          },
        },
        invocations: [
          {
            executionSuccessful: ctx.scan.status === "COMPLETED",
            ...(ctx.scan.startedAt   ? { startTimeUtc: ctx.scan.startedAt.toISOString() }   : {}),
            ...(ctx.scan.completedAt ? { endTimeUtc:   ctx.scan.completedAt.toISOString() } : {}),
          },
        ],
        results,
      },
    ],
  };
}
