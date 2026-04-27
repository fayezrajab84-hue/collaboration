/**
 * attackPathService — Phase 27 Slice C.
 *
 * Reads the correlation graph that Slice B persisted on Finding rows
 * (correlationGroupId + correlationEdges) and produces ranked attack paths
 * for the /attack-paths UI. The "best" path within a group is the one that
 * maximises the path-score formula:
 *
 *   pathScore = severity_max
 *             × pathLength             (more hops = scarier kill chain)
 *             × externalReach           (1.0 if entry node is internet-facing,
 *                                        else 0.5 for container, 0.3 for repo)
 *             × proofMultiplier         (1.5 if any node has confidence=CONFIRMED)
 *
 * For v1 we materialise paths on demand (no caching) — the data is small
 * (rarely more than a few hundred chains per org) and the UI can refetch
 * after a fresh scan. A future optimisation can persist top-N paths if
 * the org grows beyond what's quick to compute.
 */
import prisma from "../../db.js";
import type { Finding, Severity, Confidence, TargetType } from "@prisma/client";
import type { PersistedEdge } from "./bridgeInterface.js";

const SEV_WEIGHT: Record<Severity, number> = {
  CRITICAL: 4,
  HIGH:     3,
  MEDIUM:   2,
  LOW:      1,
  INFO:     0.5,
};

// Coarse internet-reach estimate without parsing CVSS. DOMAIN-targeted
// findings hit a public surface; CONTAINER and REPOSITORY findings need an
// external entry point (covered when the chain INCLUDES a domain finding).
function externalReach(entry: Finding): number {
  switch (entry.targetType) {
    case "DOMAIN":     return 1.0;
    case "CONTAINER":  return 0.5;
    case "REPOSITORY": return 0.3;
    default:           return 0.3;
  }
}

export interface AttackPathNode {
  findingId:  string;
  title:      string;
  severity:   Severity;
  scanType:   string;
  confidence: Confidence;
  targetType: TargetType;
  targetName: string | null;       // resolved repo name / image ref / domain
  filePath:   string | null;
  evidence:   Record<string, unknown> | null;
  // Phase 27.5.x — scan-type-specific specifics so the chain card answers
  // "WHICH vulnerability" inline. Without these the operator had to click
  // every node to find the line number / package / CVE.
  lineStart:      number | null;   // SAST/IAC/SECRET source-line
  ruleId:         string | null;   // Semgrep / Trivy / nuclei rule id
  cveId:          string | null;   // SCA / CONTAINER CVE
  cweId:          string | null;   // every scan type when known
  packageName:    string | null;   // SCA / CONTAINER affected package
  packageVersion: string | null;
  fixVersion:     string | null;   // SCA — what to bump to
  cvssScore:      number | null;
}

export interface AttackPathEdge {
  fromFindingId: string;
  toFindingId:   string;
  bridgeType:    PersistedEdge["bridgeType"];
  reason:        string;
  confidence:    PersistedEdge["confidence"];
}

export interface AttackPathSummary {
  groupId:         string;
  /** Phase 27.5.x — distinctive heuristic title built from the chain's
   *  lead finding (highest-severity, source-side preferred for root-cause
   *  framing). Always populated even when no AI summary exists. The UI
   *  can override with the AI tldr when one is generated. */
  title:           string;
  score:           number;
  length:          number;
  maxSeverity:     Severity;
  hasConfirmed:    boolean;
  externalReach:   number;
  /**
   * Phase 27.5.x — Application IDs that this chain's findings belong to.
   * Powers the /attack-paths Application MultiSelect filter (chain matches
   * when ANY of its asset's applications is in the selected set). Per-app
   * correlation means this is usually a single-element array, but a chain
   * crossing app boundaries (legacy data, manual re-assignment mid-sweep)
   * may briefly carry multiple — surface them honestly so the UI can
   * indicate "spans 2 applications".
   */
  applicationIds:  string[];
  // The "best" path through the group — for the list view.
  nodes:           AttackPathNode[];
  edges:           AttackPathEdge[];
}

/**
 * List ranked attack paths for an org. `limit` caps the result for the
 * dashboard; the UI passes 50 for the main page.
 */
export async function listAttackPaths(orgId: string, limit = 50): Promise<AttackPathSummary[]> {
  const findings = await prisma.finding.findMany({
    where: {
      orgId,
      correlationGroupId: { not: null },
      status:             { not: "FALSE_POSITIVE" },
    },
    include: {
      repository: { select: { fullName: true, applicationId: true } },
      container:  { select: { imageRef: true, applicationId: true } },
      domain:     { select: { domain: true,   applicationId: true } },
    },
  });

  // Group by correlationGroupId.
  const groups = new Map<string, typeof findings>();
  for (const f of findings) {
    const gid = f.correlationGroupId!;
    const list = groups.get(gid) ?? [];
    list.push(f);
    groups.set(gid, list);
  }

  const summaries: AttackPathSummary[] = [];
  for (const [groupId, members] of groups) {
    if (members.length < 2) continue;        // need at least an edge to count as a chain
    const summary = scoreGroup(groupId, members);
    if (summary) summaries.push(summary);
  }

  summaries.sort((a, b) => b.score - a.score);
  return summaries.slice(0, limit);
}

/** Fetch one chain in detail, by groupId. Returns null if no such group. */
export async function getAttackPath(orgId: string, groupId: string): Promise<AttackPathSummary | null> {
  const members = await prisma.finding.findMany({
    where: {
      orgId,
      correlationGroupId: groupId,
      status:             { not: "FALSE_POSITIVE" },
    },
    include: {
      repository: { select: { fullName: true, applicationId: true } },
      container:  { select: { imageRef: true, applicationId: true } },
      domain:     { select: { domain: true,   applicationId: true } },
    },
  });
  if (members.length === 0) return null;
  return scoreGroup(groupId, members);
}

// ── Internals ─────────────────────────────────────────────────────────

type WithTargets = Awaited<ReturnType<typeof prisma.finding.findMany>>[number] & {
  repository?: { fullName: string; applicationId: string | null } | null;
  container?:  { imageRef: string; applicationId: string | null } | null;
  domain?:     { domain: string;   applicationId: string | null } | null;
};

function scoreGroup(groupId: string, members: WithTargets[]): AttackPathSummary | null {
  if (members.length === 0) return null;

  // Chain length is just the member count for the v1 list view; a future
  // graph-traversal version can compute the actual longest-path through
  // the group. For ranking purposes the count is a reasonable proxy.
  const length = members.length;

  // Pick the entry node = the most "external" finding (DOMAIN > CONTAINER > REPO)
  // breaking ties by severity. The entry node decides externalReach.
  const sortedByReach = [...members].sort((a, b) => {
    const ar = externalReach(a as Finding);
    const br = externalReach(b as Finding);
    if (br !== ar) return br - ar;
    return SEV_WEIGHT[b.severity] - SEV_WEIGHT[a.severity];
  });
  const entry = sortedByReach[0]!;
  const reach = externalReach(entry as Finding);

  // Severity max.
  let maxSev: Severity = "INFO";
  for (const m of members) {
    if (SEV_WEIGHT[m.severity] > SEV_WEIGHT[maxSev]) maxSev = m.severity;
  }

  // Proof multiplier — does ANY member have confidence=CONFIRMED?
  const hasConfirmed = members.some((m) => m.confidence === "CONFIRMED");
  const proofMult    = hasConfirmed ? 1.5 : 1.0;

  const score = Math.round(SEV_WEIGHT[maxSev] * length * reach * proofMult * 100) / 100;

  // Materialise nodes ordered by externalReach (entry first → deepest last).
  const nodes: AttackPathNode[] = sortedByReach.map((m) => ({
    findingId:  m.id,
    title:      m.title,
    severity:   m.severity,
    scanType:   String(m.scanType),
    confidence: m.confidence,
    targetType: m.targetType,
    targetName:
      (m.repository?.fullName) ??
      (m.container?.imageRef) ??
      (m.domain?.domain) ??
      null,
    filePath:   m.filePath,
    evidence:   (m.evidence ?? null) as Record<string, unknown> | null,
    lineStart:      m.lineStart      ?? null,
    ruleId:         m.ruleId         ?? null,
    cveId:          m.cveId          ?? null,
    cweId:          m.cweId          ?? null,
    packageName:    m.packageName    ?? null,
    packageVersion: m.packageVersion ?? null,
    fixVersion:     m.fixVersion     ?? null,
    cvssScore:      m.cvssScore      ?? null,
  }));

  // Edges from correlationEdges — collapse duplicates per pair.
  const edges: AttackPathEdge[] = [];
  const seen = new Set<string>();
  for (const m of members) {
    const raw = (m.correlationEdges ?? []) as PersistedEdge[];
    for (const e of raw) {
      const key = [m.id, e.toFindingId].sort().join("|") + ":" + e.bridgeType;
      if (seen.has(key)) continue;
      seen.add(key);
      edges.push({
        fromFindingId: m.id,
        toFindingId:   e.toFindingId,
        bridgeType:    e.bridgeType,
        reason:        e.reason,
        confidence:    e.confidence,
      });
    }
  }

  // Phase 27.5.x — collect distinct application IDs for the chain so the
  // /attack-paths Application MultiSelect filter can match.
  const appIdSet = new Set<string>();
  for (const m of members) {
    const aid = m.repository?.applicationId
             ?? m.container?.applicationId
             ?? m.domain?.applicationId
             ?? null;
    if (aid) appIdSet.add(aid);
  }

  return {
    groupId,
    title:         deriveChainTitle(nodes),
    score,
    length,
    maxSeverity:   maxSev,
    hasConfirmed,
    externalReach: reach,
    applicationIds: Array.from(appIdSet),
    nodes,
    edges,
  };
}

/**
 * Heuristic title for a chain — the highest-severity finding's title,
 * preferring source-side scan types (SAST > IAC > SECRET > CONTAINER >
 * DAST > PENTEST > runtime) as a tie-breaker so the title leads with the
 * root cause rather than its observable effect.
 *
 * Examples:
 *   "Tainted Exec"          (SAST high — DVWA command-injection chain)
 *   "Md5 Loose Equality"    (SAST medium — login.php hashing chain)
 *   "Reflected XSS in /vulnerabilities/xss_r/"   (DAST high if no SAST hits)
 *
 * Always returns a non-empty string. The frontend can override with the
 * AI summary's tldr when one is available — this is the always-on fallback.
 */
function deriveChainTitle(nodes: AttackPathNode[]): string {
  if (nodes.length === 0) return "Empty chain";

  const SEV_WEIGHT: Record<string, number> = {
    CRITICAL: 4, HIGH: 3, MEDIUM: 2, LOW: 1, INFO: 0.5,
  };
  // Source-side first (root cause), then web-side (exploit angle), then
  // package/runtime. Lower number = higher priority.
  const TYPE_PRIORITY: Record<string, number> = {
    SAST: 1, IAC: 1, SECRET: 1,
    CONTAINER: 2, SCA: 2,
    DAST: 3, PENTEST: 3, PENTEST_FULL: 3,
    RUNTIME: 4,
  };

  const ranked = [...nodes].sort((a, b) => {
    const sevDiff = (SEV_WEIGHT[b.severity] ?? 0) - (SEV_WEIGHT[a.severity] ?? 0);
    if (sevDiff !== 0) return sevDiff;
    const aPri = TYPE_PRIORITY[a.scanType] ?? 99;
    const bPri = TYPE_PRIORITY[b.scanType] ?? 99;
    if (aPri !== bPri) return aPri - bPri;
    // Stable tiebreaker
    return a.findingId.localeCompare(b.findingId);
  });
  return ranked[0]?.title ?? "Correlated chain";
}
