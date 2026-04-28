/**
 * correlationService — Phase 27 Slice B engine.
 *
 * Runs every registered Bridge over every pair of findings in an org, then
 * walks the resulting graph using union-find so every finding in the same
 * connected component shares a `correlationGroupId`. Persists per-finding
 * `correlationEdges` so the UI can render the chain without re-running the
 * full sweep on every page view.
 *
 * Performance shape:
 *   - O(n²) bridge calls per org, where n = open findings count
 *   - At 10k findings, 50M comparisons; each bridge runs in microseconds
 *   - For larger orgs we'd shard by targetType + cveId — but v1 sticks with
 *     the simple full sweep; a recurring nightly job is plenty
 *
 * Caller surfaces:
 *   - `runCorrelationForOrg(orgId)` — full sweep; called by the recurring job
 *   - `runCorrelationForFinding(findingId)` — narrow refresh; called from the
 *     scan worker after upsertFindings persists a batch (incremental updates)
 */
import prisma from "../../db.js";
import { logger } from "../../logger.js";
import { cveBridge } from "./cveBridge.js";
import { routeBridge } from "./routeBridge.js";
import { portBridge } from "./portBridge.js";
import { secretBridge } from "./secretBridge.js";
import { containerExposureBridge } from "./containerExposureBridge.js";
import { runtimeBridge } from "./runtimeBridge.js";
import type {
  Bridge,
  BridgeContext,
  ContainerSummary,
  DomainSummary,
  PersistedEdge,
} from "./bridgeInterface.js";
import type { Finding } from "@prisma/client";

// Registered bridges — order doesn't matter; the engine sums all matches.
// Future slices append here without changing the engine.
const REGISTERED_BRIDGES: readonly Bridge[] = [
  cveBridge,
  routeBridge,
  portBridge,
  secretBridge,
  containerExposureBridge,
  runtimeBridge,  // Phase 28 Slice C — RUNTIME findings into chains
];

export interface CorrelationRunSummary {
  orgId:              string;
  findingsConsidered: number;
  bridgeMatches:      number;
  groupsFormed:       number;
  durationMs:         number;
}

/**
 * Full org sweep — Phase 27.5: dispatches per-application sweeps so chains
 * never cross application boundaries. Findings whose target asset has no
 * `applicationId` are explicitly cleared (correlationGroupId set to null)
 * — they DO NOT participate in any chain. This is the fix for the Phase 27
 * bug where unrelated apps sharing base-image CVEs collapsed into one mega-
 * chain.
 *
 * Returns the aggregate summary across all per-app sweeps.
 */
export async function runCorrelationForOrg(orgId: string): Promise<CorrelationRunSummary> {
  const started = Date.now();

  const apps = await prisma.application.findMany({
    where: { orgId },
    select: { id: true },
  });

  let findingsConsidered = 0;
  let bridgeMatches      = 0;
  let groupsFormed       = 0;

  for (const { id: applicationId } of apps) {
    const summary = await runCorrelationForApplication(orgId, applicationId);
    findingsConsidered += summary.findingsConsidered;
    bridgeMatches      += summary.bridgeMatches;
    groupsFormed       += summary.groupsFormed;
  }

  // Findings on assets that have no application get their correlation cleared
  // explicitly. Without this, a stale correlationGroupId from a prior org-
  // wide sweep would linger after Phase 27.5 ships.
  const cleared = await clearUnassignedFindings(orgId);
  if (cleared > 0) {
    logger.info(`[correlation] cleared correlation on ${cleared} unassigned findings (org ${orgId})`);
  }

  return {
    orgId,
    findingsConsidered,
    bridgeMatches,
    groupsFormed,
    durationMs: Date.now() - started,
  };
}

/**
 * Phase 27.5 — bridge sweep scoped to a single application's components.
 * Loads only findings on Repository / Container / Domain assets that share
 * `applicationId = applicationId`; cross-app pairs are never considered.
 */
export async function runCorrelationForApplication(
  orgId: string,
  applicationId: string,
): Promise<CorrelationRunSummary> {
  const started = Date.now();

  // Resolve the asset IDs that belong to this application.
  const [repos, containers, domains] = await Promise.all([
    prisma.repository.findMany({ where: { applicationId, orgId }, select: { id: true } }),
    prisma.container.findMany({  where: { applicationId, orgId }, select: { id: true } }),
    prisma.domain.findMany({     where: { applicationId, orgId }, select: { id: true } }),
  ]);

  const repoIds      = repos.map((r) => r.id);
  const containerIds = containers.map((c) => c.id);
  const domainIds    = domains.map((d) => d.id);

  if (repoIds.length === 0 && containerIds.length === 0 && domainIds.length === 0) {
    return { orgId, findingsConsidered: 0, bridgeMatches: 0, groupsFormed: 0, durationMs: Date.now() - started };
  }

  const findings = await prisma.finding.findMany({
    where: {
      orgId,
      status: { not: "FALSE_POSITIVE" },
      OR: [
        { repositoryId: { in: repoIds } },
        { containerId:  { in: containerIds } },
        { domainId:     { in: domainIds } },
      ],
    },
  });

  if (findings.length === 0) {
    return { orgId, findingsConsidered: 0, bridgeMatches: 0, groupsFormed: 0, durationMs: Date.now() - started };
  }

  const ctx = await buildContext(orgId);

  const edges = new Map<string, PersistedEdge[]>();
  const uf    = new UnionFind<string>();
  let bridgeMatches = 0;

  for (let i = 0; i < findings.length; i++) {
    const a = findings[i];
    if (!a) continue;
    uf.find(a.id);
    for (let j = i + 1; j < findings.length; j++) {
      const b = findings[j];
      if (!b) continue;
      for (const bridge of REGISTERED_BRIDGES) {
        const m = bridge.match(a, b, ctx);
        if (!m) continue;
        bridgeMatches++;
        appendEdge(edges, a.id, { toFindingId: b.id, ...m });
        appendEdge(edges, b.id, { toFindingId: a.id, ...m });
        uf.union(a.id, b.id);
      }
    }
  }

  const writes: Promise<unknown>[] = [];
  const groupIds = new Set<string>();
  for (const f of findings) {
    const root = uf.find(f.id);
    const isInChain = edges.has(f.id);
    const groupId = isInChain ? root : null;
    if (groupId) groupIds.add(groupId);
    writes.push(
      prisma.finding.update({
        where: { id: f.id },
        data: {
          correlationGroupId:    groupId,
          correlationEdges:      isInChain ? (edges.get(f.id) ?? []) : null,
          correlationComputedAt: new Date(),
        },
      }),
    );
  }
  await Promise.all(writes);

  return {
    orgId,
    findingsConsidered: findings.length,
    bridgeMatches,
    groupsFormed:       groupIds.size,
    durationMs:         Date.now() - started,
  };
}

/**
 * Clear correlation fields on findings whose target asset has no
 * applicationId. Without this, findings stamped during Phase 27 would
 * retain stale chain ids forever after the Phase 27.5 boundary lands.
 */
async function clearUnassignedFindings(orgId: string): Promise<number> {
  // Build the set of asset IDs that ARE assigned (so we exclude their
  // findings from the clear).
  const [assignedRepos, assignedContainers, assignedDomains] = await Promise.all([
    prisma.repository.findMany({ where: { orgId, applicationId: { not: null } }, select: { id: true } }),
    prisma.container.findMany({  where: { orgId, applicationId: { not: null } }, select: { id: true } }),
    prisma.domain.findMany({     where: { orgId, applicationId: { not: null } }, select: { id: true } }),
  ]);

  const assignedRepoIds      = assignedRepos.map((r) => r.id);
  const assignedContainerIds = assignedContainers.map((c) => c.id);
  const assignedDomainIds    = assignedDomains.map((d) => d.id);

  // Findings to clear: anything with a non-null correlationGroupId whose
  // target asset isn't in the assigned set.
  const result = await prisma.finding.updateMany({
    where: {
      orgId,
      correlationGroupId: { not: null },
      OR: [
        { AND: [
          { repositoryId: { not: null } },
          { repositoryId: { notIn: assignedRepoIds.length > 0 ? assignedRepoIds : ["__none__"] } },
        ]},
        { AND: [
          { containerId: { not: null } },
          { containerId: { notIn: assignedContainerIds.length > 0 ? assignedContainerIds : ["__none__"] } },
        ]},
        { AND: [
          { domainId: { not: null } },
          { domainId: { notIn: assignedDomainIds.length > 0 ? assignedDomainIds : ["__none__"] } },
        ]},
      ],
    },
    data: {
      correlationGroupId:    null,
      correlationEdges:      null,
      correlationComputedAt: new Date(),
    },
  });

  return result.count;
}

/**
 * Narrow refresh — recompute correlations involving a single finding. Used
 * from the scan worker so newly persisted findings are correlated without
 * waiting for the next nightly sweep.
 *
 * Implementation note: for v1 we just call `runCorrelationForOrg` on the
 * finding's org. That's O(n²) again per call but the scan worker batches
 * findings into one upsert so the cost amortises. A targeted-pair-only
 * version is a Phase 27.x optimisation when n grows beyond a few thousand.
 */
export async function runCorrelationForFinding(findingId: string): Promise<CorrelationRunSummary | null> {
  const f = await prisma.finding.findUnique({
    where:  { id: findingId },
    select: { orgId: true },
  });
  if (!f) return null;
  return runCorrelationForOrg(f.orgId);
}

// ── Internals ─────────────────────────────────────────────────────────

async function buildContext(orgId: string): Promise<BridgeContext> {
  const [containers, domains, agents] = await Promise.all([
    prisma.container.findMany({
      where:  { orgId },
      select: { id: true, imageRef: true, sourceRepositoryId: true, deployedAtDomainIds: true },
    }),
    prisma.domain.findMany({
      where:  { orgId },
      select: { id: true, domain: true, servesContainerIds: true },
    }),
    // Phase 28 Slice C — load WorkloadAgent → Container linkages so
    // runtimeBridge can resolve a RUNTIME Finding's agent_id to the
    // Container it monitors even when Finding.containerId wasn't set
    // at ingestion time (legacy alerts ingested before the operator
    // linked the agent).
    prisma.workloadAgent.findMany({
      where:  { orgId, linkedContainerId: { not: null } },
      select: { wazuhAgentId: true, linkedContainerId: true },
    }),
  ]);

  const containerById        = new Map<string, ContainerSummary>();
  const containersByImageRef = new Map<string, ContainerSummary[]>();
  for (const c of containers) {
    const summary: ContainerSummary = {
      id:                  c.id,
      imageRef:            c.imageRef,
      sourceRepositoryId:  c.sourceRepositoryId ?? null,
      deployedAtDomainIds: c.deployedAtDomainIds,
    };
    containerById.set(c.id, summary);
    const list = containersByImageRef.get(c.imageRef) ?? [];
    list.push(summary);
    containersByImageRef.set(c.imageRef, list);
  }

  const domainById = new Map<string, DomainSummary>();
  for (const d of domains) {
    domainById.set(d.id, { id: d.id, domain: d.domain, servesContainerIds: d.servesContainerIds });
  }

  const containerIdByWazuhAgentId = new Map<string, string>();
  for (const a of agents) {
    if (a.linkedContainerId) {
      containerIdByWazuhAgentId.set(a.wazuhAgentId, a.linkedContainerId);
    }
  }

  return { containerById, containersByImageRef, domainById, containerIdByWazuhAgentId };
}

function appendEdge(edges: Map<string, PersistedEdge[]>, key: string, edge: PersistedEdge): void {
  const list = edges.get(key) ?? [];
  // Skip exact duplicates (same toFindingId + bridgeType).
  if (list.some((e) => e.toFindingId === edge.toFindingId && e.bridgeType === edge.bridgeType)) return;
  list.push(edge);
  edges.set(key, list);
}

/** Lightweight union-find — used by the engine to coalesce edges into groups. */
class UnionFind<T> {
  private parent = new Map<T, T>();
  find(x: T): T {
    if (!this.parent.has(x)) { this.parent.set(x, x); return x; }
    let cur = x;
    while (this.parent.get(cur)! !== cur) cur = this.parent.get(cur)!;
    // Path compression
    let walk = x;
    while (this.parent.get(walk)! !== cur) {
      const next = this.parent.get(walk)!;
      this.parent.set(walk, cur);
      walk = next;
    }
    return cur;
  }
  union(a: T, b: T): void {
    const ra = this.find(a);
    const rb = this.find(b);
    if (ra === rb) return;
    // Anchor on the lexicographically smaller root for stability across runs.
    if (String(ra) < String(rb)) this.parent.set(rb, ra);
    else                          this.parent.set(ra, rb);
  }
}

// Test-only re-exports.
export const _testing = { UnionFind };
