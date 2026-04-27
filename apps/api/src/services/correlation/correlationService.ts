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
];

export interface CorrelationRunSummary {
  orgId:              string;
  findingsConsidered: number;
  bridgeMatches:      number;
  groupsFormed:       number;
  durationMs:         number;
}

/**
 * Full org sweep — load all OPEN findings, run every bridge across every pair,
 * union-find into groups, persist `correlationGroupId` + `correlationEdges`
 * + `correlationComputedAt` on each finding.
 *
 * Returns a summary the caller can log. Does NOT delete prior correlation
 * data unless the engine has a fresh decision for that finding (so a
 * narrowly-failing partial sweep can't blow away an entire org's correlations).
 */
export async function runCorrelationForOrg(orgId: string): Promise<CorrelationRunSummary> {
  const started = Date.now();

  const findings = await prisma.finding.findMany({
    where: {
      orgId,
      status: { not: "FALSE_POSITIVE" },  // FPs stay out of the chain
    },
    // The bridges only need a subset of fields — but Prisma `select` makes
    // the query more brittle. We accept the wider shape for v1.
  });

  if (findings.length === 0) {
    return { orgId, findingsConsidered: 0, bridgeMatches: 0, groupsFormed: 0, durationMs: Date.now() - started };
  }

  const ctx = await buildContext(orgId);

  // ── Stage 1: bridge sweep ─────────────────────────────────────────────
  // Edges as adjacency lists keyed by finding id. Each entry holds the
  // serialised match record so we don't recompute when persisting.
  const edges = new Map<string, PersistedEdge[]>();
  const uf    = new UnionFind<string>();

  let bridgeMatches = 0;

  for (let i = 0; i < findings.length; i++) {
    const a = findings[i];
    if (!a) continue;
    uf.find(a.id);    // ensure self in the structure
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
        // Multiple bridge matches between the same pair are allowed —
        // the graph UI shows the strongest as the edge label. Don't
        // break here; future scoring will use the full edge set.
      }
    }
  }

  // ── Stage 2: union-find → groupId ─────────────────────────────────────
  // Group root id used as the chain id (stable as long as the lowest
  // member id stays present; when it disappears via deletion, the group
  // re-keys on next sweep — acceptable churn).
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
  const [containers, domains] = await Promise.all([
    prisma.container.findMany({
      where:  { orgId },
      select: { id: true, imageRef: true, sourceRepositoryId: true, deployedAtDomainIds: true },
    }),
    prisma.domain.findMany({
      where:  { orgId },
      select: { id: true, domain: true, servesContainerIds: true },
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

  return { containerById, containersByImageRef, domainById };
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
