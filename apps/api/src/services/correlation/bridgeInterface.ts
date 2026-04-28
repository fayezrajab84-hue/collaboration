/**
 * Bridge interface — Phase 27 Slice B.
 *
 * A Bridge inspects two `Finding` rows (along with their target assets) and
 * decides whether they should be linked into the same attack-path chain. The
 * correlation engine runs every registered bridge over every pair of findings
 * in an org; when a bridge returns a non-null match, both findings get the
 * same `correlationGroupId` and an edge is recorded between them.
 *
 * The interface is deliberately tiny so future phases can add new bridges
 * without changing the engine. Phase 28 Slice C, Phase 28.5, Phase 28.6, and
 * Phase 29 all add bridges via this same shape — the architecture compounds.
 *
 * Contract:
 *   - `match` MUST be a pure function — no side effects, no I/O. The engine
 *     calls it potentially millions of times; everything it needs is in
 *     the `BridgeContext` or on the Finding rows themselves.
 *   - `match` MUST return null when the two findings are in different orgs
 *     (defence-in-depth — engine also checks, but bridges are the last gate).
 *   - `match` MUST be symmetric: match(a, b) === match(b, a) for the same
 *     bridge type (engine deduplicates pairs by [min(id), max(id)] before
 *     calling, but bridges that aren't symmetric will produce confusing
 *     edge directions in the graph UI).
 */
import type { Finding } from "@prisma/client";

/** Confidence bucket for the bridge match — feeds into path scoring. */
export type BridgeConfidence = "POSSIBLE" | "LIKELY" | "CONFIRMED";

/** What kind of bridge produced this edge — surfaces in the graph UI tooltip. */
export type BridgeType =
  | "cve"                // Same CVE on a repo SCA finding + a container SCA finding
  | "route"              // DAST/PENTEST URL path matches a SAST source file path
  | "port"               // PENTEST nmap-discovered port matches a container EXPOSE rule
  | "secret"             // Secret hash matches an env var hash in a container layer
  | "container_exposure" // CONTAINER finding ↔ DAST/PENTEST on a domain that container serves
                         // (closes the gap "container CVE was never in the chain even though
                         //  the operator declared the asset linkage")
  // Phase 28.x reserved tags so the type stays exhaustive across slices:
  | "runtime"
  | "waf_bypass"
  | "db_access"
  | "egress_c2"
  | "dns_resolution"
  | "c2_beacon"
  | "agent_tool"
  | "llm_attack"
  | "cloud_east_west"
  | "flow_data_access";

export interface BridgeMatch {
  bridgeType: BridgeType;
  confidence: BridgeConfidence;
  /**
   * Short human-readable reason — surfaces on the edge tooltip in the
   * /attack-paths graph UI. Keep <120 chars; this is the operator-facing
   * answer to "why does the engine think these two findings are linked?".
   */
  reason: string;
}

/**
 * Optional per-org context the engine assembles ONCE per sweep and passes
 * to every bridge call. Keeps bridges stateless while letting them consult
 * cheap precomputed lookups (e.g. an imageRef → containerId map).
 */
export interface BridgeContext {
  /**
   * For each Container row in the org, the operator-declared linkage from
   * Phase 27 Slice A — used by route/port bridges that need to know which
   * domain a container serves or which repo built it.
   */
  containerById: Map<string, ContainerSummary>;
  /** imageRef → Container rows producing it (>1 if duplicate refs across rows). */
  containersByImageRef: Map<string, ContainerSummary[]>;
  /** Domain id → operator-declared serving containers + the domain name. */
  domainById: Map<string, DomainSummary>;
  /**
   * Wazuh agent ID → Container ID. Populated from
   * `WorkloadAgent.linkedContainerId` so runtimeBridge can resolve a RUNTIME
   * Finding's `rawOutput.agent_id` to the Container the agent monitors —
   * even when the Finding row itself was persisted before the operator
   * linked the agent to a Container. Empty when no agents are enrolled or
   * no operator has set `linkedContainerId`.
   */
  containerIdByWazuhAgentId: Map<string, string>;
}

export interface ContainerSummary {
  id:                     string;
  imageRef:               string;
  sourceRepositoryId:     string | null;
  deployedAtDomainIds:    string[];
}

export interface DomainSummary {
  id:                  string;
  domain:              string;
  servesContainerIds:  string[];
}

export interface Bridge {
  /** Stable identifier — used in metrics + tests. Prefer kebab-case. */
  id: string;
  /** Returns a match or null. MUST be pure + symmetric. */
  match(a: Finding, b: Finding, ctx: BridgeContext): BridgeMatch | null;
}

/**
 * The persisted edge shape on Finding.correlationEdges. We don't model this
 * in Prisma — JSON keeps it cheap to update + query — but the shape is
 * stable so the UI can lean on it.
 */
export interface PersistedEdge {
  toFindingId: string;
  bridgeType:  BridgeType;
  confidence:  BridgeConfidence;
  reason:      string;
}
