/**
 * runtimeBridge — Phase 28 Slice C.
 *
 * Closes the architectural gap that Phase 28 Slice A (wazuhIngestService)
 * left open: RUNTIME findings (Wazuh alerts) existed as a tier in the
 * findings table but never entered correlation chains because no bridge
 * knew how to link them to other tiers.
 *
 * The semantic link this bridge encodes:
 *   "this Wazuh agent monitors a Container we know about → a runtime
 *    alert from that agent extends the chain into every other finding
 *    on the same Container (CONTAINER scan CVEs, DAST/PENTEST findings
 *    on the Domain that Container serves)."
 *
 * Linkage path (kept inside the BridgeContext so match() stays pure):
 *
 *   Finding.scanType === "RUNTIME"
 *     └── rawOutput.agent_id (from Wazuh alert)
 *           └── ctx.containerIdByWazuhAgentId.get(agent_id)
 *                 └── Container.id  ←  matches Finding.containerId on the
 *                                       other side, OR
 *                 └── ctx.containerById.get(containerId).deployedAtDomainIds
 *                       └── matches Finding.domainId on the other side
 *
 * The bridge is symmetric: match(a, b) === match(b, a) — engine
 * deduplicates pairs anyway, but symmetry is a hard contract requirement
 * (per bridgeInterface.ts).
 *
 * Confidence policy:
 *   - LIKELY when the runtime finding's severity is HIGH or CRITICAL.
 *     A high-level Wazuh rule (level ≥ 10 → HIGH/CRITICAL) firing on a
 *     monitored container is a strong signal that the activity is real,
 *     and any related vulnerability finding gains weight from the chain.
 *   - POSSIBLE when severity is MEDIUM/LOW. We still bridge — operators
 *     want to see the chain — but downrank to keep noisy hourly-buckets
 *     of low-level alerts from inflating chain scores.
 *
 * What this bridge does NOT do (deferred to Phase 28.5+):
 *   - Bridge by file path (RUNTIME alert on /var/www/index.php ↔ SAST
 *     finding on index.php). That needs path normalization across
 *     container layers + repo roots and is its own bridge plugin.
 *   - Bridge by network endpoint (RUNTIME alert on outbound C2 IP ↔
 *     egress allow-list). That's egressC2Bridge in the Phase 28.6 scope.
 *   - Bridge by process name (java exec ↔ tomcat:9 image). Process
 *     name → image mapping is fuzzy; would need a curated lookup.
 *
 * Symmetry: bridge is fully symmetric. The "isRuntimeFinding" check
 * picks the runtime side regardless of argument order; the resolved
 * containerId is compared against both `a` and `b`.
 */
import type { Finding } from "@prisma/client";
import type { Bridge, BridgeMatch, BridgeContext } from "./bridgeInterface.js";

const HIGH_OR_CRITICAL = new Set(["HIGH", "CRITICAL"]);

export const runtimeBridge: Bridge = {
  id: "runtime",
  match(a: Finding, b: Finding, ctx: BridgeContext): BridgeMatch | null {
    if (a.orgId !== b.orgId) return null;       // safety

    // Need exactly one RUNTIME finding and one non-RUNTIME finding.
    // Two RUNTIME findings on the same container would already be merged
    // by the wazuhIngestService hourly-bucket fingerprint logic — so a
    // runtime↔runtime bridge would just be noise.
    const runtimeSide = isRuntimeFinding(a) ? a : isRuntimeFinding(b) ? b : null;
    const otherSide   = (runtimeSide === a) ? b : (runtimeSide === b) ? a : null;
    if (!runtimeSide || !otherSide) return null;
    if (isRuntimeFinding(otherSide)) return null;

    // Resolve the container the runtime alert is about. Two ways:
    //   1. Direct: Finding.containerId is set (newer ingestions after
    //      wazuhIngestService.ts learns to set it).
    //   2. Via WorkloadAgent.linkedContainerId — for legacy RUNTIME rows
    //      that were ingested before the operator linked the agent.
    const containerId = resolveContainerId(runtimeSide, ctx);
    if (!containerId) return null;
    const container = ctx.containerById.get(containerId);
    if (!container) return null;

    // Direct asset match — same Container.
    if (otherSide.containerId === containerId) {
      return buildMatch(runtimeSide, container.imageRef, "container");
    }

    // Indirect asset match — Domain that the container serves.
    if (otherSide.domainId && container.deployedAtDomainIds.includes(otherSide.domainId)) {
      return buildMatch(runtimeSide, container.imageRef, "domain");
    }

    return null;
  },
};

function isRuntimeFinding(f: Finding): boolean {
  return f.scanType === "RUNTIME";
}

function resolveContainerId(runtime: Finding, ctx: BridgeContext): string | null {
  if (runtime.containerId) return runtime.containerId;
  // Fall back to the WorkloadAgent.linkedContainerId map. Pull agent_id
  // from rawOutput where wazuhIngestService stored it.
  const raw = runtime.rawOutput as { agent_id?: unknown } | null;
  const agentId = raw && typeof raw.agent_id === "string" ? raw.agent_id : null;
  if (!agentId) return null;
  return ctx.containerIdByWazuhAgentId.get(agentId) ?? null;
}

function buildMatch(
  runtime: Finding,
  imageRef: string,
  via: "container" | "domain",
): BridgeMatch {
  const confidence: BridgeMatch["confidence"] = HIGH_OR_CRITICAL.has(runtime.severity)
    ? "LIKELY"
    : "POSSIBLE";
  // Compact reason — the operator reads this on the chain edge tooltip.
  // Surface the Wazuh rule label so the operator knows what kind of
  // runtime activity triggered the link.
  const ruleLabel = runtime.ruleId ? `Wazuh rule ${runtime.ruleId}` : "Wazuh runtime alert";
  const linkedVia = via === "container" ? "the same container" : `the domain served by container ${imageRef}`;
  return {
    bridgeType: "runtime",
    confidence,
    reason: `${ruleLabel} fired on ${linkedVia}`,
  };
}
