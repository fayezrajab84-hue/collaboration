/**
 * runtimeBridge — Phase 28 Slice C.
 *
 * Closes the architectural gap that Phase 28 Slice A (wazuhIngestService)
 * left open: RUNTIME findings (Wazuh alerts) existed as a tier in the
 * findings table but never entered correlation chains.
 *
 * Semantic link encoded:
 *   "this Wazuh agent monitors a Container we know about, AND the
 *    runtime alert is HIGH-severity, AND the candidate other finding is
 *    ALSO HIGH-severity → bridge them into the same chain."
 *
 * SEVERITY GATE — both sides must be HIGH or CRITICAL.
 * ────────────────────────────────────────────────────
 * Without this gate, a single Wazuh runtime alert on a monitored container
 * forms an edge with EVERY other finding on the same container — which on
 * a real DVWA dataset (80 Trivy LOW/MEDIUM CVEs + 60 DAST/PENTEST findings
 * across all severities) collapses ALL prior chains into one mega-chain
 * via union-find amplification. Operators lose the focused chains the
 * existing bridges built; the engine becomes useless.
 *
 * This is the SAME amplification bug that hit containerExposureBridge in
 * Phase 27.5.x; the fix is the same: HIGH+ on both sides only.
 *
 * Indirect (domain-served-by-container) match also gated:
 * ───────────────────────────────────────────────────────
 * The "RUNTIME alert ↔ DAST finding on the served domain" path is even
 * more amplifying than the direct path (DVWA has 60 DAST findings on the
 * served domain). Same gate applies — only HIGH+ on both sides bridges
 * via the indirect path.
 *
 * Linkage path (kept inside BridgeContext so match() stays pure):
 *
 *   Finding.scanType === "RUNTIME" + severity HIGH/CRITICAL
 *     └── rawOutput.agent_id (from Wazuh alert)
 *           └── ctx.containerIdByWazuhAgentId.get(agent_id)
 *                 └── Container.id  ←  matches Finding.containerId, OR
 *                 └── ctx.containerById.get(cid).deployedAtDomainIds
 *                       └── matches Finding.domainId on the other side
 *
 * Confidence policy (after the severity gate fires):
 *   - LIKELY for direct container match (same container is a strong link)
 *   - POSSIBLE for indirect domain match (domain served by container is
 *     weaker — the alert is about runtime activity, the DAST finding is
 *     about HTTP-level vuln; runtimeBridge cannot prove the activity
 *     IS the exploitation of the HTTP vuln)
 *
 * What this bridge does NOT do (deferred to Phase 28.5+):
 *   - Bridge by file path (RUNTIME alert on /var/www/index.php ↔ SAST
 *     finding on index.php) — needs path normalization
 *   - Bridge by network endpoint (RUNTIME outbound C2 ↔ egress allow-list)
 *     — that's egressC2Bridge in Phase 28.6
 *   - Semantic-rule matching (SSH brute-force ↔ sshd-class container CVE)
 *     — needs a curated rule-to-component taxonomy
 *
 * Symmetry: bridge is fully symmetric — argument order doesn't change the
 * result. Required by the engine's pair-deduplication contract.
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

    // ── Severity gate ────────────────────────────────────────────────────
    // Both sides must be HIGH or CRITICAL. Without this gate a single
    // RUNTIME alert collapses every CONTAINER/DAST/PENTEST finding on the
    // monitored container into one mega-chain via union-find amplification
    // (~140 findings on a real DVWA dataset). The gate keeps the chain
    // focused on findings that actually compound risk together.
    if (!HIGH_OR_CRITICAL.has(runtimeSide.severity)) return null;
    if (!HIGH_OR_CRITICAL.has(otherSide.severity))   return null;

    // Resolve the container the runtime alert is about. Two ways:
    //   1. Direct: Finding.containerId is set (newer ingestions after
    //      wazuhIngestService.ts learns to set it).
    //   2. Via WorkloadAgent.linkedContainerId — for legacy RUNTIME rows
    //      that were ingested before the operator linked the agent.
    const containerId = resolveContainerId(runtimeSide, ctx);
    if (!containerId) return null;
    const container = ctx.containerById.get(containerId);
    if (!container) return null;

    // Direct asset match — same Container. Strongest link → LIKELY.
    if (otherSide.containerId === containerId) {
      return buildMatch(runtimeSide, container.imageRef, "container");
    }

    // Indirect asset match — Domain served by the container. Weaker link
    // (HTTP-level finding may be unrelated to the runtime activity) →
    // POSSIBLE confidence.
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
  // Direct container match → LIKELY (strong, same asset). Indirect via
  // domain → POSSIBLE (the runtime alert may be unrelated to the web vuln).
  const confidence: BridgeMatch["confidence"] = via === "container"
    ? "LIKELY"
    : "POSSIBLE";
  const ruleLabel = runtime.ruleId ? `Wazuh rule ${runtime.ruleId}` : "Wazuh runtime alert";
  const linkedVia = via === "container"
    ? "the same container"
    : `the domain served by container ${imageRef}`;
  return {
    bridgeType: "runtime",
    confidence,
    reason: `${ruleLabel} fired on ${linkedVia}`,
  };
}
