/**
 * containerExposureBridge — Phase 27.5.x.
 *
 * Closes the "container CVE was never in the chain" gap that surfaced on
 * the DVWA dataset: even though the operator had declared the dvwa Domain
 * is served by the dvwa Container via Phase 27 Slice A's asset graph, the
 * existing 4 bridges never linked the two. cveBridge needed a matching
 * CVE on a different target type (DVWA's source-code SAST findings have
 * no CVEs); routeBridge is source↔url only; portBridge needs port info
 * in the pentest evidence (most DAST/PENTEST findings are HTTP-level);
 * secretBridge needs a shared hash. None fired.
 *
 * The semantic link this bridge encodes:
 *   "this container has a vulnerability AND it serves this domain →
 *    a DAST/PENTEST finding on the domain extends the chain into the
 *    container's blast-radius CVEs."
 *
 * Severity gate (Phase 27.5.x correction): we only fire when BOTH sides
 * are HIGH or CRITICAL. The first version fired on every (container,
 * web) pair regardless of severity, producing N×M edges per linked
 * (container, domain) — on a real DVWA dataset that exploded into a
 * 142-node mega-chain. Restricting to HIGH+ on both sides keeps the
 * chain meaningful: low-severity glibc CVEs no longer drag every web
 * info-leak alert into the chain.
 *
 * Confidence policy (after the severity gate fires):
 *   - LIKELY when container side is CRITICAL (these tend to be RCE in
 *     listening services — Apache, nginx, the JVM, libssl — where web-
 *     driven exploitation is plausible).
 *   - POSSIBLE when container side is HIGH (still real but not always
 *     web-reachable; runtime reachability is a Phase 14.5 follow-up).
 *
 * Symmetry: bridge is fully symmetric — match(a, b) === match(b, a) for
 * any pair. The engine deduplicates pairs anyway but symmetry is a hard
 * contract requirement (per bridgeInterface.ts).
 */
import type { Finding } from "@prisma/client";
import type { Bridge, BridgeMatch, BridgeContext } from "./bridgeInterface.js";

const HIGH_OR_CRITICAL = new Set(["HIGH", "CRITICAL"]);
const CRITICAL = new Set(["CRITICAL"]);

export const containerExposureBridge: Bridge = {
  id: "container_exposure",
  match(a: Finding, b: Finding, ctx: BridgeContext): BridgeMatch | null {
    if (a.orgId !== b.orgId) return null;       // safety

    // Need exactly one CONTAINER-target finding and one URL-bearing finding
    const containerSide = isContainerFinding(a) ? a : isContainerFinding(b) ? b : null;
    const webSide       = isWebFinding(a)       ? a : isWebFinding(b)       ? b : null;
    if (!containerSide || !webSide || containerSide === webSide) return null;
    if (!containerSide.containerId) return null;
    if (!webSide.domainId)          return null;

    // Severity gate — both sides must be HIGH or CRITICAL. Without this
    // every container CVE × every web finding produces an edge (4640
    // edges on the DVWA dataset → one 142-node mega-chain). The gate
    // keeps focus on chains that actually matter.
    if (!HIGH_OR_CRITICAL.has(containerSide.severity)) return null;
    if (!HIGH_OR_CRITICAL.has(webSide.severity))       return null;

    // Operator-declared linkage check: the container must list this domain
    // (or symmetrically the domain must list this container). Without the
    // graph link there's no real "this container serves this domain" claim.
    const container = ctx.containerById.get(containerSide.containerId);
    if (!container) return null;
    const directLink = container.deployedAtDomainIds.includes(webSide.domainId);
    let symmetricLink = false;
    if (!directLink) {
      const dom = ctx.domainById.get(webSide.domainId);
      symmetricLink = Boolean(dom?.servesContainerIds.includes(containerSide.containerId));
    }
    if (!directLink && !symmetricLink) return null;

    // Confidence — LIKELY only for container CRITICAL (true RCE-class).
    // HIGH stays POSSIBLE because it may still be a non-web-reachable
    // privilege escalation in a sidecar tool.
    const confidence: BridgeMatch["confidence"] = CRITICAL.has(containerSide.severity)
      ? "LIKELY"
      : "POSSIBLE";

    // Build a compact reason string so the operator can read the chain
    // edge tooltip without needing to expand the node detail. Show the
    // CVE when present (most container findings have one); fall back to
    // the package name; final fallback to the finding title.
    const containerLabel =
      containerSide.cveId
        ?? (containerSide.packageName
              ? (containerSide.packageVersion
                  ? `${containerSide.packageName}@${containerSide.packageVersion}`
                  : containerSide.packageName)
              : containerSide.title);

    return {
      bridgeType: "container_exposure",
      confidence,
      reason:
        `Container ${container.imageRef} (${containerLabel}) serves the domain hit by this DAST/PENTEST finding`,
    };
  },
};

function isContainerFinding(f: Finding): boolean {
  // Phase 28 Slice C iteration: skip RUNTIME findings here. RUNTIME alerts
  // ALSO carry targetType=CONTAINER + containerId (so runtimeBridge can
  // resolve them), but they're not container *CVEs* — they're real-world
  // runtime activity. Letting containerExposureBridge fire on RUNTIME
  // findings produces duplicate edges (~16 extra per RUNTIME finding on
  // a real DVWA dataset) since runtimeBridge already covers the same
  // RUNTIME ↔ DAST/PENTEST link with better semantics + reason text.
  // The CONTAINER scanType filter keeps this bridge focused on what its
  // name says: container-image vulnerability findings only.
  return f.targetType === "CONTAINER"
    && f.scanType    === "CONTAINER"
    && Boolean(f.containerId);
}

function isWebFinding(f: Finding): boolean {
  return (f.scanType === "DAST" || f.scanType === "PENTEST" || f.scanType === "PENTEST_FULL")
    && Boolean(f.domainId);
}
