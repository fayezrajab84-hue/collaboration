/**
 * portBridge — Phase 27 Slice B.
 *
 * Links a PENTEST finding that mentions an exposed port (nmap discovery, port
 * scan results) to a Container that exposes the same port. Powers the chain:
 * "discovered open port → on this container → which has CVE on the listening
 * service → which is reachable from public domain."
 *
 * v1 reads the listening port from the finding's evidence/rawOutput; container
 * EXPOSE port enumeration is a future enhancement (image config inspect — not
 * cheap to do at correlation time, so the operator-declared
 * `exposedPorts: number[]` field is the natural place to add it later).
 */
import type { Finding } from "@prisma/client";
import type { Bridge, BridgeMatch, BridgeContext } from "./bridgeInterface.js";

const PORT_KEYS = ["port", "dst_port", "destination_port", "listen_port"];

export const portBridge: Bridge = {
  id: "port",
  match(a: Finding, b: Finding, ctx: BridgeContext): BridgeMatch | null {
    if (a.orgId !== b.orgId) return null;

    // Need one PENTEST-shaped finding with a port and one CONTAINER finding
    // on a container in the same org. Order doesn't matter (symmetric).
    const portSide = isPentestFinding(a) ? a : isPentestFinding(b) ? b : null;
    const cntrSide = isContainerFinding(a) ? a : isContainerFinding(b) ? b : null;
    if (!portSide || !cntrSide || portSide === cntrSide) return null;

    const port = extractPort(portSide);
    if (port == null) return null;

    if (!cntrSide.containerId) return null;
    const container = ctx.containerById.get(cntrSide.containerId);
    if (!container) return null;

    // The pentest finding's domain (if known) must overlap the container's
    // serving domains for this to be a real chain. If we can't verify the
    // overlap, we still emit a POSSIBLE link — the operator can confirm.
    const overlap = portSide.domainId
      ? container.deployedAtDomainIds.includes(portSide.domainId)
      : false;

    return {
      bridgeType: "port",
      confidence: overlap ? "LIKELY" : "POSSIBLE",
      reason: overlap
        ? `Pentest hit port ${port} on a domain served by ${container.imageRef}`
        : `Pentest hit port ${port} on container ${container.imageRef}`,
    };
  },
};

function isPentestFinding(f: Finding): boolean {
  return f.scanType === "PENTEST" || f.scanType === "PENTEST_FULL";
}

function isContainerFinding(f: Finding): boolean {
  return f.targetType === "CONTAINER" && Boolean(f.containerId);
}

function extractPort(f: Finding): number | null {
  const ev  = (f.evidence  ?? {}) as Record<string, unknown>;
  const raw = (f.rawOutput ?? {}) as Record<string, unknown>;
  for (const k of PORT_KEYS) {
    const v = ev[k] ?? raw[k];
    if (typeof v === "number" && Number.isFinite(v)) return v;
    if (typeof v === "string" && /^\d+$/.test(v))    return Number(v);
  }
  return null;
}
