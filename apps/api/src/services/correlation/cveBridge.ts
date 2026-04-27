/**
 * cveBridge — Phase 27 Slice B.
 *
 * Links findings that reference the same CVE across different target types.
 * The most common chain we want to see: a repo's SCA finding (CVE-X in
 * package.json) AND a container's SCA finding (same CVE-X in the image's
 * /app/node_modules) — that's the same vulnerability traveling from source
 * to runtime artifact, and it's the simplest possible attack-chain link.
 *
 * Strong signal — same `cveId` + cross-target = LIKELY confidence by default,
 * CONFIRMED when both findings are also on linked assets (Phase 27 Slice A
 * declared the repo builds this container's image).
 */
import type { Finding } from "@prisma/client";
import type { Bridge, BridgeMatch, BridgeContext } from "./bridgeInterface.js";

export const cveBridge: Bridge = {
  id: "cve",
  match(a: Finding, b: Finding, ctx: BridgeContext): BridgeMatch | null {
    if (a.orgId !== b.orgId) return null;          // safety
    if (!a.cveId || !b.cveId) return null;         // need a CVE on both sides
    if (a.cveId !== b.cveId) return null;          // must be the same CVE

    // Most useful when the two findings hit DIFFERENT target types — same
    // CVE on the same target is just deduplication noise.
    if (a.targetType === b.targetType && sameTargetId(a, b)) return null;

    const confidence = isAssetLinked(a, b, ctx) ? "CONFIRMED" : "LIKELY";

    return {
      bridgeType: "cve",
      confidence,
      reason: `Same CVE (${a.cveId}) detected on ${a.targetType.toLowerCase()} + ${b.targetType.toLowerCase()}`,
    };
  },
};

function sameTargetId(a: Finding, b: Finding): boolean {
  if (a.targetType === "REPOSITORY" && b.targetType === "REPOSITORY") return a.repositoryId === b.repositoryId;
  if (a.targetType === "CONTAINER"  && b.targetType === "CONTAINER")  return a.containerId  === b.containerId;
  if (a.targetType === "DOMAIN"     && b.targetType === "DOMAIN")     return a.domainId     === b.domainId;
  return false;
}

/**
 * Returns true when the two findings sit on assets the operator has linked
 * via Phase 27 Slice A. That makes the CVE match much higher confidence —
 * we know not only "same CVE" but "same software flowing across stages".
 */
function isAssetLinked(a: Finding, b: Finding, ctx: BridgeContext): boolean {
  // Repo↔Container link
  if (a.repositoryId && b.containerId) return repoBuildsContainer(a.repositoryId, b.containerId, ctx);
  if (b.repositoryId && a.containerId) return repoBuildsContainer(b.repositoryId, a.containerId, ctx);
  return false;
}

function repoBuildsContainer(repoId: string, containerId: string, ctx: BridgeContext): boolean {
  const c = ctx.containerById.get(containerId);
  return Boolean(c && c.sourceRepositoryId === repoId);
}
