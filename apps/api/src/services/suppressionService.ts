/**
 * Suppression service — hides accepted-risk findings from default queries.
 *
 * A suppression targets a Finding.fingerprint, so it survives re-scans (the
 * fingerprint is stable across runs). Suppressions can have an expiry after
 * which findings reappear automatically.
 */
import prisma from "../db.js";

/** Returns the set of fingerprints that are currently suppressed (not expired, not revoked). */
export async function activeSuppressedFingerprints(orgId: string): Promise<Set<string>> {
  const now  = new Date();
  const rows = await prisma.suppression.findMany({
    where: {
      orgId,
      revokedAt: null,
      OR: [{ expiresAt: null }, { expiresAt: { gt: now } }],
    },
    select: { fingerprint: true },
  });
  return new Set(rows.map((r) => r.fingerprint));
}

export async function create(input: {
  orgId:        string;
  fingerprint:  string;
  reason:       string;
  expiresAt?:   Date | null;
  approvedById: string;
}) {
  return prisma.suppression.create({
    data: {
      orgId:        input.orgId,
      fingerprint:  input.fingerprint,
      reason:       input.reason,
      expiresAt:    input.expiresAt ?? null,
      approvedById: input.approvedById,
    },
  });
}

export async function revoke(id: string, orgId: string, userId: string) {
  return prisma.suppression.updateMany({
    where: { id, orgId, revokedAt: null },
    data:  { revokedAt: new Date(), revokedById: userId },
  });
}

export async function list(orgId: string, opts: { active?: boolean } = {}) {
  const now = new Date();
  const where: Record<string, unknown> = { orgId };
  if (opts.active) {
    where["revokedAt"] = null;
    where["OR"]        = [{ expiresAt: null }, { expiresAt: { gt: now } }];
  }
  return prisma.suppression.findMany({
    where,
    orderBy: { createdAt: "desc" },
  });
}
