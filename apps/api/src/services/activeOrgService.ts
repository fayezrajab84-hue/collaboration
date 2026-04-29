/**
 * activeOrgService — single source of truth for "which org is the user
 * currently looking at?"
 *
 * Resolution order:
 *   1. session.activeOrgId — set by `POST /auth/org/switch` when the user
 *      picks an org in the sidebar dropdown. Cleared if it points to a
 *      stale membership (org deleted, user removed from org).
 *   2. Deterministic fallback — TEAM orgs over PERSONAL (so an invited
 *      org wins over the user's auto-created personal sandbox), then
 *      oldest membership first.
 *
 * Returns null if the user has no memberships at all, or if there's no
 * authenticated user on the request.
 *
 * Replaces the ad-hoc `prisma.organizationMember.findFirst({ where: { userId } })`
 * pattern that previously returned a non-deterministic membership and
 * surfaced as "empty data after sign-in" for users who belonged to
 * multiple orgs (the personal sandbox usually won the race).
 */
import type { Request } from "express";
import prisma from "../db.js";

// Allow `req.session.activeOrgId` — set by `POST /auth/org/switch`.
declare module "express-session" {
  interface SessionData {
    activeOrgId?: string;
  }
}

export type ActiveMembership = NonNullable<
  Awaited<ReturnType<typeof getActiveMembership>>
>;

export async function getActiveMembership(req: Request) {
  const user = req.user as { id: string } | undefined;
  if (!user?.id) return null;

  // Phase A4 — Bearer-token auth pins the active org to the token's
  // own orgId (tokens are minted scoped to one org and cannot escalate
  // to siblings even if the creator is a member of multiple). Session
  // activeOrgId is ignored when a token is in play — automation must
  // be deterministic; "which org does my CI scan target?" cannot
  // depend on whatever the operator last clicked in the sidebar.
  const tokenOrgId = req.apiToken?.orgId;
  if (tokenOrgId) {
    return prisma.organizationMember.findUnique({
      where: { userId_orgId: { userId: user.id, orgId: tokenOrgId } },
    });
  }

  const sessionOrgId = req.session.activeOrgId;
  if (sessionOrgId) {
    const m = await prisma.organizationMember.findUnique({
      where: { userId_orgId: { userId: user.id, orgId: sessionOrgId } },
    });
    if (m) return m;
    // Session points at a membership the user no longer has — drop it so
    // the fallback runs and the next /auth/org/switch can persist a fresh
    // choice.
    delete req.session.activeOrgId;
  }

  return prisma.organizationMember.findFirst({
    where: { userId: user.id },
    // OrgType enum is { PERSONAL, TEAM } — Postgres orders alphabetically,
    // so `desc` puts TEAM ahead of PERSONAL. Tiebreaker is the org's own
    // creation time (OrganizationMember has no createdAt column) — oldest
    // org wins so the result is stable across requests.
    orderBy: [{ org: { type: "desc" } }, { org: { createdAt: "asc" } }],
  });
}
