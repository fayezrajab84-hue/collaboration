/**
 * Members + invitations API.
 *
 *   GET    /api/members                    — list current members (any auth user)
 *   PATCH  /api/members/:userId            — change a member's role (ADMIN+)
 *   DELETE /api/members/:userId            — remove a member from the org (ADMIN+)
 *
 *   GET    /api/members/invitations        — list pending invitations (ADMIN+)
 *   POST   /api/members/invitations        — invite by GitHub username (ADMIN+)
 *   DELETE /api/members/invitations/:id    — revoke a pending invitation (ADMIN+)
 *
 * Org scoping: all routes operate on req.orgId (set by requireRole middleware).
 * Single-org-per-user is the current data model — multi-org would add a
 * :slug parameter and a member-of-that-org check.
 *
 * Last-owner safety: the API blocks any operation that would leave the org
 * with zero OWNER members (demote, remove, role-change away from OWNER).
 */
import { Router } from "express";
import { z } from "zod";
import { Role } from "@prisma/client";
import prisma from "../../db.js";
import { getActiveMembership } from "../../services/activeOrgService.js";
import { requireAuth } from "../../middleware/requireAuth.js";
import { requireRole } from "../../middleware/requireRole.js";
import * as audit from "../../services/auditService.js";

const router = Router();

const VALID_ROLES = ["OWNER", "ADMIN", "SECURITY", "DEVELOPER", "VIEWER"] as const;
const roleSchema = z.enum(VALID_ROLES);

const inviteSchema = z.object({
  // GitHub username — case-insensitive, normalized to lowercase before storing.
  githubUsername: z
    .string()
    .min(1)
    .max(39)                      // GitHub's max
    .regex(/^[a-zA-Z0-9-]+$/, "letters, digits, hyphens only"),
  role: roleSchema.default("DEVELOPER"),
  /** Days until invitation expires. Default 14. */
  expiresInDays: z.number().int().min(1).max(90).default(14),
});

const patchRoleSchema = z.object({
  role: roleSchema,
});

// ── Helpers ──────────────────────────────────────────────────────────────────

async function ownerCount(orgId: string): Promise<number> {
  return prisma.organizationMember.count({
    where: { orgId, role: "OWNER" },
  });
}

// ── Member listing ───────────────────────────────────────────────────────────

router.get("/", requireAuth, async (req, res, next) => {
  try {
    const user = req.user as { id: string };
    const member = await getActiveMembership(req);
    if (!member) { res.json({ members: [] }); return; }

    const members = await prisma.organizationMember.findMany({
      where:   { orgId: member.orgId },
      include: { user: { select: { id: true, username: true, email: true, avatarUrl: true, createdAt: true } } },
      orderBy: [{ role: "asc" }, { user: { username: "asc" } }],
    });

    res.json({
      members: members.map((m) => ({
        userId:    m.user.id,
        username:  m.user.username,
        email:     m.user.email,
        avatarUrl: m.user.avatarUrl,
        role:      m.role,
        joinedAt:  m.user.createdAt,
        // Mark the current viewer's row so the UI can disable destructive actions on themselves.
        isYou:     m.user.id === user.id,
      })),
    });
  } catch (err) { next(err); }
});

// ── Member role change ───────────────────────────────────────────────────────

router.patch("/:userId", requireRole("ADMIN"), async (req, res, next) => {
  try {
    const actor   = req.user as { id: string };
    const target  = req.params["userId"]!;
    const body    = patchRoleSchema.parse(req.body);

    const existing = await prisma.organizationMember.findUnique({
      where: { userId_orgId: { userId: target, orgId: req.orgId! } },
    });
    if (!existing) { res.status(404).json({ error: "Member not found in this org" }); return; }

    // Last-owner guard: can't demote the only OWNER.
    if (existing.role === "OWNER" && body.role !== "OWNER") {
      const owners = await ownerCount(req.orgId!);
      if (owners <= 1) {
        res.status(409).json({ error: "Cannot demote the last OWNER. Promote another member first." });
        return;
      }
    }

    if (existing.role === body.role) {
      res.json({ ok: true, unchanged: true });
      return;
    }

    await prisma.organizationMember.update({
      where: { userId_orgId: { userId: target, orgId: req.orgId! } },
      data:  { role: body.role },
    });

    await audit.log({
      orgId: req.orgId!, userId: actor.id,
      action: "member.role_change", resourceType: "OrganizationMember", resourceId: target,
      metadata: { from: existing.role, to: body.role },
    });

    res.json({ ok: true });
  } catch (err) { next(err); }
});

// ── Member removal ───────────────────────────────────────────────────────────

router.delete("/:userId", requireRole("ADMIN"), async (req, res, next) => {
  try {
    const actor  = req.user as { id: string };
    const target = req.params["userId"]!;

    const existing = await prisma.organizationMember.findUnique({
      where: { userId_orgId: { userId: target, orgId: req.orgId! } },
    });
    if (!existing) { res.status(404).json({ error: "Member not found in this org" }); return; }

    // Last-owner guard: can't remove the only OWNER.
    if (existing.role === "OWNER") {
      const owners = await ownerCount(req.orgId!);
      if (owners <= 1) {
        res.status(409).json({ error: "Cannot remove the last OWNER. Promote another member first." });
        return;
      }
    }

    // Self-removal guard: blocking yourself out is too easy to do by accident.
    // ADMINs can remove themselves only via the explicit "Leave organization"
    // flow (not built yet) — for now it's blocked.
    if (target === actor.id) {
      res.status(409).json({ error: "You cannot remove yourself. An OWNER must do it." });
      return;
    }

    await prisma.organizationMember.delete({
      where: { userId_orgId: { userId: target, orgId: req.orgId! } },
    });

    await audit.log({
      orgId: req.orgId!, userId: actor.id,
      action: "member.remove", resourceType: "OrganizationMember", resourceId: target,
      metadata: { previousRole: existing.role },
    });

    res.json({ ok: true });
  } catch (err) { next(err); }
});

// ── Invitations: list ────────────────────────────────────────────────────────

router.get("/invitations", requireRole("ADMIN"), async (req, res, next) => {
  try {
    const rows = await prisma.invitation.findMany({
      where:   { orgId: req.orgId!, acceptedAt: null },
      orderBy: { createdAt: "desc" },
    });

    // Enrich with inviter username (no Prisma relation defined; cheap join).
    const inviterIds = Array.from(new Set(rows.map((r) => r.invitedById)));
    const inviters = inviterIds.length === 0
      ? []
      : await prisma.user.findMany({
          where:  { id: { in: inviterIds } },
          select: { id: true, username: true, avatarUrl: true },
        });
    const inviterById = new Map(inviters.map((u) => [u.id, u]));

    res.json({
      invitations: rows.map((r) => ({
        id:             r.id,
        githubUsername: r.githubUsername,
        role:           r.role,
        expiresAt:      r.expiresAt,
        createdAt:      r.createdAt,
        invitedBy:      inviterById.get(r.invitedById) ?? null,
      })),
    });
  } catch (err) { next(err); }
});

// ── Invitations: create ──────────────────────────────────────────────────────

router.post("/invitations", requireRole("ADMIN"), async (req, res, next) => {
  try {
    const actor    = req.user as { id: string };
    const body     = inviteSchema.parse(req.body);
    const username = body.githubUsername.toLowerCase();

    // Reject if a member with that username already exists in the org.
    const alreadyMember = await prisma.organizationMember.findFirst({
      where: { orgId: req.orgId!, user: { username: { equals: username, mode: "insensitive" } } },
      include: { user: { select: { username: true } } },
    });
    if (alreadyMember) {
      res.status(409).json({ error: `${alreadyMember.user.username} is already a member of this org` });
      return;
    }

    const expiresAt = new Date(Date.now() + body.expiresInDays * 24 * 60 * 60 * 1000);

    const row = await prisma.invitation.upsert({
      where:  { orgId_githubUsername: { orgId: req.orgId!, githubUsername: username } },
      // Refresh the invite (new role, new expiry) if one was already pending —
      // the unique constraint on (orgId, githubUsername) means we'd 500 otherwise.
      update: { role: body.role, expiresAt, invitedById: actor.id, acceptedAt: null, acceptedUserId: null },
      create: {
        orgId:          req.orgId!,
        githubUsername: username,
        role:           body.role,
        invitedById:    actor.id,
        expiresAt,
      },
    });

    // Inviting someone is an explicit "this org is shared, not my personal
    // sandbox" signal. Promote PERSONAL → TEAM so getActiveMembership's
    // type-based ordering can prefer this org over an invitee's auto-personal
    // sandbox. updateMany + where:{type:PERSONAL} is idempotent — already-TEAM
    // orgs are skipped silently.
    await prisma.organization.updateMany({
      where: { id: req.orgId!, type: "PERSONAL" },
      data:  { type: "TEAM" },
    });

    await audit.log({
      orgId: req.orgId!, userId: actor.id,
      action: "invitation.create", resourceType: "Invitation", resourceId: row.id,
      metadata: { githubUsername: username, role: body.role, expiresAt: expiresAt.toISOString() },
    });

    res.status(201).json({
      id:             row.id,
      githubUsername: row.githubUsername,
      role:           row.role,
      expiresAt:      row.expiresAt,
      createdAt:      row.createdAt,
    });
  } catch (err) { next(err); }
});

// ── Invitations: revoke ──────────────────────────────────────────────────────

router.delete("/invitations/:id", requireRole("ADMIN"), async (req, res, next) => {
  try {
    const actor = req.user as { id: string };
    const id    = req.params["id"]!;

    const existing = await prisma.invitation.findFirst({
      where: { id, orgId: req.orgId! },
    });
    if (!existing) { res.status(404).json({ error: "Invitation not found" }); return; }
    if (existing.acceptedAt) {
      res.status(409).json({ error: "Invitation already accepted; remove the member instead" });
      return;
    }

    await prisma.invitation.delete({ where: { id } });

    await audit.log({
      orgId: req.orgId!, userId: actor.id,
      action: "invitation.revoke", resourceType: "Invitation", resourceId: id,
      metadata: { githubUsername: existing.githubUsername, role: existing.role },
    });

    res.json({ ok: true });
  } catch (err) { next(err); }
});

export default router;
