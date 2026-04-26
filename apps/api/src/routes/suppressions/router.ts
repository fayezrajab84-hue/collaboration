/**
 * Suppressions (accepted-risk) routes.
 * Create/revoke require SECURITY+. Read allowed for any authenticated member.
 */
import { Router } from "express";
import { z } from "zod";
import prisma from "../../db.js";
import { getActiveMembership } from "../../services/activeOrgService.js";
import { requireAuth } from "../../middleware/requireAuth.js";
import { requireRole } from "../../middleware/requireRole.js";
import * as suppressions from "../../services/suppressionService.js";
import * as audit from "../../services/auditService.js";

const router = Router();

const createSchema = z.object({
  fingerprint: z.string().min(1),
  reason:      z.string().min(3).max(2000),
  expiresAt:   z.string().datetime().optional().nullable(),
});

// List suppressions
router.get("/", requireAuth, async (req, res, next) => {
  try {
    const user   = req.user as { id: string };
    const member = await getActiveMembership(req);
    if (!member) { res.json([]); return; }
    const active = req.query["active"] === "true";
    const rows   = await suppressions.list(member.orgId, { active });
    res.json(rows);
  } catch (err) { next(err); }
});

// Create suppression — SECURITY+
router.post("/", requireRole("SECURITY"), async (req, res, next) => {
  try {
    const body = createSchema.parse(req.body);
    const user = req.user as { id: string };

    // Verify the fingerprint belongs to a finding in this org
    const finding = await prisma.finding.findFirst({
      where: { fingerprint: body.fingerprint, orgId: req.orgId! },
      select: { id: true, title: true, severity: true },
    });
    if (!finding) { res.status(404).json({ error: "Finding not found for fingerprint" }); return; }

    const row = await suppressions.create({
      orgId:        req.orgId!,
      fingerprint:  body.fingerprint,
      reason:       body.reason,
      expiresAt:    body.expiresAt ? new Date(body.expiresAt) : null,
      approvedById: user.id,
    });

    await audit.log({
      orgId:        req.orgId!,
      userId:       user.id,
      action:       "suppression.create",
      resourceType: "Suppression",
      resourceId:   row.id,
      metadata:     { fingerprint: body.fingerprint, reason: body.reason, findingTitle: finding.title },
    });

    res.status(201).json(row);
  } catch (err) { next(err); }
});

// Revoke suppression — SECURITY+
router.delete("/:id", requireRole("SECURITY"), async (req, res, next) => {
  try {
    const user = req.user as { id: string };
    const id   = req.params["id"]!;
    const result = await suppressions.revoke(id, req.orgId!, user.id);
    if (result.count === 0) { res.status(404).json({ error: "Suppression not found or already revoked" }); return; }
    await audit.log({
      orgId:        req.orgId!,
      userId:       user.id,
      action:       "suppression.revoke",
      resourceType: "Suppression",
      resourceId:   id,
    });
    res.json({ ok: true });
  } catch (err) { next(err); }
});

export default router;
