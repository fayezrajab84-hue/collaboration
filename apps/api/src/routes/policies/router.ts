/**
 * Policy CRUD — admins define security policies (thresholds, SLAs, required
 * scan types) that the PR check publisher enforces.
 */
import { Router } from "express";
import { z } from "zod";
import prisma from "../../db.js";
import { requireAuth } from "../../middleware/requireAuth.js";
import { requireRole } from "../../middleware/requireRole.js";

const router = Router();

const ruleSchema = z.object({
  type: z.enum([
    "SEVERITY_THRESHOLD",
    "BLOCK_ON_NEW_ONLY",
    "SLA_DAYS",
    "IGNORE_DEV_DEPS",
    "SCAN_TYPE_REQUIRED",
  ]),
  config: z.record(z.unknown()).default({}),
});

const upsertSchema = z.object({
  name:           z.string().min(1).max(80),
  description:    z.string().max(500).optional(),
  isDefault:      z.boolean().optional(),
  isActive:       z.boolean().optional(),
  repoIds:        z.array(z.string()).default([]),
  branchPatterns: z.array(z.string()).default([]),
  rules:          z.array(ruleSchema).default([]),
});

// List policies
router.get("/", requireAuth, async (req, res, next) => {
  try {
    const user = req.user as { id: string };
    const member = await prisma.organizationMember.findFirst({ where: { userId: user.id } });
    if (!member) { res.json([]); return; }
    const rows = await prisma.policy.findMany({
      where: { orgId: member.orgId },
      include: { rules: true, _count: { select: { repositories: true } } },
      orderBy: [{ isDefault: "desc" }, { createdAt: "asc" }],
    });
    res.json(rows);
  } catch (err) { next(err); }
});

// Get one
router.get("/:id", requireAuth, async (req, res, next) => {
  try {
    const user = req.user as { id: string };
    const member = await prisma.organizationMember.findFirst({ where: { userId: user.id } });
    if (!member) { res.status(404).json({ error: "not found" }); return; }
    const policy = await prisma.policy.findFirst({
      where: { id: req.params.id, orgId: member.orgId },
      include: { rules: true },
    });
    if (!policy) { res.status(404).json({ error: "not found" }); return; }
    res.json(policy);
  } catch (err) { next(err); }
});

// Create — ADMIN+
router.post("/", requireRole("ADMIN"), async (req, res, next) => {
  try {
    const body   = upsertSchema.parse(req.body);
    const user   = req.user as { id: string };
    const member = await prisma.organizationMember.findFirst({ where: { userId: user.id } });
    if (!member) { res.status(403).json({ error: "no org" }); return; }

    // If marking this policy as default, clear any other default first
    if (body.isDefault) {
      await prisma.policy.updateMany({
        where: { orgId: member.orgId, isDefault: true },
        data:  { isDefault: false },
      });
    }

    const policy = await prisma.policy.create({
      data: {
        orgId:          member.orgId,
        name:           body.name,
        description:    body.description,
        isDefault:      body.isDefault ?? false,
        isActive:       body.isActive  ?? true,
        repoIds:        body.repoIds,
        branchPatterns: body.branchPatterns,
        rules: {
          create: body.rules.map((r) => ({
            type: r.type,
            config: r.config as object,
          })),
        },
      },
      include: { rules: true },
    });
    res.status(201).json(policy);
  } catch (err) { next(err); }
});

// Update — ADMIN+
router.put("/:id", requireRole("ADMIN"), async (req, res, next) => {
  try {
    const body   = upsertSchema.parse(req.body);
    const user   = req.user as { id: string };
    const member = await prisma.organizationMember.findFirst({ where: { userId: user.id } });
    if (!member) { res.status(403).json({ error: "no org" }); return; }

    const existing = await prisma.policy.findFirst({
      where: { id: req.params.id, orgId: member.orgId },
    });
    if (!existing) { res.status(404).json({ error: "not found" }); return; }

    if (body.isDefault && !existing.isDefault) {
      await prisma.policy.updateMany({
        where: { orgId: member.orgId, isDefault: true },
        data:  { isDefault: false },
      });
    }

    const updated = await prisma.$transaction(async (tx) => {
      // Replace rules wholesale
      await tx.policyRule.deleteMany({ where: { policyId: req.params.id } });
      return tx.policy.update({
        where: { id: req.params.id },
        data: {
          name:           body.name,
          description:    body.description,
          isDefault:      body.isDefault ?? false,
          isActive:       body.isActive  ?? true,
          repoIds:        body.repoIds,
          branchPatterns: body.branchPatterns,
          rules: {
          create: body.rules.map((r) => ({
            type: r.type,
            config: r.config as object,
          })),
        },
        },
        include: { rules: true },
      });
    });
    res.json(updated);
  } catch (err) { next(err); }
});

// Delete — ADMIN+
router.delete("/:id", requireRole("ADMIN"), async (req, res, next) => {
  try {
    const user   = req.user as { id: string };
    const member = await prisma.organizationMember.findFirst({ where: { userId: user.id } });
    if (!member) { res.status(403).json({ error: "no org" }); return; }
    await prisma.policy.deleteMany({
      where: { id: req.params.id, orgId: member.orgId },
    });
    res.status(204).end();
  } catch (err) { next(err); }
});

export default router;
