import { Router } from "express";
import { z } from "zod";
import { requireAuth } from "../../middleware/requireAuth.js";
import prisma from "../../db.js";
import { triggerScan } from "../../services/scanService.js";
import type { ScanType } from "@devsecops/types";

const router = Router();
router.use(requireAuth);

const createContainerSchema = z.object({
  imageRef: z.string().min(1, "Image reference is required"),
  registry: z.string().optional(),
});

// List containers
router.get("/", async (req, res, next) => {
  try {
    const user = req.user as { id: string };
    const member = await prisma.organizationMember.findFirst({ where: { userId: user.id } });
    if (!member) { res.json([]); return; }
    const containers = await prisma.container.findMany({
      where: { orgId: member.orgId },
      orderBy: { addedAt: "desc" },
    });
    res.json(containers);
  } catch (err) { next(err); }
});

// Add container
router.post("/", async (req, res, next) => {
  try {
    const body = createContainerSchema.parse(req.body);
    const user = req.user as { id: string };
    const member = await prisma.organizationMember.findFirst({ where: { userId: user.id } });
    if (!member) { res.status(400).json({ error: "No organization found" }); return; }

    const container = await prisma.container.create({
      data: { orgId: member.orgId, imageRef: body.imageRef, registry: body.registry ?? null },
    });
    res.status(201).json(container);
  } catch (err) { next(err); }
});

// Get container
router.get("/:id", async (req, res, next) => {
  try {
    const user = req.user as { id: string };
    const member = await prisma.organizationMember.findFirst({ where: { userId: user.id } });
    const container = await prisma.container.findFirst({
      where: { id: req.params["id"], orgId: member?.orgId },
    });
    if (!container) { res.status(404).json({ error: "Container not found" }); return; }
    res.json(container);
  } catch (err) { next(err); }
});

// Delete container
router.delete("/:id", async (req, res, next) => {
  try {
    const user = req.user as { id: string };
    const member = await prisma.organizationMember.findFirst({ where: { userId: user.id } });
    const container = await prisma.container.findFirst({
      where: { id: req.params["id"], orgId: member?.orgId },
    });
    if (!container) { res.status(404).json({ error: "Container not found" }); return; }
    await prisma.container.delete({ where: { id: container.id } });
    res.json({ ok: true });
  } catch (err) { next(err); }
});

// Trigger scan
router.post("/:id/scan", async (req, res, next) => {
  try {
    const user = req.user as { id: string };
    const member = await prisma.organizationMember.findFirst({ where: { userId: user.id } });
    const container = await prisma.container.findFirst({
      where: { id: req.params["id"], orgId: member?.orgId },
    });
    if (!container) { res.status(404).json({ error: "Container not found" }); return; }

    const scanTypes: ScanType[] = ["CONTAINER"];
    const result = await triggerScan({
      orgId: member!.orgId,
      targetType: "CONTAINER",
      targetId: container.id,
      scanTypes,
      imageRef: container.imageRef,
    });
    res.status(202).json(result);
  } catch (err) { next(err); }
});

export default router;
