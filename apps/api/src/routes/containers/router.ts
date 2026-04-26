import { Router } from "express";
import { z } from "zod";
import { requireAuth } from "../../middleware/requireAuth.js";
import { requireRole } from "../../middleware/requireRole.js";
import prisma from "../../db.js";
import { triggerScan } from "../../services/scanService.js";
import { generateContainerSbom } from "../../services/sbomService.js";
import { scoreTarget } from "../../services/riskScoringService.js";
import * as audit from "../../services/auditService.js";
import type { ScanType } from "@devsecops/types";

const router = Router();
router.use(requireAuth);

const createContainerSchema = z.object({
  imageRef: z.string().min(1, "Image reference is required"),
  registry: z.string().optional(),
});

const updateContainerSchema = z.object({
  imageRef: z.string().min(1).optional(),
  registry: z.string().nullable().optional(),
});

// List containers
router.get("/", async (req, res, next) => {
  try {
    const user = req.user as { id: string };
    const member = await prisma.organizationMember.findFirst({ where: { userId: user.id } });
    if (!member) { res.json([]); return; }

    const [containers, countRows] = await Promise.all([
      prisma.container.findMany({ where: { orgId: member.orgId }, orderBy: { addedAt: "desc" } }),
      prisma.finding.groupBy({
        by: ["containerId", "severity"],
        where: { orgId: member.orgId, containerId: { not: null }, status: { not: "FALSE_POSITIVE" } },
        _count: { id: true },
      }),
    ]);

    const countMap: Record<string, Record<string, number>> = {};
    for (const row of countRows) {
      const cid = row.containerId!;
      if (!countMap[cid]) countMap[cid] = {};
      countMap[cid][row.severity] = row._count.id;
    }

    const result = containers.map((c) => ({
      ...c,
      findingCounts: {
        CRITICAL: countMap[c.id]?.CRITICAL ?? 0,
        HIGH: countMap[c.id]?.HIGH ?? 0,
        MEDIUM: countMap[c.id]?.MEDIUM ?? 0,
        LOW: countMap[c.id]?.LOW ?? 0,
      },
    }));

    res.json(result);
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

// Update container
router.patch("/:id", async (req, res, next) => {
  try {
    const body = updateContainerSchema.parse(req.body);
    const user = req.user as { id: string };
    const member = await prisma.organizationMember.findFirst({ where: { userId: user.id } });
    const container = await prisma.container.findFirst({
      where: { id: req.params["id"], orgId: member?.orgId },
    });
    if (!container) { res.status(404).json({ error: "Container not found" }); return; }
    const updated = await prisma.container.update({
      where: { id: container.id },
      data: {
        ...(body.imageRef && { imageRef: body.imageRef }),
        ...(body.registry !== undefined && { registry: body.registry }),
      },
    });
    res.json(updated);
  } catch (err) { next(err); }
});

// Delete container — ADMIN+
router.delete("/:id", requireRole("ADMIN"), async (req, res, next) => {
  try {
    const user = req.user as { id: string };
    const container = await prisma.container.findFirst({
      where: { id: req.params["id"], orgId: req.orgId! },
    });
    if (!container) { res.status(404).json({ error: "Container not found" }); return; }
    await prisma.container.delete({ where: { id: container.id } });
    await audit.log({
      orgId:        req.orgId!,
      userId:       user.id,
      action:       "container.delete",
      resourceType: "Container",
      resourceId:   container.id,
      metadata:     { imageRef: container.imageRef },
    });
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

// POST /api/containers/:id/risk-score
router.post("/:id/risk-score", async (req, res, next) => {
  try {
    const user   = req.user as { id: string };
    const member = await prisma.organizationMember.findFirst({ where: { userId: user.id } });
    const target = await prisma.container.findFirst({ where: { id: req.params["id"], orgId: member?.orgId } });
    if (!target) { res.status(404).json({ error: "Container not found" }); return; }
    await scoreTarget("CONTAINER", target.id);
    const updated = await prisma.container.findUniqueOrThrow({ where: { id: target.id } });
    res.json({ aiRiskScore: updated.aiRiskScore, aiRiskReason: updated.aiRiskReason, aiRiskScoredAt: updated.aiRiskScoredAt });
  } catch (err) { next(err); }
});

// GET /api/containers/:id/sbom?format=cyclonedx|spdx — SBOM download
//
// CycloneDX is the default. SPDX (ISO/IEC 5962) offered as an alternate
// for procurement reviewers that require it.
router.get("/:id/sbom", async (req, res, next) => {
  try {
    const user      = req.user as { id: string };
    const member    = await prisma.organizationMember.findFirst({ where: { userId: user.id } });
    const container = await prisma.container.findFirst({
      where: { id: req.params["id"], orgId: member?.orgId },
    });
    if (!container) { res.status(404).json({ error: "Container not found" }); return; }

    const formatRaw = String(req.query["format"] ?? "cyclonedx").toLowerCase();
    if (formatRaw !== "cyclonedx" && formatRaw !== "spdx") {
      res.status(400).json({ error: "format must be cyclonedx or spdx" });
      return;
    }
    const format = formatRaw as SbomFormat;

    const sbom = await generateContainerSbom({ imageRef: container.imageRef, format });

    if (member?.orgId) {
      await audit.log({
        orgId: member.orgId, userId: user.id,
        action: "sbom.download", resourceType: "Container", resourceId: container.id,
        metadata: { format, imageRef: container.imageRef },
      });
    }

    const meta     = SBOM_FORMAT_META[format];
    const safeName = container.imageRef.replace(/[^a-zA-Z0-9._-]/g, "_");
    res.setHeader("Content-Type",        meta.contentType);
    res.setHeader("Content-Disposition", `attachment; filename="${safeName}-sbom.${meta.suffix}"`);
    res.send(JSON.stringify(sbom, null, 2));
  } catch (err) { next(err); }
});

export default router;
