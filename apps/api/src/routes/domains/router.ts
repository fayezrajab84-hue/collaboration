import { Router } from "express";
import { z } from "zod";
import { requireAuth } from "../../middleware/requireAuth.js";
import prisma from "../../db.js";
import { triggerScan } from "../../services/scanService.js";
import type { ScanType } from "@devsecops/types";

const router = Router();
router.use(requireAuth);

const createDomainSchema = z.object({
  domain: z
    .string()
    .min(1)
    .regex(/^(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$/, "Invalid domain"),
});

const updateDomainSchema = z.object({
  domain: z
    .string()
    .min(1)
    .regex(/^(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$/, "Invalid domain")
    .optional(),
});

// List domains
router.get("/", async (req, res, next) => {
  try {
    const user = req.user as { id: string };
    const member = await prisma.organizationMember.findFirst({ where: { userId: user.id } });
    if (!member) { res.json([]); return; }

    const [domains, countRows] = await Promise.all([
      prisma.domain.findMany({ where: { orgId: member.orgId }, orderBy: { addedAt: "desc" } }),
      prisma.finding.groupBy({
        by: ["domainId", "severity"],
        where: { orgId: member.orgId, domainId: { not: null }, status: { not: "FALSE_POSITIVE" } },
        _count: { id: true },
      }),
    ]);

    const countMap: Record<string, Record<string, number>> = {};
    for (const row of countRows) {
      const did = row.domainId!;
      if (!countMap[did]) countMap[did] = {};
      countMap[did][row.severity] = row._count.id;
    }

    const result = domains.map((d) => ({
      ...d,
      findingCounts: {
        CRITICAL: countMap[d.id]?.CRITICAL ?? 0,
        HIGH: countMap[d.id]?.HIGH ?? 0,
        MEDIUM: countMap[d.id]?.MEDIUM ?? 0,
        LOW: countMap[d.id]?.LOW ?? 0,
      },
    }));

    res.json(result);
  } catch (err) { next(err); }
});

// Add domain
router.post("/", async (req, res, next) => {
  try {
    const body = createDomainSchema.parse(req.body);
    const user = req.user as { id: string };
    const member = await prisma.organizationMember.findFirst({ where: { userId: user.id } });
    if (!member) { res.status(400).json({ error: "No organization found" }); return; }

    const domain = await prisma.domain.create({
      data: { orgId: member.orgId, domain: body.domain },
    });
    res.status(201).json(domain);
  } catch (err) { next(err); }
});

// Get domain
router.get("/:id", async (req, res, next) => {
  try {
    const user = req.user as { id: string };
    const member = await prisma.organizationMember.findFirst({ where: { userId: user.id } });
    const domain = await prisma.domain.findFirst({
      where: { id: req.params["id"], orgId: member?.orgId },
    });
    if (!domain) { res.status(404).json({ error: "Domain not found" }); return; }
    res.json(domain);
  } catch (err) { next(err); }
});

// Update domain
router.patch("/:id", async (req, res, next) => {
  try {
    const body = updateDomainSchema.parse(req.body);
    const user = req.user as { id: string };
    const member = await prisma.organizationMember.findFirst({ where: { userId: user.id } });
    const domain = await prisma.domain.findFirst({
      where: { id: req.params["id"], orgId: member?.orgId },
    });
    if (!domain) { res.status(404).json({ error: "Domain not found" }); return; }
    const updated = await prisma.domain.update({
      where: { id: domain.id },
      data: { ...(body.domain && { domain: body.domain }) },
    });
    res.json(updated);
  } catch (err) { next(err); }
});

// Delete domain
router.delete("/:id", async (req, res, next) => {
  try {
    const user = req.user as { id: string };
    const member = await prisma.organizationMember.findFirst({ where: { userId: user.id } });
    const domain = await prisma.domain.findFirst({
      where: { id: req.params["id"], orgId: member?.orgId },
    });
    if (!domain) { res.status(404).json({ error: "Domain not found" }); return; }
    await prisma.domain.delete({ where: { id: domain.id } });
    res.json({ ok: true });
  } catch (err) { next(err); }
});

// Trigger scan (DAST + Pentest)
router.post("/:id/scan", async (req, res, next) => {
  try {
    const user = req.user as { id: string };
    const member = await prisma.organizationMember.findFirst({ where: { userId: user.id } });
    const domain = await prisma.domain.findFirst({
      where: { id: req.params["id"], orgId: member?.orgId },
    });
    if (!domain) { res.status(404).json({ error: "Domain not found" }); return; }

    const scanTypes: ScanType[] = ["DAST", "PENTEST"];
    const result = await triggerScan({
      orgId: member!.orgId,
      targetType: "DOMAIN",
      targetId: domain.id,
      scanTypes,
      domain: domain.domain,
    });
    res.status(202).json(result);
  } catch (err) { next(err); }
});

export default router;
