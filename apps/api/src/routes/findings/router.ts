import { Router } from "express";
import { z } from "zod";
import { requireAuth } from "../../middleware/requireAuth.js";
import prisma from "../../db.js";

const router = Router();
router.use(requireAuth);

const updateFindingSchema = z.object({
  status: z.enum(["OPEN", "ACKNOWLEDGED", "FALSE_POSITIVE", "FIXED"]),
});

// List findings with filters
router.get("/", async (req, res, next) => {
  try {
    const user = req.user as { id: string };
    const member = await prisma.organizationMember.findFirst({ where: { userId: user.id } });
    if (!member) { res.json({ data: [], total: 0 }); return; }

    const q = req.query;
    const page = Math.max(1, parseInt(q["page"] as string || "1"));
    const limit = Math.min(100, parseInt(q["limit"] as string || "25"));
    const skip = (page - 1) * limit;

    const where: Record<string, unknown> = { orgId: member.orgId };
    if (q["severity"]) where["severity"] = { in: [q["severity"]].flat() };
    if (q["scanType"]) where["scanType"] = { in: [q["scanType"]].flat() };
    if (q["status"]) where["status"] = { in: [q["status"]].flat() };
    if (q["repoId"]) where["repositoryId"] = q["repoId"];
    if (q["containerId"]) where["containerId"] = q["containerId"];
    if (q["domainId"]) where["domainId"] = q["domainId"];
    if (q["search"]) {
      where["OR"] = [
        { title: { contains: q["search"] as string, mode: "insensitive" } },
        { description: { contains: q["search"] as string, mode: "insensitive" } },
        { cveId: { contains: q["search"] as string, mode: "insensitive" } },
      ];
    }

    const [data, total] = await Promise.all([
      prisma.finding.findMany({
        where,
        orderBy: [{ severity: "asc" }, { firstSeen: "desc" }],
        skip,
        take: limit,
        include: { ticket: { select: { id: true, status: true, jiraKey: true } } },
      }),
      prisma.finding.count({ where }),
    ]);

    res.json({ data, total, page, limit, totalPages: Math.ceil(total / limit) });
  } catch (err) { next(err); }
});

// Get finding
router.get("/:id", async (req, res, next) => {
  try {
    const user = req.user as { id: string };
    const member = await prisma.organizationMember.findFirst({ where: { userId: user.id } });
    const finding = await prisma.finding.findFirst({
      where: { id: req.params["id"], orgId: member?.orgId },
      include: { ticket: true, scanJob: true },
    });
    if (!finding) { res.status(404).json({ error: "Finding not found" }); return; }
    res.json(finding);
  } catch (err) { next(err); }
});

// Update finding status
router.patch("/:id", async (req, res, next) => {
  try {
    const body = updateFindingSchema.parse(req.body);
    const user = req.user as { id: string };
    const member = await prisma.organizationMember.findFirst({ where: { userId: user.id } });
    const finding = await prisma.finding.findFirst({
      where: { id: req.params["id"], orgId: member?.orgId },
    });
    if (!finding) { res.status(404).json({ error: "Finding not found" }); return; }

    const updated = await prisma.finding.update({
      where: { id: finding.id },
      data: {
        status: body.status,
        resolvedAt: body.status === "FIXED" ? new Date() : null,
      },
    });
    res.json(updated);
  } catch (err) { next(err); }
});

// Dashboard summary
router.get("/summary/stats", async (req, res, next) => {
  try {
    const user = req.user as { id: string };
    const member = await prisma.organizationMember.findFirst({ where: { userId: user.id } });
    if (!member) { res.json({}); return; }

    const [severityCounts, scanTypeCounts, statusCounts] = await Promise.all([
      prisma.finding.groupBy({
        by: ["severity"],
        where: { orgId: member.orgId, status: { not: "FALSE_POSITIVE" } },
        _count: true,
      }),
      prisma.finding.groupBy({
        by: ["scanType"],
        where: { orgId: member.orgId },
        _count: true,
      }),
      prisma.finding.groupBy({
        by: ["status"],
        where: { orgId: member.orgId },
        _count: true,
      }),
    ]);

    res.json({ severityCounts, scanTypeCounts, statusCounts });
  } catch (err) { next(err); }
});

export default router;
