import { Router } from "express";
import { requireAuth } from "../../middleware/requireAuth.js";
import prisma from "../../db.js";
import { addClient, removeClient } from "../../services/sseService.js";

const router = Router();
router.use(requireAuth);

// List scan jobs
router.get("/", async (req, res, next) => {
  try {
    const user = req.user as { id: string };
    const member = await prisma.organizationMember.findFirst({ where: { userId: user.id } });
    if (!member) { res.json({ data: [], total: 0 }); return; }

    const page = Math.max(1, parseInt(req.query["page"] as string || "1"));
    const limit = Math.min(50, parseInt(req.query["limit"] as string || "20"));
    const skip = (page - 1) * limit;

    const [data, total] = await Promise.all([
      prisma.scanJob.findMany({
        where: { orgId: member.orgId },
        orderBy: { createdAt: "desc" },
        skip,
        take: limit,
      }),
      prisma.scanJob.count({ where: { orgId: member.orgId } }),
    ]);

    res.json({ data, total, page, limit, totalPages: Math.ceil(total / limit) });
  } catch (err) { next(err); }
});

// Get scan job
router.get("/:id", async (req, res, next) => {
  try {
    const user = req.user as { id: string };
    const member = await prisma.organizationMember.findFirst({ where: { userId: user.id } });
    const scan = await prisma.scanJob.findFirst({
      where: { id: req.params["id"], orgId: member?.orgId },
    });
    if (!scan) { res.status(404).json({ error: "Scan job not found" }); return; }
    res.json(scan);
  } catch (err) { next(err); }
});

// SSE stream for real-time scan progress
router.get("/:id/events", async (req, res, next) => {
  try {
    const user = req.user as { id: string };
    const member = await prisma.organizationMember.findFirst({ where: { userId: user.id } });
    const scan = await prisma.scanJob.findFirst({
      where: { id: req.params["id"], orgId: member?.orgId },
    });
    if (!scan) { res.status(404).json({ error: "Scan job not found" }); return; }

    const scanJobId = req.params["id"] as string;

    res.setHeader("Content-Type", "text/event-stream");
    res.setHeader("Cache-Control", "no-cache");
    res.setHeader("Connection", "keep-alive");
    res.setHeader("X-Accel-Buffering", "no");
    res.flushHeaders();

    // Send current status immediately
    res.write(`data: ${JSON.stringify({ type: "INITIAL", status: scan.status, scanJobId })}\n\n`);

    addClient(scanJobId, res);

    req.on("close", () => {
      removeClient(scanJobId, res);
    });
  } catch (err) { next(err); }
});

export default router;
