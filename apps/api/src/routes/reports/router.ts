/**
 * Reports routes (Phase 5)
 *
 * POST /api/reports/generate — streams a full security report as SSE tokens
 */

import { Router } from "express";
import { requireAuth } from "../../middleware/requireAuth.js";
import prisma from "../../db.js";
import { streamSecurityReport } from "../../services/reportService.js";

const router = Router();
router.use(requireAuth);

router.post("/generate", async (req, res, next) => {
  try {
    const user   = req.user as { id: string };
    const member = await prisma.organizationMember.findFirst({ where: { userId: user.id } });
    if (!member) { res.status(403).json({ error: "No organization found" }); return; }

    res.setHeader("Content-Type",      "text/event-stream");
    res.setHeader("Cache-Control",     "no-cache, no-transform");
    res.setHeader("Connection",        "keep-alive");
    res.setHeader("X-Accel-Buffering", "no");
    res.flushHeaders();

    const keepAlive = setInterval(() => res.write(": ping\n\n"), 15_000);
    let closed = false;

    req.on("close", () => { closed = true; clearInterval(keepAlive); });

    await streamSecurityReport(
      member.orgId,
      (token) => { if (!closed) res.write(`data: ${JSON.stringify({ token })}\n\n`); },
      () => {
        if (!closed) {
          res.write(`data: ${JSON.stringify({ done: true })}\n\n`);
          clearInterval(keepAlive);
          res.end();
        }
      },
      (err) => {
        if (!closed) {
          res.write(`data: ${JSON.stringify({ error: err.message })}\n\n`);
          clearInterval(keepAlive);
          res.end();
        }
      },
    );
  } catch (err) { next(err); }
});

export default router;
