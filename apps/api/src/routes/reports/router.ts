/**
 * Reports API
 *
 * GET  /api/reports              — list reports for the user's org (paginated)
 * GET  /api/reports/:id/html     — download the HTML file
 * DELETE /api/reports/:id        — delete a stored report
 * POST /api/reports/generate     — on-demand: generate report for a scan job (fire-and-forget)
 * POST /api/reports/ai-generate  — legacy AI streaming security report (SSE)
 */

import { Router }       from "express";
import { z }            from "zod";
import { requireAuth }  from "../../middleware/requireAuth.js";
import prisma           from "../../db.js";
import { logger }       from "../../logger.js";
import { streamSecurityReport }  from "../../services/reportService.js";
import { generateTargetReport }  from "../../services/reportHtmlService.js";

const router = Router();
router.use(requireAuth);

// ── Helpers ───────────────────────────────────────────────────────────────────

async function getOrgId(userId: string): Promise<string | null> {
  const m = await prisma.organizationMember.findFirst({ where: { userId } });
  return m?.orgId ?? null;
}

// ── GET /api/reports — list ───────────────────────────────────────────────────

router.get("/", async (req, res, next) => {
  try {
    const orgId = await getOrgId((req.user as { id: string }).id);
    if (!orgId) { res.status(403).json({ error: "No organisation" }); return; }

    const page  = Math.max(1, Number(req.query["page"]  ?? 1));
    const limit = Math.min(50, Math.max(1, Number(req.query["limit"] ?? 20)));
    const skip  = (page - 1) * limit;

    const [total, reports] = await Promise.all([
      prisma.report.count({ where: { orgId } }),
      prisma.report.findMany({
        where:   { orgId },
        orderBy: { generatedAt: "desc" },
        skip,
        take: limit,
        select: {
          id: true, scanJobId: true, targetType: true, targetId: true,
          trigger: true, title: true, metadata: true, generatedAt: true,
          // Omit htmlContent — too large for list responses
        },
      }),
    ]);

    res.json({
      data:  reports,
      total,
      page,
      limit,
      pages: Math.ceil(total / limit),
    });
  } catch (err) { next(err); }
});

// ── GET /api/reports/:id/html — download ─────────────────────────────────────

router.get("/:id/html", async (req, res, next) => {
  try {
    const orgId = await getOrgId((req.user as { id: string }).id);
    if (!orgId) { res.status(403).json({ error: "No organisation" }); return; }

    const report = await prisma.report.findFirst({
      where: { id: req.params["id"], orgId },
      select: { htmlContent: true, title: true, generatedAt: true },
    });
    if (!report) { res.status(404).json({ error: "Report not found" }); return; }

    const date     = report.generatedAt.toISOString().split("T")[0];
    const safeName = report.title.replace(/[^a-z0-9\-_ ]/gi, "").replace(/\s+/g, "-").toLowerCase();
    const filename = `breachlens-${safeName}-${date}.html`;

    res.setHeader("Content-Type",        "text/html; charset=utf-8");
    res.setHeader("Content-Disposition", `attachment; filename="${filename}"`);
    res.send(report.htmlContent);
  } catch (err) { next(err); }
});

// ── DELETE /api/reports/:id ───────────────────────────────────────────────────

router.delete("/:id", async (req, res, next) => {
  try {
    const orgId = await getOrgId((req.user as { id: string }).id);
    if (!orgId) { res.status(403).json({ error: "No organisation" }); return; }

    const report = await prisma.report.findFirst({ where: { id: req.params["id"], orgId } });
    if (!report) { res.status(404).json({ error: "Report not found" }); return; }

    await prisma.report.delete({ where: { id: req.params["id"] } });
    res.json({ success: true });
  } catch (err) { next(err); }
});

// ── POST /api/reports/generate — on-demand HTML report ───────────────────────

const GenerateSchema = z.object({ scanJobId: z.string().min(1) });

router.post("/generate", async (req, res, next) => {
  try {
    const orgId = await getOrgId((req.user as { id: string }).id);
    if (!orgId) { res.status(403).json({ error: "No organisation" }); return; }

    const parse = GenerateSchema.safeParse(req.body);
    if (!parse.success) {
      res.status(422).json({ error: "scanJobId is required" });
      return;
    }

    const { scanJobId } = parse.data;

    // Verify the scan belongs to this org
    const scan = await prisma.scanJob.findFirst({ where: { id: scanJobId, orgId } });
    if (!scan) { res.status(404).json({ error: "Scan job not found" }); return; }
    if (scan.status !== "COMPLETED") {
      res.status(400).json({ error: "Report can only be generated for completed scans" });
      return;
    }

    // Fire-and-forget; respond immediately
    generateTargetReport(scanJobId).catch((err: Error) =>
      logger.warn(`[report] on-demand generation failed: ${err.message}`)
    );

    res.json({ queued: true, message: "Report generation started — refresh in a few seconds" });
  } catch (err) { next(err); }
});

// ── POST /api/reports/ai-generate — legacy SSE AI streaming report ────────────

router.post("/ai-generate", async (req, res, next) => {
  try {
    const user   = req.user as { id: string };
    const orgId  = await getOrgId(user.id);
    if (!orgId) { res.status(403).json({ error: "No organization found" }); return; }

    res.setHeader("Content-Type",      "text/event-stream");
    res.setHeader("Cache-Control",     "no-cache, no-transform");
    res.setHeader("Connection",        "keep-alive");
    res.setHeader("X-Accel-Buffering", "no");
    res.flushHeaders();

    const keepAlive = setInterval(() => res.write(": ping\n\n"), 15_000);
    let closed = false;
    req.on("close", () => { closed = true; clearInterval(keepAlive); });

    await streamSecurityReport(
      orgId,
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
