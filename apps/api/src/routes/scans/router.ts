import { Router } from "express";
import { requireAuth } from "../../middleware/requireAuth.js";
import prisma from "../../db.js";
import { addClient, removeClient, emitStatusChange, emit } from "../../services/sseService.js";
import { scanQueues } from "../../queues/definitions.js";
import { generateScanSummary } from "../../services/scanSummaryService.js";
import type { ScanType } from "@devsecops/types";

const router = Router();

// ── Internal phase-progress callback (no user auth — scanner calls this over internal network)
router.post("/:id/progress", async (req, res) => {
  const { pct, phase } = req.body as { pct?: number; phase?: string };
  if (typeof pct === "number") {
    emit(req.params["id"], {
      type: "PHASE_PROGRESS",
      phase: phase ?? "scanning",
      pct: Math.min(100, Math.max(0, Math.round(pct))),
    });
  }
  res.json({ ok: true });
});

// ── Crawler-progress callback (Phase 5) ──────────────────────────────────────
// The Playwright crawler sidecar posts live crawl stats here during a DAST
// scan's pre-crawl phase. The API fans them out over the existing SSE stream
// so the frontend can show "pages crawled: 42, XHR found: 19, current URL…"
// without polling.
router.post("/:id/crawler-progress", async (req, res) => {
  const b = req.body as {
    pages_visited?: number;
    pages_queued?: number;
    xhr_observed?: number;
    forms_found?: number;
    current_url?: string | null;
    elapsed_secs?: number;
  };
  emit(req.params["id"], {
    type: "CRAWLER_PROGRESS",
    pagesVisited: Math.max(0, b.pages_visited ?? 0),
    pagesQueued:  Math.max(0, b.pages_queued ?? 0),
    xhrObserved:  Math.max(0, b.xhr_observed ?? 0),
    formsFound:   Math.max(0, b.forms_found ?? 0),
    currentUrl:   b.current_url ?? null,
    elapsedSecs:  b.elapsed_secs ?? 0,
  });
  res.json({ ok: true });
});

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
        include: {
          repository: { select: { id: true, fullName: true } },
          container:  { select: { id: true, imageRef: true } },
          domain:     { select: { id: true, domain: true } },
        },
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
      include: {
        repository: { select: { fullName: true } },
        container:  { select: { imageRef: true } },
        domain:     { select: { domain: true } },
      },
    });
    if (!scan) { res.status(404).json({ error: "Scan job not found" }); return; }

    // Attach computed "confirmed" count — findings that existed before this
    // scan ran AND were re-observed in it.  Computed on the fly to avoid a
    // schema migration; the fact that upsertFindings bumps `lastSeen` inside
    // the scan's time window is our truth source.
    // "New"       = firstSeen between startedAt and completedAt
    // "Confirmed" = firstSeen < startedAt, lastSeen >= startedAt
    const scanTargetFilter =
      scan.targetType === "REPOSITORY" ? { repositoryId: scan.targetId }
      : scan.targetType === "CONTAINER" ? { containerId: scan.targetId }
      : { domainId: scan.targetId };

    let confirmedCount = 0;
    let newThisScan   = 0;
    if (scan.startedAt) {
      const windowEnd = scan.completedAt ?? new Date();
      [confirmedCount, newThisScan] = await Promise.all([
        prisma.finding.count({
          where: {
            orgId:    scan.orgId,
            scanType: { in: scan.scanTypes },
            ...scanTargetFilter,
            firstSeen: { lt: scan.startedAt },
            lastSeen:  { gte: scan.startedAt, lte: windowEnd },
          },
        }),
        prisma.finding.count({
          where: {
            orgId:    scan.orgId,
            scanType: { in: scan.scanTypes },
            ...scanTargetFilter,
            firstSeen: { gte: scan.startedAt, lte: windowEnd },
          },
        }),
      ]);
    }

    res.json({ ...scan, confirmedCount, newThisScan });
  } catch (err) { next(err); }
});

// Cancel a scan job
router.post("/:id/cancel", async (req, res, next) => {
  try {
    const user = req.user as { id: string };
    const member = await prisma.organizationMember.findFirst({ where: { userId: user.id } });
    const scan = await prisma.scanJob.findFirst({
      where: { id: req.params["id"], orgId: member?.orgId },
    });
    if (!scan) { res.status(404).json({ error: "Scan job not found" }); return; }
    if (!["PENDING", "RUNNING"].includes(scan.status)) {
      res.status(409).json({ error: `Cannot cancel a scan in ${scan.status} state` });
      return;
    }

    // Remove any waiting BullMQ jobs (active jobs will finish but DB marks them cancelled)
    const jobIds = (scan.bullJobIds ?? {}) as Record<string, string>;
    await Promise.allSettled(
      Object.entries(jobIds).map(async ([scanType, jobId]) => {
        const queue = scanQueues[scanType as ScanType];
        if (!queue || !jobId) return;
        try {
          const job = await queue.getJob(jobId);
          if (job) await job.remove();
        } catch {
          // Job may already be active or completed — ignore
        }
      })
    );

    await prisma.scanJob.update({
      where: { id: scan.id },
      data: { status: "CANCELLED", completedAt: new Date() },
    });

    emitStatusChange(scan.id, "CANCELLED");
    res.json({ success: true });
  } catch (err) { next(err); }
});

// Delete a scan job (and its findings)
router.delete("/:id", async (req, res, next) => {
  try {
    const user   = req.user as { id: string };
    const member = await prisma.organizationMember.findFirst({ where: { userId: user.id } });
    const scan   = await prisma.scanJob.findFirst({
      where: { id: req.params["id"], orgId: member?.orgId },
    });
    if (!scan) { res.status(404).json({ error: "Scan job not found" }); return; }

    await prisma.scanJob.delete({ where: { id: scan.id } });
    res.json({ success: true });
  } catch (err) { next(err); }
});

// Delete all failed scan jobs for the org
router.delete("/", async (req, res, next) => {
  try {
    if (req.query["status"] !== "FAILED") {
      res.status(400).json({ error: "Only bulk-delete of FAILED scans is supported" });
      return;
    }
    const user   = req.user as { id: string };
    const member = await prisma.organizationMember.findFirst({ where: { userId: user.id } });
    if (!member) { res.json({ count: 0 }); return; }

    const { count } = await prisma.scanJob.deleteMany({
      where: { orgId: member.orgId, status: "FAILED" },
    });
    res.json({ count });
  } catch (err) { next(err); }
});

// On-demand AI summary generation (for old scans or manual refresh)
router.post("/:id/summary", async (req, res, next) => {
  try {
    const user   = req.user as { id: string };
    const member = await prisma.organizationMember.findFirst({ where: { userId: user.id } });
    const scan   = await prisma.scanJob.findFirst({
      where: { id: req.params["id"], orgId: member?.orgId },
    });
    if (!scan) { res.status(404).json({ error: "Scan job not found" }); return; }
    if (scan.status !== "COMPLETED") {
      res.status(409).json({ error: "Summary only available for completed scans" });
      return;
    }

    // Reset so generateScanSummary doesn't short-circuit on existing value
    await prisma.scanJob.update({
      where: { id: scan.id },
      data: { aiSummary: null, aiSummarisedAt: null },
    });

    // Run in background — client polls GET /:id for the result
    generateScanSummary(scan.id).catch(() => {});
    res.json({ queued: true });
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
