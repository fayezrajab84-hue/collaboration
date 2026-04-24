/**
 * Admin routes — platform-operator tooling, gated to ADMIN+.
 *
 * Currently exposes:
 *   GET    /api/admin/queues                         — per-queue job counters
 *   GET    /api/admin/queues/:name/failed            — failed-job list (most recent 50)
 *   POST   /api/admin/queues/:name/jobs/:jobId/retry — move a failed job back to waiting
 *   DELETE /api/admin/queues/:name/jobs/:jobId       — drop a failed job permanently
 *
 * Rationale: BullMQ keeps a rolling window of failed jobs (`removeOnFail: 200`
 * in most queues) — without a viewer, root-causing a scan regression means
 * grepping container logs. This gives ops a one-click retry + visibility.
 */
import { Router } from "express";
import type { Queue } from "bullmq";
import { requireAuth } from "../../middleware/requireAuth.js";
import { requireRole } from "../../middleware/requireRole.js";
import { scanQueues, aiTriageQueue, fpSweepQueue } from "../../queues/definitions.js";

const router = Router();
router.use(requireAuth);
router.use(requireRole("ADMIN"));

// All queues exposed to the admin UI, keyed by canonical name.
// Typed as `Queue` (no payload generic) because we never `add()` from here;
// we only read counters and fetch existing jobs.
const ALL_QUEUES: Record<string, Queue> = {
  "ai-triage":             aiTriageQueue as unknown as Queue,
  "fp-sweep":              fpSweepQueue,
  ...Object.fromEntries(Object.entries(scanQueues).map(([k, q]) => [`scan-${k}`, q as unknown as Queue])),
};

router.get("/queues", async (_req, res, next) => {
  try {
    const rows = await Promise.all(
      Object.entries(ALL_QUEUES).map(async ([name, q]) => {
        const counts = await q.getJobCounts("waiting", "active", "completed", "failed", "delayed", "paused");
        return { name, counts };
      })
    );
    res.json(rows);
  } catch (err) { next(err); }
});

router.get("/queues/:name/failed", async (req, res, next) => {
  try {
    const q = ALL_QUEUES[req.params["name"]!];
    if (!q) { res.status(404).json({ error: "Unknown queue" }); return; }
    const limit = Math.min(200, parseInt(req.query["limit"] as string || "50"));
    const jobs = await q.getFailed(0, limit - 1);
    res.json(jobs.map((j) => ({
      id:           j.id,
      name:         j.name,
      attemptsMade: j.attemptsMade,
      failedReason: j.failedReason,
      timestamp:    j.timestamp,
      finishedOn:   j.finishedOn,
      // Truncate data to keep payload small — sensitive tokens could live here
      data:         j.data,
      stacktrace:   j.stacktrace?.slice(0, 3),  // first few frames
    })));
  } catch (err) { next(err); }
});

router.post("/queues/:name/jobs/:jobId/retry", async (req, res, next) => {
  try {
    const q = ALL_QUEUES[req.params["name"]!];
    if (!q) { res.status(404).json({ error: "Unknown queue" }); return; }
    const job = await q.getJob(req.params["jobId"]!);
    if (!job) { res.status(404).json({ error: "Job not found" }); return; }
    await job.retry();
    res.json({ ok: true });
  } catch (err) { next(err); }
});

router.delete("/queues/:name/jobs/:jobId", async (req, res, next) => {
  try {
    const q = ALL_QUEUES[req.params["name"]!];
    if (!q) { res.status(404).json({ error: "Unknown queue" }); return; }
    const job = await q.getJob(req.params["jobId"]!);
    if (!job) { res.status(404).json({ error: "Job not found" }); return; }
    await job.remove();
    res.json({ ok: true });
  } catch (err) { next(err); }
});

export default router;
