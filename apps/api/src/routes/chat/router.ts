/**
 * Chat routes — SSE streaming AI responses
 *
 * POST /api/chat         — stream a chat response token-by-token
 * GET  /api/chat/stats   — quick org stats for the chat welcome screen
 */

import { Router } from "express";
import { z } from "zod";
import { requireAuth } from "../../middleware/requireAuth.js";
import prisma from "../../db.js";
import { getActiveMembership } from "../../services/activeOrgService.js";
import { streamChat, buildOrgStats } from "../../services/chatService.js";

const router = Router();
router.use(requireAuth);

// ── Schema ────────────────────────────────────────────────────────────────────

const chatSchema = z.object({
  message: z.string().min(1).max(2000),
  history: z
    .array(
      z.object({
        role:    z.enum(["user", "assistant"]),
        content: z.string().max(4000),
      }),
    )
    .max(20)
    .default([]),
});

// ── GET /api/chat/stats ───────────────────────────────────────────────────────
// Returns a quick summary used by the chat welcome screen.

router.get("/stats", async (req, res, next) => {
  try {
    const user   = req.user as { id: string };
    const member = await getActiveMembership(req);
    if (!member) { res.json({ totalOpen: 0, critical: 0, high: 0, medium: 0, low: 0 }); return; }

    const stats = await buildOrgStats(member.orgId);
    res.json(stats);
  } catch (err) { next(err); }
});

// ── POST /api/chat ────────────────────────────────────────────────────────────
// Streams the AI response as Server-Sent Events.
// Each event: data: {"token":"..."}\n\n
// Final event: data: {"done":true}\n\n
// Error event: data: {"error":"..."}\n\n

router.post("/", async (req, res, next) => {
  try {
    const user   = req.user as { id: string };
    const member = await getActiveMembership(req);
    if (!member) { res.status(403).json({ error: "No organization found" }); return; }

    const { message, history } = chatSchema.parse(req.body);

    // ── SSE headers ───────────────────────────────────────────────────────────
    res.setHeader("Content-Type",  "text/event-stream");
    res.setHeader("Cache-Control", "no-cache, no-transform");
    res.setHeader("Connection",    "keep-alive");
    res.setHeader("X-Accel-Buffering", "no");   // disable nginx buffering
    res.flushHeaders();

    // Keep-alive ping so the connection doesn't time out on slow CPU inference
    const keepAlive = setInterval(() => {
      res.write(": ping\n\n");
    }, 15_000);

    const messages = [...history, { role: "user" as const, content: message }];
    let closed = false;

    const cleanup = () => {
      clearInterval(keepAlive);
    };

    req.on("close", () => {
      closed = true;
      cleanup();
    });

    await streamChat(
      member.orgId,
      messages,
      (token) => {
        if (!closed) {
          res.write(`data: ${JSON.stringify({ token })}\n\n`);
        }
      },
      () => {
        if (!closed) {
          res.write(`data: ${JSON.stringify({ done: true })}\n\n`);
          cleanup();
          res.end();
        }
      },
      (err) => {
        if (!closed) {
          res.write(`data: ${JSON.stringify({ error: err.message })}\n\n`);
          cleanup();
          res.end();
        }
      },
    );
  } catch (err) { next(err); }
});

export default router;
