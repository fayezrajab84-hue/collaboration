/**
 * AI Triage Worker
 *
 * Processes new findings immediately after a scan completes.
 * Pre-populates AI analysis + fix suggestions so developers see instant
 * results when they open a finding — no on-demand wait required.
 *
 * Design decisions:
 *  - Concurrency = 1: Ollama runs on CPU and can only serve one request at a time
 *  - Priority queue: CRITICAL(1) → HIGH(2) → MEDIUM(3) → LOW(4) → INFO(5)
 *  - Skips findings already analysed (re-scans of known findings)
 *  - Fix suggestions generated only for code-centric scan types (SAST/IAC/SCA/CONTAINER/SECRET)
 *  - DAST/PENTEST skipped for fix suggestions (no source code context)
 *  - lockDuration = 12 min: analysis (6 min) + fix (5 min) + buffer
 */

import { Worker } from "bullmq";
import { bullRedis } from "../redis.js";
import { logger } from "../logger.js";
import prisma from "../db.js";
import { analyseFinding } from "../services/aiService.js";
import { generateFixSuggestion } from "../services/fixSuggestionService.js";
import type { AiTriageJobPayload } from "../queues/definitions.js";

// Scan types where a code-level fix diff makes sense
const FIX_SUGGESTION_TYPES = new Set(["SAST", "IAC", "SCA", "CONTAINER", "SECRET"]);

// Severities worth triaging automatically (skip INFO to save CPU)
const TRIAGE_SEVERITIES = new Set(["CRITICAL", "HIGH", "MEDIUM", "LOW"]);

async function processAiTriage(payload: AiTriageJobPayload): Promise<void> {
  const { findingId, scanType, severity } = payload;

  if (!TRIAGE_SEVERITIES.has(severity)) {
    logger.debug(`[ai-triage] skipping ${severity} finding ${findingId}`);
    return;
  }

  // Skip if already analysed (could happen on rapid re-scans)
  const finding = await prisma.finding.findUnique({
    where:  { id: findingId },
    select: { id: true, aiAnalysedAt: true, aiFixSuggestedAt: true, status: true },
  });

  if (!finding) {
    logger.warn(`[ai-triage] finding ${findingId} not found — skipping`);
    return;
  }

  // Don't re-triage findings the user has already manually reviewed
  if (finding.status === "FALSE_POSITIVE" || finding.status === "IGNORED") {
    logger.debug(`[ai-triage] skipping ${finding.status} finding ${findingId}`);
    return;
  }

  const needsAnalysis = !finding.aiAnalysedAt;
  const needsFix      = !finding.aiFixSuggestedAt && FIX_SUGGESTION_TYPES.has(scanType);

  if (!needsAnalysis && !needsFix) {
    logger.debug(`[ai-triage] finding ${findingId} already fully triaged — skipping`);
    return;
  }

  // ── AI Analysis ─────────────────────────────────────────────────────────────
  if (needsAnalysis) {
    try {
      logger.info(`[ai-triage] analysing finding ${findingId} (${scanType} ${severity})`);
      await analyseFinding(findingId);
      logger.info(`[ai-triage] analysis done for ${findingId}`);
    } catch (err) {
      const msg = err instanceof Error ? err.message : String(err);
      logger.warn(`[ai-triage] analysis failed for ${findingId}: ${msg}`);
      // Don't rethrow — still try fix suggestion even if analysis failed
    }
  }

  // ── Fix Suggestion ───────────────────────────────────────────────────────────
  if (needsFix) {
    try {
      logger.info(`[ai-triage] generating fix for finding ${findingId} (${scanType})`);
      await generateFixSuggestion(findingId);
      logger.info(`[ai-triage] fix suggestion done for ${findingId}`);
    } catch (err) {
      const msg = err instanceof Error ? err.message : String(err);
      logger.warn(`[ai-triage] fix suggestion failed for ${findingId}: ${msg}`);
    }
  }
}

export function initAiTriageWorker(): void {
  const worker = new Worker<AiTriageJobPayload>(
    "ai-triage",
    async (job) => {
      await processAiTriage(job.data);
    },
    {
      connection:   bullRedis,
      concurrency:  1,          // Ollama is single-threaded — never run two at once
      lockDuration: 1_200_000,  // 20 min — analysis (6 min) + fix (10 min on 7B model) + buffer
    },
  );

  worker.on("failed", (job, err) => {
    if (!job) return;
    logger.error(`[ai-triage] job failed for finding ${job.data.findingId}: ${err.message}`);
  });

  worker.on("completed", (job) => {
    logger.debug(`[ai-triage] job completed for finding ${job.data.findingId}`);
  });

  logger.info("[ai-triage] worker initialized (concurrency=1)");
}
