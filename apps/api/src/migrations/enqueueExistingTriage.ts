/**
 * One-time script: enqueue AI triage for existing CRITICAL/HIGH findings
 * that have never been automatically analysed.
 *
 * Run:
 *   docker exec admiring-hertz-api-1 sh -c \
 *     "node --import tsx/esm /app/apps/api/src/migrations/enqueueExistingTriage.ts"
 */

import { aiTriageQueue } from "../queues/definitions.js";
import prisma from "../db.js";
import { logger } from "../logger.js";

const PRIO: Record<string, number> = { CRITICAL: 1, HIGH: 2, MEDIUM: 3 };

async function run() {
  const findings = await prisma.finding.findMany({
    where: {
      aiAnalysedAt: null,
      severity:     { in: ["CRITICAL", "HIGH"] },   // MEDIUM deferred — too many for retroactive triage
      status:       { notIn: ["FALSE_POSITIVE", "IGNORED", "FIXED"] },
    },
    select: { id: true, scanType: true, severity: true },
  });

  logger.info(`[enqueue-triage] found ${findings.length} untriaged CRITICAL/HIGH findings`);

  if (findings.length === 0) {
    logger.info("[enqueue-triage] nothing to enqueue");
    return;
  }

  const jobs = findings.map((f) => ({
    name: "triage" as const,
    data: { findingId: f.id, scanType: f.scanType, severity: f.severity },
    opts: {
      priority: PRIO[f.severity] ?? 3,
      jobId:    `triage-${f.id}`,   // dedup — safe to re-run
    },
  }));

  await aiTriageQueue.addBulk(jobs);
  logger.info(`[enqueue-triage] enqueued ${jobs.length} triage jobs — CRITICAL first`);
}

run()
  .then(() => process.exit(0))
  .catch((err) => { console.error(err); process.exit(1); });
