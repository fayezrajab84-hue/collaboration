/**
 * AI Scan Summary Service (Phase 2)
 *
 * After a ScanJob completes, generates a 2-3 sentence executive summary
 * of what was found and stores it in the DB.  Non-streaming — runs in the
 * background so it never blocks the worker.
 */

import axios from "axios";
import prisma from "../db.js";
import { config } from "../config.js";
import { logger } from "../logger.js";

// ── Summary generator ─────────────────────────────────────────────────────────

export async function generateScanSummary(scanJobId: string): Promise<void> {
  try {
    // Load scan + its top findings
    const scan = await prisma.scanJob.findUnique({
      where: { id: scanJobId },
      include: {
        repository: { select: { fullName: true } },
        container:  { select: { imageRef: true } },
        domain:     { select: { domain: true } },
        findings: {
          where:   { status: { notIn: ["FALSE_POSITIVE", "IGNORED"] } },
          orderBy: [{ severity: "asc" }, { firstSeen: "desc" }],
          take:    10,
          select:  { title: true, severity: true, scanType: true, cveId: true },
        },
      },
    });

    if (!scan || scan.status !== "COMPLETED") return;

    const target =
      scan.repository?.fullName ??
      scan.container?.imageRef  ??
      scan.domain?.domain       ??
      "unknown target";

    const total =
      scan.criticalCount + scan.highCount + scan.mediumCount +
      scan.lowCount + scan.infoCount;

    if (total === 0) {
      // No findings — save a clean bill of health message immediately
      await prisma.scanJob.update({
        where: { id: scanJobId },
        data: {
          aiSummary:      `Scan of **${target}** completed with no findings detected across ${scan.scanTypes.join(", ")} checks.`,
          aiSummarisedAt: new Date(),
        },
      });
      return;
    }

    // Build severity summary line
    const sevParts: string[] = [];
    if (scan.criticalCount) sevParts.push(`${scan.criticalCount} critical`);
    if (scan.highCount)     sevParts.push(`${scan.highCount} high`);
    if (scan.mediumCount)   sevParts.push(`${scan.mediumCount} medium`);
    if (scan.lowCount)      sevParts.push(`${scan.lowCount} low`);
    const sevLine = sevParts.join(", ");

    // Top findings list
    const topList = scan.findings
      .slice(0, 5)
      .map((f) => `- [${f.severity}] ${f.title}${f.cveId ? ` (${f.cveId})` : ""} via ${f.scanType}`)
      .join("\n");

    const prompt = `You are a security analyst. Summarise this scan result in exactly 2-3 sentences for an engineering manager. Be specific about the most important risks. Do not use bullet points — write flowing prose.

Scan target  : ${target}
Scan types   : ${scan.scanTypes.join(", ")}
Total findings: ${total} (${sevLine})
Top findings :
${topList}

Write your 2-3 sentence summary now:`;

    const resp = await axios.post(
      `${config.OLLAMA_URL}/api/generate`,
      {
        model:  config.OLLAMA_MODEL,
        prompt,
        stream: false,
        options: { temperature: 0.2, num_predict: 200, num_ctx: 1024 },
      },
      { timeout: 300_000 },
    );

    const summary: string = ((resp.data as { response?: string }).response ?? "").trim();

    if (summary) {
      await prisma.scanJob.update({
        where: { id: scanJobId },
        data: { aiSummary: summary, aiSummarisedAt: new Date() },
      });
      logger.info(`[scanSummary] generated for scan ${scanJobId}`);
    }
  } catch (err) {
    // Non-fatal — log and move on; the scan result is not affected
    logger.warn(`[scanSummary] failed for scan ${scanJobId}: ${(err as Error).message}`);
  }
}
