/**
 * AI Security Report Service (Phase 5)
 *
 * Generates a full-org security report as streamed markdown.
 * Sections: Executive Summary, Finding Overview, Top Risks, Remediation Roadmap.
 */

import axios from "axios";
import prisma from "../db.js";
import { config } from "../config.js";
import { logger } from "../logger.js";

// ── Report context builder ─────────────────────────────────────────────────────

async function buildReportContext(orgId: string): Promise<string> {
  const [sevCounts, typeCounts, statusCounts, topFindings, repos, containers, domains] =
    await Promise.all([
      prisma.finding.groupBy({ by: ["severity"], where: { orgId }, _count: true }),
      prisma.finding.groupBy({ by: ["scanType"], where: { orgId, status: "OPEN" }, _count: true }),
      prisma.finding.groupBy({ by: ["status"], where: { orgId }, _count: true }),
      prisma.finding.findMany({
        where: { orgId, status: "OPEN", severity: { in: ["CRITICAL", "HIGH"] } },
        orderBy: [{ severity: "asc" }, { firstSeen: "desc" }],
        take: 10,
        select: {
          title: true, severity: true, scanType: true, cveId: true,
          repository: { select: { fullName: true } },
          container:  { select: { imageRef: true } },
          domain:     { select: { domain: true } },
        },
      }),
      prisma.repository.findMany({
        where: { orgId },
        select: { fullName: true, aiRiskScore: true, aiRiskReason: true },
        orderBy: { aiRiskScore: "desc" },
        take: 5,
      }),
      prisma.container.findMany({
        where: { orgId },
        select: { imageRef: true, aiRiskScore: true, aiRiskReason: true },
        orderBy: { aiRiskScore: "desc" },
        take: 5,
      }),
      prisma.domain.findMany({
        where: { orgId },
        select: { domain: true, aiRiskScore: true, aiRiskReason: true },
        orderBy: { aiRiskScore: "desc" },
        take: 5,
      }),
    ]);

  const sevMap: Record<string, number> = {};
  for (const s of sevCounts) sevMap[s.severity] = s._count;
  const statusMap: Record<string, number> = {};
  for (const s of statusCounts) statusMap[s.status] = s._count;

  const total = Object.values(sevMap).reduce((a, b) => a + b, 0);
  const open  = statusMap["OPEN"] ?? 0;

  const topList = topFindings
    .map((f) => {
      const t = f.repository?.fullName ?? f.container?.imageRef ?? f.domain?.domain ?? "unknown";
      return `  - [${f.severity}] ${f.title}${f.cveId ? ` (${f.cveId})` : ""} | ${f.scanType} | ${t}`;
    })
    .join("\n");

  const riskTargets = [
    ...repos.filter((r) => r.aiRiskScore != null).map((r) => `  - Repo ${r.fullName}: score ${r.aiRiskScore} — ${r.aiRiskReason ?? ""}`),
    ...containers.filter((c) => c.aiRiskScore != null).map((c) => `  - Container ${c.imageRef}: score ${c.aiRiskScore} — ${c.aiRiskReason ?? ""}`),
    ...domains.filter((d) => d.aiRiskScore != null).map((d) => `  - Domain ${d.domain}: score ${d.aiRiskScore} — ${d.aiRiskReason ?? ""}`),
  ].join("\n") || "  No AI risk scores available yet.";

  const byType = typeCounts.map((t) => `${t.scanType}: ${t._count}`).join(", ");

  return `=== SECURITY DATA ===
Total findings: ${total} | Open: ${open}
By severity: CRITICAL=${sevMap["CRITICAL"] ?? 0}, HIGH=${sevMap["HIGH"] ?? 0}, MEDIUM=${sevMap["MEDIUM"] ?? 0}, LOW=${sevMap["LOW"] ?? 0}
By scan type (open): ${byType || "none"}
By status: ${Object.entries(statusMap).map(([k, v]) => `${k}=${v}`).join(", ")}

TOP CRITICAL/HIGH OPEN FINDINGS:
${topList || "  None"}

HIGHEST RISK TARGETS:
${riskTargets}`;
}

// ── Streaming report generator ─────────────────────────────────────────────────

export async function streamSecurityReport(
  orgId:    string,
  onToken:  (token: string) => void,
  onDone:   () => void,
  onError:  (err: Error) => void,
): Promise<void> {
  let context: string;
  try {
    context = await buildReportContext(orgId);
  } catch (err) {
    onError(new Error(`Failed to build report context: ${(err as Error).message}`));
    return;
  }

  const today = new Date().toISOString().split("T")[0];

  const prompt = `${context}

=== INSTRUCTIONS ===
You are a senior security analyst. Write a professional security report in markdown for the data above.
Date: ${today}

Use exactly these sections with these headings:
## Executive Summary
(2-3 sentences covering overall posture, total findings, top risk)

## Finding Overview
(table or bullet breakdown by severity and scan type)

## Top Risks
(numbered list of the 5 most critical issues with impact and affected target)

## Remediation Roadmap
(3 prioritised action items with timeframe: Immediate / 30 days / 90 days)

Write the full report now:`;

  logger.info(`[report] generating security report for org ${orgId}`);

  try {
    const resp = await axios.post(
      `${config.OLLAMA_URL}/api/generate`,
      {
        model:  config.OLLAMA_MODEL,
        prompt,
        stream: true,
        options: { temperature: 0.2, num_predict: 800, num_ctx: 2048 },
      },
      { responseType: "stream", timeout: 600_000 },
    );

    const stream = resp.data as NodeJS.ReadableStream;
    let finished = false;

    stream.on("data", (chunk: Buffer) => {
      for (const line of chunk.toString().split("\n")) {
        const trimmed = line.trim();
        if (!trimmed) continue;
        try {
          const parsed = JSON.parse(trimmed) as { response?: string; done?: boolean };
          if (parsed.response) onToken(parsed.response);
          if (parsed.done && !finished) { finished = true; onDone(); }
        } catch { /* partial chunk */ }
      }
    });

    stream.on("end",   () => { if (!finished) { finished = true; onDone(); } });
    stream.on("error", (err: Error) => { if (!finished) { finished = true; onError(err); } });
  } catch (err: unknown) {
    const msg = err instanceof Error ? err.message : String(err);
    logger.error(`[report] ollama request failed: ${msg}`);
    onError(new Error(`AI service unavailable: ${msg}`));
  }
}
