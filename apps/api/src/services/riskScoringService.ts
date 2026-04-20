/**
 * AI Risk Scoring Service (Phase 3)
 *
 * Generates a 0-100 risk score + one-sentence reason for a target
 * (repository, container, or domain) based on its open findings.
 * Runs as a fire-and-forget after scan completion.
 */

import axios from "axios";
import prisma from "../db.js";
import { config } from "../config.js";
import { logger } from "../logger.js";
import type { TargetType } from "@devsecops/types";

// ── Score helpers ─────────────────────────────────────────────────────────────

export function riskLabel(score: number): string {
  if (score >= 80) return "CRITICAL";
  if (score >= 60) return "HIGH";
  if (score >= 35) return "MEDIUM";
  return "LOW";
}

// ── Main scorer ───────────────────────────────────────────────────────────────

export async function scoreTarget(
  targetType: TargetType,
  targetId:   string,
): Promise<void> {
  try {
    // Fetch open findings for this target
    const findings = await prisma.finding.findMany({
      where: {
        targetType,
        [`${targetType === "REPOSITORY" ? "repositoryId" : targetType === "CONTAINER" ? "containerId" : "domainId"}`]: targetId,
        status: { in: ["OPEN", "ACKNOWLEDGED"] },
      },
      select: { severity: true, title: true, scanType: true, cveId: true },
    });

    // Count by severity
    const counts = { CRITICAL: 0, HIGH: 0, MEDIUM: 0, LOW: 0, INFO: 0 };
    for (const f of findings) {
      counts[f.severity as keyof typeof counts] =
        (counts[f.severity as keyof typeof counts] ?? 0) + 1;
    }
    const total = findings.length;

    // Fast-path: no findings → score 0
    if (total === 0) {
      await saveScore(targetType, targetId, 0, "No open findings detected.");
      return;
    }

    // Sort by severity (CRITICAL first) so the model sees the worst findings
    const SEV_ORDER: Record<string, number> = { CRITICAL: 0, HIGH: 1, MEDIUM: 2, LOW: 3, INFO: 4 };
    const sorted = [...findings].sort(
      (a, b) => (SEV_ORDER[a.severity] ?? 99) - (SEV_ORDER[b.severity] ?? 99),
    );

    // Top 8 worst findings for context
    const topFindings = sorted
      .slice(0, 8)
      .map((f) => `- [${f.severity}] ${f.scanType}: ${f.title}${f.cveId ? ` (${f.cveId})` : ""}`)
      .join("\n");

    const targetName = await getTargetName(targetType, targetId);

    const prompt = `You are a security analyst. Score this target's risk from 0 to 100.
Scoring guide: 0=no findings, 1-20=only info/low, 21-40=some medium, 41-60=high severity present, 61-80=multiple high or one critical, 81-100=multiple critical.
Respond ONLY with valid JSON: {"score": <integer 0-100>, "reason": "<one sentence>"}

Target: ${targetName}
Severity summary: ${counts.CRITICAL} CRITICAL, ${counts.HIGH} HIGH, ${counts.MEDIUM} MEDIUM, ${counts.LOW} LOW, ${counts.INFO} INFO (${total} total)
Worst findings:
${topFindings}

JSON:`;

    const resp = await axios.post(
      `${config.OLLAMA_URL}/api/generate`,
      {
        model:  config.OLLAMA_MODEL,
        prompt,
        stream: false,
        format: "json",
        options: { temperature: 0.1, num_predict: 120, num_ctx: 2048 },
      },
      { timeout: 300_000 },
    );

    const raw = ((resp.data as { response?: string }).response ?? "").trim();
    const parsed = JSON.parse(raw) as { score?: number; reason?: string };
    const score  = Math.min(100, Math.max(0, Math.round(parsed.score ?? 0)));
    const reason = (parsed.reason ?? "").trim() || `${counts.CRITICAL} critical and ${counts.HIGH} high severity findings detected.`;

    await saveScore(targetType, targetId, score, reason);
    logger.info(`[riskScore] ${targetType} ${targetId} → ${score} (${riskLabel(score)})`);
  } catch (err) {
    logger.warn(`[riskScore] failed for ${targetType} ${targetId}: ${(err as Error).message}`);
  }
}

// ── Helpers ───────────────────────────────────────────────────────────────────

async function getTargetName(targetType: TargetType, targetId: string): Promise<string> {
  if (targetType === "REPOSITORY") {
    const r = await prisma.repository.findUnique({ where: { id: targetId }, select: { fullName: true } });
    return r?.fullName ?? targetId;
  }
  if (targetType === "CONTAINER") {
    const c = await prisma.container.findUnique({ where: { id: targetId }, select: { imageRef: true } });
    return c?.imageRef ?? targetId;
  }
  const d = await prisma.domain.findUnique({ where: { id: targetId }, select: { domain: true } });
  return d?.domain ?? targetId;
}

async function saveScore(
  targetType: TargetType,
  targetId:   string,
  score:      number,
  reason:     string,
): Promise<void> {
  const data = { aiRiskScore: score, aiRiskReason: reason, aiRiskScoredAt: new Date() };
  if (targetType === "REPOSITORY") {
    await prisma.repository.update({ where: { id: targetId }, data });
  } else if (targetType === "CONTAINER") {
    await prisma.container.update({ where: { id: targetId }, data });
  } else {
    await prisma.domain.update({ where: { id: targetId }, data });
  }
}
