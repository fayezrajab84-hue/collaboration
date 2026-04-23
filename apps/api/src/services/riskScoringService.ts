/**
 * AI Risk Scoring Service (Phase 3)
 *
 * Generates a 0-100 risk score + one-sentence reason for a target
 * (repository, container, or domain) based on its open findings.
 * Runs as a fire-and-forget after scan completion.
 */

import { z } from "zod";
import { AIServiceName } from "@prisma/client";
import prisma from "../db.js";
import { logger } from "../logger.js";
import { invokeAI, AIError } from "./aiClient.js";
import type { TargetType } from "@devsecops/types";

const riskSchema = z.object({
  score:  z.number(),
  reason: z.string().optional(),
});

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

    const { name: targetName, orgId } = await getTargetInfo(targetType, targetId);
    if (!orgId) {
      logger.warn(`[riskScore] no orgId for ${targetType} ${targetId} — skipping`);
      return;
    }

    const SYSTEM = `You are a security analyst. Score targets' risk from 0 to 100.
Scoring guide: 0=no findings, 1-20=only info/low, 21-40=some medium, 41-60=high severity present, 61-80=multiple high or one critical, 81-100=multiple critical.
Respond ONLY with valid JSON: {"score": <integer 0-100>, "reason": "<one sentence>"}`;

    const prompt = `Target: ${targetName}
Severity summary: ${counts.CRITICAL} CRITICAL, ${counts.HIGH} HIGH, ${counts.MEDIUM} MEDIUM, ${counts.LOW} LOW, ${counts.INFO} INFO (${total} total)
Worst findings:
${topFindings}

JSON:`;

    let parsed: { score?: number; reason?: string };
    try {
      const result = await invokeAI({
        service:         AIServiceName.RISK_SCORE,
        orgId,
        system:          SYSTEM,
        messages:        [{ role: "user", content: prompt }],
        schema:          riskSchema,
        maxOutputTokens: 120,
        temperature:     0.1,
        timeoutMs:       300_000,
      });
      parsed = result.data;
    } catch (err) {
      if (err instanceof AIError) {
        logger.warn(`[riskScore] invokeAI failed for ${targetType} ${targetId}: ${err.kind} — ${err.message}`);
        return;
      }
      throw err;
    }

    const score  = Math.min(100, Math.max(0, Math.round(parsed.score ?? 0)));
    const reason = (parsed.reason ?? "").trim() || `${counts.CRITICAL} critical and ${counts.HIGH} high severity findings detected.`;

    await saveScore(targetType, targetId, score, reason);
    logger.info(`[riskScore] ${targetType} ${targetId} → ${score} (${riskLabel(score)})`);
  } catch (err) {
    logger.warn(`[riskScore] failed for ${targetType} ${targetId}: ${(err as Error).message}`);
  }
}

// ── Helpers ───────────────────────────────────────────────────────────────────

async function getTargetInfo(
  targetType: TargetType,
  targetId:   string,
): Promise<{ name: string; orgId: string | null }> {
  if (targetType === "REPOSITORY") {
    const r = await prisma.repository.findUnique({
      where: { id: targetId }, select: { fullName: true, orgId: true },
    });
    return { name: r?.fullName ?? targetId, orgId: r?.orgId ?? null };
  }
  if (targetType === "CONTAINER") {
    const c = await prisma.container.findUnique({
      where: { id: targetId }, select: { imageRef: true, orgId: true },
    });
    return { name: c?.imageRef ?? targetId, orgId: c?.orgId ?? null };
  }
  const d = await prisma.domain.findUnique({
    where: { id: targetId }, select: { domain: true, orgId: true },
  });
  return { name: d?.domain ?? targetId, orgId: d?.orgId ?? null };
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
