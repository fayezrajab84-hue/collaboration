/**
 * AI False Positive Detection Service
 *
 * Analyses a security finding and assesses whether it's a false positive,
 * using scan-type-aware heuristics fed through the multi-provider AI client.
 *
 * Results are cached on Finding.aiFpAnalysis / Finding.aiFpAnalysedAt.
 * Pass force=true to regenerate the cached result.
 */

import { z } from "zod";
import { AIServiceName } from "@prisma/client";
import prisma from "../db.js";
import { logger } from "../logger.js";
import { invokeAI, AIError } from "./aiClient.js";

// ── Types ─────────────────────────────────────────────────────────────────────

export type FpVerdict   = "LIKELY_FP" | "LIKELY_REAL" | "UNCERTAIN";
export type FpConfidence = "HIGH" | "MEDIUM" | "LOW";

export interface FpAnalysis {
  verdict:    FpVerdict;
  confidence: FpConfidence;
  reasoning:  string;      // 2-3 sentence explanation
  indicators: string[];    // concrete evidence items
}

const fpSchema = z.object({
  verdict:    z.enum(["LIKELY_FP", "LIKELY_REAL", "UNCERTAIN"]),
  confidence: z.enum(["HIGH", "MEDIUM", "LOW"]),
  reasoning:  z.string(),
  indicators: z.array(z.string()),
});

// ── Prompt ────────────────────────────────────────────────────────────────────

const SYSTEM_PROMPT = `You are a senior security analyst specialising in false positive triage.
Analyse the finding below and decide if it is a false positive.
Reply ONLY with a valid JSON object — no markdown, no text outside the JSON.

Schema (all fields required):
{
  "verdict":    "LIKELY_FP" | "LIKELY_REAL" | "UNCERTAIN",
  "confidence": "HIGH" | "MEDIUM" | "LOW",
  "reasoning":  "2-3 sentence explanation of your assessment",
  "indicators": ["up to 4 concrete evidence items that support your verdict"]
}

Verdict rules:
- LIKELY_FP  → test/example/mock file, placeholder secret, unreachable code, no real attack surface, compensating control
- LIKELY_REAL → real code path, real credential format, accessible endpoint, no sanitisation, exploitable condition
- UNCERTAIN  → not enough context to decide

Scan-type hints:
- SAST   : Is the file a test/mock/fixture? Is the code path reachable? Is the rule too generic?
- SCA    : Is the vulnerable package actually called at runtime? Is there a patched version in use?
- SECRET : Does the value look like a real secret or a placeholder/example/dummy?
- IAC    : Are there compensating controls that mitigate the flagged misconfiguration?
- DAST / PENTEST : Is the evidence from an actual HTTP response, or a scanner artefact?`;

function buildPrompt(f: Record<string, unknown>): string {
  const lines = [
    `Scan type: ${f["scanType"]}`,
    `Severity: ${f["severity"]}`,
    `Title: ${f["title"]}`,
    `Description: ${String(f["description"]).slice(0, 400)}`,
  ];

  if (f["filePath"])      lines.push(`File: ${f["filePath"]}`);
  if (f["lineStart"])     lines.push(`Line: ${f["lineStart"]}`);
  if (f["ruleId"])        lines.push(`Rule ID: ${f["ruleId"]}`);
  if (f["cveId"])         lines.push(`CVE: ${f["cveId"]}`);
  if (f["packageName"])   lines.push(`Package: ${f["packageName"]}@${f["packageVersion"] ?? "?"}`);
  if (f["fixVersion"])    lines.push(`Fix available: ${f["fixVersion"]}`);
  if (f["remediation"])   lines.push(`Remediation hint: ${String(f["remediation"]).slice(0, 200)}`);

  // Surface the most telling piece of evidence
  const evidence = f["evidence"] as Record<string, unknown> | null;
  if (evidence) {
    const detail = evidence["detail"] ?? evidence["snippet"] ?? evidence["request"];
    if (detail) lines.push(`Evidence: ${String(detail).slice(0, 200)}`);
  }

  return lines.join("\n");
}

// ── Core function ─────────────────────────────────────────────────────────────

export async function checkFalsePositive(
  findingId: string,
  force = false,
): Promise<FpAnalysis> {
  const finding = await prisma.finding.findUniqueOrThrow({ where: { id: findingId } });

  // Return cached result unless forced refresh
  if (!force && finding.aiFpAnalysis) {
    logger.info(`[fp] returning cached FP analysis for finding ${findingId}`);
    return finding.aiFpAnalysis as unknown as FpAnalysis;
  }

  const prompt = buildPrompt(finding as unknown as Record<string, unknown>);
  logger.info(`[fp] generating FP analysis for finding ${findingId} (${finding.scanType}) via aiClient`);

  // ── Call configured AI provider ─────────────────────────────────────────────
  let analysis: FpAnalysis;
  try {
    const result = await invokeAI({
      service:         AIServiceName.FP_TRIAGE,
      orgId:           finding.orgId,
      system:          SYSTEM_PROMPT,
      messages:        [{ role: "user", content: prompt }],
      schema:          fpSchema,
      maxOutputTokens: 300,
      temperature:     0.1,
      findingId,
    });
    analysis = result.data;
  } catch (err) {
    if (err instanceof AIError) {
      logger.error(`[fp] invokeAI failed for finding ${findingId}: ${err.kind} — ${err.message}`);
      if (err.kind === "INVALID_OUTPUT") {
        throw new Error("AI returned an unreadable response — please try again.");
      }
      throw new Error(
        `AI service is unavailable (${err.kind}). Check that the configured provider is reachable. (${err.message})`,
      );
    }
    throw err;
  }

  // Normalise — ensure indicators is always a non-empty array
  analysis.indicators = analysis.indicators.slice(0, 4).filter(
    (i): i is string => typeof i === "string",
  );
  if (analysis.indicators.length === 0) {
    analysis.indicators = [analysis.reasoning.split(".")[0] ?? "see reasoning"];
  }

  // ── Derive confidence override from AI verdict ──────────────────────────────
  // Keep operator-visible Confidence column in sync with AI triage, so the
  // dashboard doesn't contradict the drawer's verdict. Rules:
  //   LIKELY_FP   + HIGH/MED  → POSSIBLE  (demote)
  //   LIKELY_REAL + HIGH      → CONFIRMED (promote, only from LIKELY)
  //   otherwise               → leave as-is
  // Never overwrite CONFIRMED set by the runtime verifier — that is ground truth.
  const current = finding.confidence;
  let nextConfidence: "CONFIRMED" | "LIKELY" | "POSSIBLE" | null = null;

  if (analysis.verdict === "LIKELY_FP" &&
      (analysis.confidence === "HIGH" || analysis.confidence === "MEDIUM") &&
      current !== "CONFIRMED") {
    nextConfidence = "POSSIBLE";
  } else if (analysis.verdict === "LIKELY_REAL" &&
             analysis.confidence === "HIGH" &&
             current === "LIKELY") {
    nextConfidence = "CONFIRMED";
  }

  // ── Cache in DB ─────────────────────────────────────────────────────────────
  await prisma.finding.update({
    where: { id: findingId },
    data: {
      aiFpAnalysis:   analysis as object,
      aiFpAnalysedAt: new Date(),
      ...(nextConfidence && nextConfidence !== current ? { confidence: nextConfidence } : {}),
    },
  });

  if (nextConfidence && nextConfidence !== current) {
    logger.info(
      `[fp] confidence ${current} → ${nextConfidence} for finding ${findingId} ` +
      `(AI: ${analysis.verdict}/${analysis.confidence})`,
    );
  }

  logger.info(`[fp] FP analysis cached for finding ${findingId}: ${analysis.verdict} (${analysis.confidence})`);
  return analysis;
}
