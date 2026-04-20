/**
 * AI False Positive Detection Service
 *
 * Analyses a security finding and assesses whether it's a false positive,
 * using scan-type-aware heuristics fed to Ollama (local CPU inference).
 *
 * Results are cached on Finding.aiFpAnalysis / Finding.aiFpAnalysedAt.
 * Pass force=true to regenerate the cached result.
 */

import axios from "axios";
import prisma from "../db.js";
import { logger } from "../logger.js";
import { config } from "../config.js";

// ── Types ─────────────────────────────────────────────────────────────────────

export type FpVerdict   = "LIKELY_FP" | "LIKELY_REAL" | "UNCERTAIN";
export type FpConfidence = "HIGH" | "MEDIUM" | "LOW";

export interface FpAnalysis {
  verdict:    FpVerdict;
  confidence: FpConfidence;
  reasoning:  string;      // 2-3 sentence explanation
  indicators: string[];    // concrete evidence items
}

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
  logger.info(`[fp] generating FP analysis for finding ${findingId} (${finding.scanType})`);

  // ── Call Ollama ─────────────────────────────────────────────────────────────
  let rawContent: string;
  try {
    const resp = await axios.post(
      `${config.OLLAMA_URL}/api/chat`,
      {
        model:   config.OLLAMA_MODEL,
        messages: [
          { role: "system", content: SYSTEM_PROMPT },
          { role: "user",   content: prompt },
        ],
        stream:  false,
        format:  "json",
        options: { temperature: 0.1, num_predict: 300, num_ctx: 1024 },
      },
      { timeout: 180_000 },
    );

    rawContent = (resp.data?.message?.content ?? resp.data?.response ?? "") as string;
  } catch (err: unknown) {
    const msg = err instanceof Error ? err.message : String(err);
    logger.error(`[fp] ollama request failed: ${msg}`);
    throw new Error(`AI service unavailable: ${msg}`);
  }

  // ── Parse & validate ────────────────────────────────────────────────────────
  let analysis: FpAnalysis;
  try {
    analysis = JSON.parse(rawContent) as FpAnalysis;

    if (
      !["LIKELY_FP", "LIKELY_REAL", "UNCERTAIN"].includes(analysis.verdict)    ||
      !["HIGH", "MEDIUM", "LOW"].includes(analysis.confidence)                  ||
      typeof analysis.reasoning !== "string"                                    ||
      !Array.isArray(analysis.indicators)
    ) {
      throw new Error("schema mismatch");
    }

    // Normalise — ensure indicators is always a non-empty array
    analysis.indicators = analysis.indicators.slice(0, 4).filter(
      (i): i is string => typeof i === "string",
    );
    if (analysis.indicators.length === 0) {
      analysis.indicators = [analysis.reasoning.split(".")[0] ?? "see reasoning"];
    }
  } catch {
    logger.error(`[fp] unparseable response: ${rawContent.slice(0, 300)}`);
    throw new Error("AI returned an unreadable response — please try again.");
  }

  // ── Cache in DB ─────────────────────────────────────────────────────────────
  await prisma.finding.update({
    where: { id: findingId },
    data: {
      aiFpAnalysis:   analysis as object,
      aiFpAnalysedAt: new Date(),
    },
  });

  logger.info(`[fp] FP analysis cached for finding ${findingId}: ${analysis.verdict} (${analysis.confidence})`);
  return analysis;
}
