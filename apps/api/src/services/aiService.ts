/**
 * AI Analysis Service — powered by Ollama (offline, CPU-friendly).
 *
 * Generates a structured security analysis for any Finding:
 *   - Plain-English summary of the vulnerability
 *   - Business impact (what an attacker can do)
 *   - Step-by-step remediation
 *   - Risk context (prevalence, conditions, known exploits)
 *
 * Results are cached on the Finding record (aiAnalysis / aiAnalysedAt)
 * so repeated opens of the same finding are instant.
 */

import axios from "axios";
import prisma from "../db.js";
import { logger } from "../logger.js";
import { config } from "../config.js";

// ── Types ─────────────────────────────────────────────────────────────────────

export interface AIAnalysis {
  summary:      string;
  impact:       string;
  remediation:  string[];
  risk_context: string;
}

// ── Prompt ────────────────────────────────────────────────────────────────────

const SYSTEM_PROMPT = `You are an expert cybersecurity analyst and developer advocate.
Analyse the security finding below and respond ONLY with a valid JSON object — no markdown fences, no explanation outside the JSON.

Required schema (all fields mandatory):
{
  "summary":      "2-3 sentence plain-English explanation of what this vulnerability is and how it arises",
  "impact":       "What a real attacker could do if they exploited this — be specific and practical",
  "remediation":  ["Concrete actionable step 1", "Concrete actionable step 2", "Concrete actionable step 3"],
  "risk_context": "How common is this issue, what conditions make it exploitable, any known CVEs or real-world exploits"
}`;

function buildPrompt(finding: Record<string, unknown>): string {
  const lines: string[] = [
    `Title: ${finding["title"]}`,
    `Severity: ${finding["severity"]}`,
    `Scan Type: ${finding["scanType"]}`,
    `Scanner: ${finding["scanner"]}`,
    `Rule ID: ${finding["ruleId"] ?? "N/A"}`,
    `Description: ${finding["description"]}`,
  ];

  if (finding["filePath"])      lines.push(`File: ${finding["filePath"]}`);
  if (finding["lineStart"])     lines.push(`Line: ${finding["lineStart"]}`);
  if (finding["cveId"])         lines.push(`CVE: ${finding["cveId"]}`);
  if (finding["cweId"])         lines.push(`CWE: ${finding["cweId"]}`);
  if (finding["packageName"])   lines.push(`Package: ${finding["packageName"]}@${finding["packageVersion"] ?? "unknown"}`);
  if (finding["fixVersion"])    lines.push(`Fix available in: ${finding["fixVersion"]}`);
  if (finding["cvssScore"])     lines.push(`CVSS Score: ${finding["cvssScore"]}`);
  if (finding["remediation"])   lines.push(`Existing remediation hint: ${String(finding["remediation"]).slice(0, 300)}`);

  const refs = finding["references"];
  if (Array.isArray(refs) && refs.length > 0) {
    lines.push(`References: ${(refs as string[]).slice(0, 3).join(", ")}`);
  }

  return lines.join("\n");
}

// ── Core function ─────────────────────────────────────────────────────────────

export async function analyseFinding(
  findingId: string,
  force = false,
): Promise<AIAnalysis> {
  const finding = await prisma.finding.findUniqueOrThrow({ where: { id: findingId } });

  // Return cached result unless a forced refresh is requested
  if (!force && finding.aiAnalysis) {
    logger.info(`[ai] returning cached analysis for finding ${findingId}`);
    return finding.aiAnalysis as unknown as AIAnalysis;
  }

  const prompt = buildPrompt(finding as unknown as Record<string, unknown>);
  logger.info(`[ai] generating analysis for finding ${findingId} (model: ${config.OLLAMA_MODEL})`);

  // ── Call Ollama ─────────────────────────────────────────────────────────────
  let rawContent: string;
  try {
    const resp = await axios.post(
      `${config.OLLAMA_URL}/api/chat`,
      {
        model:    config.OLLAMA_MODEL,
        messages: [
          { role: "system", content: SYSTEM_PROMPT },
          { role: "user",   content: prompt },
        ],
        stream:  false,
        format:  "json",   // Ollama enforces JSON-mode output
        options: {
          temperature: 0.1,  // low temp = deterministic, factual
          num_predict:  800,
          num_ctx:     2048,
        },
      },
      { timeout: 360_000 },  // 6 min — CPU inference can be slow
    );

    rawContent = (resp.data?.message?.content ?? resp.data?.response ?? "") as string;
  } catch (err: unknown) {
    const msg = err instanceof Error ? err.message : String(err);
    logger.error(`[ai] ollama request failed: ${msg}`);
    throw new Error(
      `AI service is unavailable. Make sure the Ollama container is running and the model has finished downloading. (${msg})`,
    );
  }

  // ── Parse & validate ────────────────────────────────────────────────────────
  let analysis: AIAnalysis;
  try {
    analysis = JSON.parse(rawContent) as AIAnalysis;

    if (
      typeof analysis.summary      !== "string" ||
      typeof analysis.impact       !== "string" ||
      !Array.isArray(analysis.remediation)       ||
      typeof analysis.risk_context !== "string"
    ) {
      throw new Error("schema mismatch");
    }
  } catch {
    logger.error(`[ai] unparseable response (first 300 chars): ${rawContent.slice(0, 300)}`);
    throw new Error("AI returned an unreadable response — please try again.");
  }

  // ── Cache in DB ─────────────────────────────────────────────────────────────
  await prisma.finding.update({
    where: { id: findingId },
    data: {
      aiAnalysis:   analysis as object,
      aiAnalysedAt: new Date(),
    },
  });

  logger.info(`[ai] analysis cached for finding ${findingId}`);
  return analysis;
}
