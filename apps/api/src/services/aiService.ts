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

import { z } from "zod";
import { AIServiceName } from "@prisma/client";
import prisma from "../db.js";
import { logger } from "../logger.js";
import { invokeAI, AIError } from "./aiClient.js";

// ── Types ─────────────────────────────────────────────────────────────────────

export interface AIAnalysis {
  summary:      string;
  impact:       string;
  remediation:  string[];
  risk_context: string;
}

// Zod schema enforces the contract at parse time — invokeAI runs this against
// the provider's structured-output response and throws AIError(INVALID_OUTPUT)
// on mismatch, which the caller already maps to a friendly message.
const analysisSchema = z.object({
  summary:      z.string(),
  impact:       z.string(),
  remediation:  z.array(z.string()),
  risk_context: z.string(),
});

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

const REQUIRES_LOGIN = /^requires?\s+login$/i;

/** Extract the best available code snippet for a finding (SAST/IAC/SECRET). */
function extractSnippet(finding: Record<string, unknown>): string | null {
  // Direct codeSnippet column (cleaned, no N: prefixes)
  if (typeof finding["codeSnippet"] === "string" && (finding["codeSnippet"] as string).trim()) {
    const s = (finding["codeSnippet"] as string).trim();
    if (!REQUIRES_LOGIN.test(s)) return s.slice(0, 600);
  }

  const raw = finding["rawOutput"] as Record<string, unknown> | null;
  if (!raw) return null;

  if (finding["scanType"] === "SAST") {
    // Prefer per-location snippets from the backfill (most accurate per-hit code)
    const locs = raw["locations"] as Array<{ snippet?: string | null }> | undefined;
    if (Array.isArray(locs)) {
      const locSnippet = locs.find((l) => l.snippet && !REQUIRES_LOGIN.test((l.snippet as string).trim()))?.snippet;
      if (locSnippet) return (locSnippet as string).slice(0, 600);
    }
    // Fallback: Semgrep extra.lines (non-Pro rules)
    const semgrepItem = (raw["merged"] === true ? raw["primary"] : raw) as Record<string, unknown> | undefined ?? raw;
    const extraLines = (semgrepItem["extra"] as Record<string, unknown> | undefined)?.["lines"];
    if (typeof extraLines === "string" && extraLines.trim() && !REQUIRES_LOGIN.test(extraLines.trim())) {
      return extraLines.trim().slice(0, 600);
    }
  }

  if (finding["scanType"] === "IAC") {
    // Merged IAC: use the first resource's snippet (clean, stored at scan time)
    if (raw["merged"] === true) {
      const resources = raw["resources"] as Array<{ snippet?: string | null }> | undefined;
      if (Array.isArray(resources)) {
        const rs = resources.find((r) => r.snippet);
        if (rs?.snippet) return (rs.snippet as string).slice(0, 600);
      }
      // Fall through to primary.code_block
    }
    // Non-merged or primary code_block fallback
    const src = (raw["merged"] === true ? raw["primary"] : raw) as Record<string, unknown> | undefined ?? raw;
    const codeBlock = src["code_block"];
    if (Array.isArray(codeBlock)) {
      return (codeBlock as Array<[number, string]>)
        .map(([no, content]) => `${no}: ${content.replace(/\n$/, "")}`)
        .join("\n")
        .slice(0, 600);
    }
  }

  if (finding["scanType"] === "SECRET") {
    // Show context lines from the first occurrence but redact the secret value —
    // the LLM needs file context to give concrete advice, but must never see the raw credential.
    const occs = raw["occurrences"] as Array<{ snippet?: string | null; lineStart?: number | null }> | undefined;
    const firstWithSnippet = Array.isArray(occs) ? occs.find((o) => o.snippet) : null;
    if (firstWithSnippet?.snippet) {
      const snippet   = firstWithSnippet.snippet;
      const lineStart = firstWithSnippet.lineStart ?? null;
      // Redact the secret line (same logic as the UI)
      const lines     = snippet.split("\n");
      const secretIdx = lineStart != null ? Math.min(2, lineStart - 1) : 2;
      const redacted  = lines
        .map((line, idx) => {
          if (idx !== secretIdx) return line;
          return line
            .replace(/eyJ[A-Za-z0-9_-]{10,}(?:\.[A-Za-z0-9_-]{10,}){1,2}/g, "eyJ[REDACTED]")
            .replace(/AKIA[A-Z0-9]{16}/g, "AKIA[REDACTED]")
            .replace(/([:=]\s*["'`]?)([A-Za-z0-9+/=_\-]{20,})(["'`]?)/g, "$1[REDACTED]$3")
            .replace(/\b([A-Za-z0-9+/=_\-]{30,})\b/g, "[REDACTED]");
        })
        .join("\n");
      return redacted.slice(0, 600);
    }
  }

  return null;
}

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

  // Include code snippet when available — helps the LLM give concrete advice
  const snippet = extractSnippet(finding);
  if (snippet) {
    lines.push(`\nVulnerable code:\n\`\`\`\n${snippet}\n\`\`\``);
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
  logger.info(`[ai] generating analysis for finding ${findingId} via aiClient`);

  // ── Route through the multi-provider client ────────────────────────────────
  // Routing precedence (from aiClient): per-service routing override → org
  // default provider → synthetic Ollama fallback. Schema validation happens
  // inside invokeAI; on mismatch we get AIError(INVALID_OUTPUT).
  let analysis: AIAnalysis;
  try {
    const result = await invokeAI({
      service:         AIServiceName.ANALYSE_FINDING,
      orgId:           finding.orgId,
      system:          SYSTEM_PROMPT,
      messages:        [{ role: "user", content: prompt }],
      schema:          analysisSchema,
      maxOutputTokens: 900,
      temperature:     0.1,
      findingId,
    });
    analysis = result.data;
  } catch (err) {
    if (err instanceof AIError) {
      logger.error(`[ai] invokeAI failed for finding ${findingId}: ${err.kind} — ${err.message}`);
      if (err.kind === "INVALID_OUTPUT") {
        throw new Error("AI returned an unreadable response — please try again.");
      }
      throw new Error(
        `AI service is unavailable (${err.kind}). Check that the configured provider is reachable. (${err.message})`,
      );
    }
    throw err;
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
