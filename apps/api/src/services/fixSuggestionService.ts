/**
 * AI Fix Suggestion Service
 *
 * Generates a GitHub-style unified diff (or config patch) that fixes
 * the security vulnerability described by a Finding.
 *
 * Adapts the prompt based on scan type:
 *   SAST / SECRET / IAC  → uses code snippet captured at scan time (no auth needed)
 *   SCA  / CONTAINER     → dependency version bump diff
 *   DAST / PENTEST       → server-side code or config patch
 *
 * Result is cached in Finding.aiFixSuggestion / Finding.aiFixSuggestedAt.
 */

import axios from "axios";
import prisma from "../db.js";
import { config } from "../config.js";
import { logger } from "../logger.js";

// ── rawOutput fallback extractors ─────────────────────────────────────────────

/**
 * Try to extract a useful code snippet from the scanner's raw JSON output.
 * Used only when GitHub fetch is unavailable or skipped.
 */
function extractFromRawOutput(
  rawOutput: unknown,
  scanType:  string,
  lineStart: number | null,
): string | null {
  if (!rawOutput || typeof rawOutput !== "object") return null;
  const raw = rawOutput as Record<string, unknown>;

  if (scanType === "SAST") {
    // Merged SAST findings wrap the original Semgrep item under raw["primary"].
    // Non-merged findings keep the Semgrep item at the top level.
    const semgrepItem = (raw["merged"] === true
      ? raw["primary"] as Record<string, unknown> | undefined
      : raw) ?? raw;

    // Semgrep stores the matching line(s) in extra.lines
    const extra = semgrepItem["extra"] as Record<string, unknown> | undefined;
    if (typeof extra?.["lines"] === "string" && extra["lines"].trim()) {
      return extra["lines"].trim();
    }

    // Second fallback: first location snippet stored in merged rawOutput.locations
    const locations = raw["locations"] as Array<{ snippet?: string | null }> | undefined;
    const locSnippet = Array.isArray(locations)
      ? locations.find((l) => l.snippet)?.snippet ?? null
      : null;
    if (locSnippet) return locSnippet;
  }

  if (scanType === "IAC") {
    // Checkov: code_block is [[lineNo, "content\n"], ...]
    const codeBlock = raw["code_block"];
    if (Array.isArray(codeBlock) && codeBlock.length > 0) {
      return (codeBlock as Array<[number, string]>)
        .map(([no, content]) => `${no}: ${content.replace(/\n$/, "")}`)
        .join("\n");
    }
    // Fallback: surface the resource name so the AI has something to work with
    if (raw["resource"]) return `Resource: ${String(raw["resource"])}`;
  }

  if (scanType === "SECRET") {
    // Never expose the actual raw secret — just confirm what was detected
    const detector = raw["DetectorName"] ?? raw["DetectorType"] ?? "unknown";
    const verified  = raw["Verified"] ? "verified" : "unverified";
    return `[${verified} ${detector} credential detected at line ${lineStart ?? "?"}]`;
  }

  return null;
}

// ── Snippet cleaners ──────────────────────────────────────────────────────────

/**
 * Semgrep prefixes every line in extra.lines with its line number:
 *   "42:     eval(user_input)\n43:     return result"
 *
 * Passing these raw to the LLM causes two problems:
 *   1. The model treats "42" as relative-line-1 and generates @@ -1,… hunks
 *   2. The "N:" prefix ends up inside the +/- lines of the generated diff
 *
 * This function detects and strips those prefixes, returning just the code.
 * We separately embed the absolute line range in the prompt text so the LLM
 * can still generate correct @@ hunk headers.
 */
function stripSemgrepLinePrefixes(snippet: string): string {
  const lines = snippet.split("\n");
  // Only strip when every non-empty line starts with a digit prefix
  const hasNums = lines.every((l) => l.trim() === "" || /^\s*\d+:\s?/.test(l));
  if (!hasNums) return snippet;
  return lines.map((l) => l.replace(/^\s*\d+:\s?/, "")).join("\n");
}

// ── Prompt builders ───────────────────────────────────────────────────────────

function buildPrompt(
  f:         Record<string, unknown>,
  snippet:   string | null,
): string {
  const scanType    = String(f["scanType"] ?? "");
  const title       = String(f["title"] ?? "");
  const description = String(f["description"] ?? "").slice(0, 400);
  const filePath    = f["filePath"] ? String(f["filePath"]) : null;
  const lineStart   = f["lineStart"] ? Number(f["lineStart"]) : null;
  const remediation = f["remediation"] ? String(f["remediation"]).slice(0, 250) : null;
  const pkg         = f["packageName"]    ? String(f["packageName"])    : null;
  const pkgVer      = f["packageVersion"] ? String(f["packageVersion"]) : null;
  const fixVer      = f["fixVersion"]     ? String(f["fixVersion"])     : null;
  const cveId       = f["cveId"]          ? String(f["cveId"])          : null;

  // IAC extras from rawOutput
  const raw = (f["rawOutput"] ?? {}) as Record<string, unknown>;
  const iacResource  = raw["resource"]    ? String(raw["resource"])   : null;
  const iacCheckId   = raw["check_id"]    ? String(raw["check_id"])   : null;
  const iacGuideline = raw["guideline"]   ? String(raw["guideline"])  : null;

  const FORMAT = `Return ONLY a unified diff — no explanation, no markdown fences.
Format exactly:
--- a/<file>
+++ b/<file>
@@ -<line>,<count> +<line>,<count> @@
 context line
-line to remove
+replacement line
 context line`;

  // ── SCA / Container: version bump ────────────────────────────────────────
  if (scanType === "SCA" || scanType === "CONTAINER") {
    const depFile = detectDependencyFile(f);
    return `Fix this vulnerable dependency by bumping to the patched version.

Vulnerability : ${title}${cveId ? ` (${cveId})` : ""}
Package       : ${pkg ?? "unknown"}${pkgVer ? `@${pkgVer}` : ""}
Fix version   : ${fixVer ?? "latest"}
File          : ${filePath ?? depFile}
Description   : ${description}
${remediation ? `Fix hint     : ${remediation}` : ""}

${FORMAT}`;
  }

  // ── IAC: infrastructure-as-code config fix ───────────────────────────────
  if (scanType === "IAC") {
    const file = filePath ?? "main.tf";
    return `Fix this IaC misconfiguration with a minimal change to the Terraform/CloudFormation/Kubernetes config.

Check         : ${iacCheckId ?? title}
Resource      : ${iacResource ?? "see file"}
File          : ${file}
Line          : ${lineStart ?? 1}–${f["lineEnd"] ? Number(f["lineEnd"]) : (lineStart ?? 1)}
Description   : ${description}
${iacGuideline ? `Guideline    : ${iacGuideline}` : ""}
${remediation  ? `Fix hint     : ${remediation}`  : ""}
${snippet      ? `\nCurrent code:\n${snippet}` : "\n(Fix the resource block above.)"}

${FORMAT}`;
  }

  // ── SECRET: hardcoded credential fix ─────────────────────────────────────
  if (scanType === "SECRET") {
    const file = filePath ?? "src/config.js";
    const detector = (raw["DetectorName"] ?? raw["DetectorType"] ?? "credential") as string;
    return `Fix this hardcoded secret by replacing it with a secure alternative (environment variable or secrets manager lookup).

Secret type   : ${detector}
File          : ${file}
Line          : ${lineStart ?? "?"}
Description   : ${description}
${remediation  ? `Fix hint     : ${remediation}` : ""}
${snippet      ? `\nCode context (secret value is redacted):\n${snippet}` : ""}

Remove the hardcoded credential and load it from process.env.<SUITABLE_NAME> or equivalent.

${FORMAT}`;
  }

  // ── SAST: source code vulnerability fix ──────────────────────────────────
  if (scanType === "SAST") {
    const file      = filePath ?? "src/app.js";
    const lineEnd   = f["lineEnd"]  ? Number(f["lineEnd"])  : lineStart;
    // Strip Semgrep's "N: code" line-number prefixes — the LLM must use the
    // absolute line range stated below, not the embedded numbers, when
    // constructing the @@ hunk header.
    const cleanCode = snippet ? stripSemgrepLinePrefixes(snippet) : null;
    return `Fix this security vulnerability with a minimal, targeted code change.

Vulnerability : ${title}
File          : ${file}
Lines         : ${lineStart ?? 1}–${lineEnd ?? lineStart ?? 1}
Description   : ${description}
${remediation  ? `Fix hint     : ${remediation}` : ""}
${cleanCode    ? `\nVulnerable code (starts at line ${lineStart ?? 1}):\n${cleanCode}` : "\n(No code preview available — use the description and line number above.)"}

IMPORTANT:
- Use exactly "--- a/${file}" and "+++ b/${file}" as file headers.
- The @@ hunk must reference the real line numbers shown above (starting at ${lineStart ?? 1}).
- Change only the vulnerable lines. Keep surrounding context lines unchanged.
- Do NOT add explanatory comments or change unrelated code.

${FORMAT}`;
  }

  // ── DAST / PENTEST: server-side code or config ────────────────────────────
  const guessedFile = guessFileFromTitle(title);
  return `Provide a server-side code or configuration fix for this vulnerability.

Vulnerability : ${title}
Description   : ${description}
${remediation ? `Fix hint: ${remediation}` : ""}

Use a realistic filename such as ${guessedFile}.
${FORMAT}`;
}

/** Guess which dependency manifest file is likely based on finding context */
function detectDependencyFile(f: Record<string, unknown>): string {
  const pkg   = String(f["packageName"] ?? "").toLowerCase();
  const title = String(f["title"]       ?? "").toLowerCase();
  if (pkg.includes("pip") || title.includes("python") || title.includes("pypi")) return "requirements.txt";
  if (title.includes("maven") || title.includes("pom"))    return "pom.xml";
  if (title.includes("gradle"))                            return "build.gradle";
  if (title.includes("gem") || title.includes("ruby"))     return "Gemfile";
  if (title.includes("composer") || title.includes("php")) return "composer.json";
  if (title.includes("cargo") || title.includes("rust"))   return "Cargo.toml";
  if (title.includes("go.mod") || title.includes("golang"))return "go.mod";
  return "package.json";
}

/** Guess a reasonable filename from the vulnerability title */
function guessFileFromTitle(title: string): string {
  const t = title.toLowerCase();
  if (t.includes("header") || t.includes("csp") || t.includes("cors")) return "nginx.conf or src/middleware/security.js";
  if (t.includes("sql"))        return "src/db/queries.js";
  if (t.includes("xss"))        return "src/app.js";
  if (t.includes("csrf"))       return "src/middleware/csrf.js";
  if (t.includes("auth"))       return "src/auth/index.js";
  if (t.includes("tls") || t.includes("ssl") || t.includes("cert")) return "nginx.conf";
  if (t.includes("redirect"))   return "src/routes/index.js";
  return "src/app/security.js";
}

// ── Core function ─────────────────────────────────────────────────────────────

export async function generateFixSuggestion(
  findingId: string,
  force = false,
): Promise<string> {
  const finding = await prisma.finding.findUniqueOrThrow({ where: { id: findingId } });

  if (!force && finding.aiFixSuggestion) {
    logger.info(`[fix] returning cached fix suggestion for finding ${findingId}`);
    return finding.aiFixSuggestion;
  }

  const f = finding as unknown as Record<string, unknown>;

  // ── Use scan-time stored code snippet (no external auth needed) ───────────
  let snippet: string | null = null;
  if (["SAST", "IAC", "SECRET"].includes(finding.scanType)) {
    snippet = extractFromRawOutput(finding.rawOutput, finding.scanType, finding.lineStart);
    // Also check the codeSnippet field stored directly on the finding
    if (!snippet && finding.codeSnippet) snippet = finding.codeSnippet;
    logger.info(`[fix] code context for ${findingId}: ${snippet ? "stored snippet" : "description only"}`);
  }

  const prompt = buildPrompt(f, snippet);
  logger.info(`[fix] generating fix for ${findingId} (${finding.scanType})`);

  let raw: string;
  try {
    const resp = await axios.post(
      `${config.OLLAMA_URL}/api/generate`,
      {
        model:  config.OLLAMA_MODEL,
        prompt,
        stream: false,
        options: { temperature: 0.15, num_predict: 1024, num_ctx: 4096 },
      },
      { timeout: 300_000 },
    );
    raw = ((resp.data as { response?: string }).response ?? "").trim();
  } catch (err: unknown) {
    const msg = err instanceof Error ? err.message : String(err);
    logger.error(`[fix] ollama request failed: ${msg}`);
    throw new Error(`AI service unavailable: ${msg}`);
  }

  if (!raw) throw new Error("AI returned an empty response — please try again.");

  // Strip any accidental markdown fences the model might add
  const cleaned = raw
    .replace(/^```(?:diff|patch)?\n?/m, "")
    .replace(/\n?```$/m, "")
    .trim();

  await prisma.finding.update({
    where: { id: findingId },
    data: { aiFixSuggestion: cleaned, aiFixSuggestedAt: new Date() },
  });

  logger.info(`[fix] fix suggestion cached for finding ${findingId}`);
  return cleaned;
}
