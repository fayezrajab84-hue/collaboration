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

// ── Language detection (mirrors apps/web/src/components/SyntaxHighlight.tsx) ──
// Knowing the language lets the model emit syntactically-correct fixes instead
// of guessing from the snippet alone — a significant accuracy win on small
// snippets where Python and JS look superficially similar.
const EXT_TO_LANG: Record<string, string> = {
  ts: "TypeScript", tsx: "TypeScript (TSX)", js: "JavaScript", jsx: "JavaScript (JSX)",
  mjs: "JavaScript", cjs: "JavaScript",
  py: "Python", pyi: "Python",
  java: "Java", go: "Go", rb: "Ruby", php: "PHP",
  c: "C", h: "C", cpp: "C++", cc: "C++", cxx: "C++",
  cs: "C#",
  yaml: "YAML", yml: "YAML", json: "JSON", jsonc: "JSON", xml: "XML",
  sh: "Bash", bash: "Bash", zsh: "Bash",
  ps1: "PowerShell", psm1: "PowerShell",
  html: "HTML", htm: "HTML", css: "CSS", scss: "SCSS",
  tf: "Terraform (HCL)", tfvars: "Terraform (HCL)", hcl: "HCL",
  sql: "SQL", rs: "Rust", kt: "Kotlin", kts: "Kotlin",
  swift: "Swift", scala: "Scala", groovy: "Groovy", gradle: "Groovy (Gradle)",
  r: "R", lua: "Lua", perl: "Perl", pl: "Perl",
  vue: "Vue.js (SFC)", svelte: "Svelte", toml: "TOML",
  md: "Markdown", dockerfile: "Dockerfile", containerfile: "Dockerfile",
  proto: "Protobuf", dart: "Dart", ex: "Elixir", exs: "Elixir",
  clj: "Clojure", cljs: "ClojureScript", m: "Objective-C", mm: "Objective-C++",
  env: "dotenv", properties: "Java properties", ini: "INI",
};
const BASENAME_TO_LANG: Record<string, string> = {
  dockerfile: "Dockerfile", containerfile: "Dockerfile",
  makefile: "Makefile", jenkinsfile: "Groovy (Jenkinsfile)",
  vagrantfile: "Ruby", gemfile: "Ruby", rakefile: "Ruby",
  procfile: "YAML", caddyfile: "Caddyfile",
};

function detectLanguage(filePath: string | null | undefined): string | null {
  if (!filePath) return null;
  const base = filePath.split(/[\\/]/).pop()?.toLowerCase() ?? "";
  const byBase = BASENAME_TO_LANG[base];
  if (byBase) return byBase;
  const ext = base.includes(".") ? base.split(".").pop() ?? "" : "";
  return EXT_TO_LANG[ext] ?? null;
}

/**
 * A unified diff is only useful if it actually has the structural markers
 * Git/GitHub need to apply it. This rejects:
 *   - hallucinated "here's how you fix it" prose
 *   - markdown-only output
 *   - diffs missing the `--- a/`, `+++ b/`, or `@@ ... @@` markers
 *   - diffs that have no `+` or `-` lines (i.e. nothing changed)
 */
function isValidUnifiedDiff(s: string): boolean {
  if (!s || s.length < 20) return false;
  if (!/^---\s+a\//m.test(s)) return false;
  if (!/^\+\+\+\s+b\//m.test(s)) return false;
  if (!/^@@\s+-\d+(,\d+)?\s+\+\d+(,\d+)?\s+@@/m.test(s)) return false;
  // Must have at least one actual change line (not just context)
  const changes = s.split("\n").filter((l) => /^[+-]/.test(l) && !/^(\+\+\+|---)/.test(l));
  return changes.length > 0;
}

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

    // Semgrep stores the matching line(s) in extra.lines.
    // Discard the Semgrep Pro paywall placeholder — it is useless as code context.
    const extra = semgrepItem["extra"] as Record<string, unknown> | undefined;
    const rawLines = typeof extra?.["lines"] === "string" ? (extra["lines"] as string).trim() : "";
    if (rawLines && !/^requires?\s+login$/i.test(rawLines)) {
      return rawLines;
    }

    // Second fallback: first non-empty location snippet (backfilled from GitHub).
    // This is the primary source after the backfillSastLocationSnippets migration.
    const locations = raw["locations"] as Array<{ snippet?: string | null }> | undefined;
    const locSnippet = Array.isArray(locations)
      ? (locations.find((l) => l.snippet && !/^requires?\s+login$/i.test((l.snippet as string).trim()))?.snippet ?? null)
      : null;
    if (locSnippet) return locSnippet;
  }

  if (scanType === "IAC") {
    // Merged IAC: use the first resource's stored snippet (clean code, no N: prefixes)
    if (raw["merged"] === true) {
      const resources = raw["resources"] as Array<{ snippet?: string | null; resource?: string | null }> | undefined;
      if (Array.isArray(resources)) {
        const rs = resources.find((r) => r.snippet);
        if (rs?.snippet) return rs.snippet;
        // No snippet — at least surface the resource name
        const firstResource = resources[0]?.resource;
        if (firstResource) return `Resource: ${firstResource}`;
      }
    }
    // Non-merged: Checkov code_block is [[lineNo, "content\n"], ...]
    const src = (raw["merged"] === true ? raw["primary"] : raw) as Record<string, unknown> | undefined ?? raw;
    const codeBlock = src["code_block"];
    if (Array.isArray(codeBlock) && codeBlock.length > 0) {
      return (codeBlock as Array<[number, string]>)
        .map(([no, content]) => `${no}: ${content.replace(/\n$/, "")}`)
        .join("\n");
    }
    // Fallback: surface the resource name so the AI has something to work with
    const resource = src["resource"] ?? raw["resource"];
    if (resource) return `Resource: ${String(resource)}`;
  }

  if (scanType === "SECRET") {
    // Never expose the actual raw secret — just confirm what was detected
    const detector = raw["DetectorName"] ?? raw["DetectorType"] ?? "unknown";
    const verified  = raw["Verified"] ? "verified" : "unverified";
    return `[${verified} ${detector} credential detected at line ${lineStart ?? "?"}]`;
  }

  if (scanType === "DAST" || scanType === "PENTEST" || scanType === "PENTEST_FULL") {
    // Merged DAST findings store occurrences[] — extract the first 3 as evidence blocks
    const occurrences = raw["occurrences"] as Array<{
      url?: string; param?: string; attack?: string; evidence?: string;
      responseStatus?: string | number | null; confidence?: string; severity?: string;
    }> | undefined;

    if (Array.isArray(occurrences) && occurrences.length > 0) {
      const blocks = occurrences.slice(0, 3).map((occ, i) => {
        const lines: string[] = [`[Affected URL ${i + 1}]`];
        if (occ.url)                    lines.push(`URL: ${occ.url}`);
        if (occ.param)                  lines.push(`Vulnerable Parameter: ${occ.param}`);
        if (occ.responseStatus != null) lines.push(`HTTP Status: ${occ.responseStatus}`);
        if (occ.confidence)             lines.push(`Confidence: ${occ.confidence}`);
        if (occ.attack)                 lines.push(`Attack Payload: ${String(occ.attack).slice(0, 200)}`);
        if (occ.evidence)               lines.push(`Evidence: ${String(occ.evidence).slice(0, 200)}`);
        return lines.join("\n");
      });
      return blocks.join("\n\n");
    }

    // Non-merged: try to surface URL and any attack data from the primary object
    const url    = raw["url"]    ?? raw["filePath"];
    const attack = raw["attack"] ?? raw["other"];
    if (url || attack) {
      const lines: string[] = [];
      if (url)    lines.push(`URL: ${url}`);
      if (attack) lines.push(`Attack Payload: ${String(attack).slice(0, 200)}`);
      return lines.join("\n");
    }
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

  // IAC extras: for merged findings read from primary (original Checkov JSON)
  const raw    = (f["rawOutput"] ?? {}) as Record<string, unknown>;
  const rawSrc = (raw["merged"] === true && raw["primary"])
    ? raw["primary"] as Record<string, unknown>
    : raw;
  const iacResource  = rawSrc["resource"]  ? String(rawSrc["resource"])  : null;
  const iacCheckId   = rawSrc["check_id"]  ? String(rawSrc["check_id"])  : null;
  const iacGuideline = rawSrc["guideline"] ? String(rawSrc["guideline"]) : null;

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
    const targetFile = filePath ?? depFile;
    const lang = detectLanguage(targetFile) ?? "manifest";
    return `Fix this vulnerable dependency by bumping to the patched version.

Vulnerability : ${title}${cveId ? ` (${cveId})` : ""}
Package       : ${pkg ?? "unknown"}${pkgVer ? `@${pkgVer}` : ""}
Fix version   : ${fixVer ?? "latest"}
File          : ${targetFile}
Language      : ${lang}
Description   : ${description}
${remediation ? `Fix hint     : ${remediation}` : ""}

${FORMAT}`;
  }

  // ── IAC: infrastructure-as-code config fix ───────────────────────────────
  if (scanType === "IAC") {
    const file = filePath ?? "main.tf";
    const lang = detectLanguage(file) ?? "Terraform/YAML";
    return `Fix this IaC misconfiguration with a minimal change to the Terraform/CloudFormation/Kubernetes config.

Check         : ${iacCheckId ?? title}
Resource      : ${iacResource ?? "see file"}
File          : ${file}
Language      : ${lang}
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
    const lang = detectLanguage(file) ?? "source code";
    return `Fix this hardcoded secret by replacing it with a secure alternative (environment variable or secrets manager lookup).

Secret type   : ${detector}
File          : ${file}
Language      : ${lang}
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
    const lang = detectLanguage(file) ?? "source code";
    return `Fix this security vulnerability with a minimal, targeted code change.

Vulnerability : ${title}
File          : ${file}
Language      : ${lang}
Lines         : ${lineStart ?? 1}–${lineEnd ?? lineStart ?? 1}
Description   : ${description}
${remediation  ? `Fix hint     : ${remediation}` : ""}
${cleanCode    ? `\nVulnerable code (starts at line ${lineStart ?? 1}):\n${cleanCode}` : "\n(No code preview available — use the description and line number above.)"}

IMPORTANT:
- Output must be valid ${lang} syntax — do not mix in JavaScript/Python/etc. unless that is the language above.
- Use exactly "--- a/${file}" and "+++ b/${file}" as file headers.
- The @@ hunk must reference the real line numbers shown above (starting at ${lineStart ?? 1}).
- Change only the vulnerable lines. Keep surrounding context lines unchanged.
- Do NOT add explanatory comments or change unrelated code.

${FORMAT}`;
  }

  // ── DAST / PENTEST: server-side fix using real scanner evidence ──────────────
  const guessedFile = guessFileFromTitle(title);
  // Count how many affected URLs were found for the log label
  const urlCount = snippet
    ? (snippet.match(/\[Affected URL/g) ?? []).length || 1
    : 0;
  return `Fix this web vulnerability detected by dynamic scanning (DAST/Pentest).

Vulnerability : ${title}
Description   : ${description}
${remediation ? `Fix hint      : ${remediation}` : ""}
${snippet
    ? `\nScanner Evidence (${urlCount} affected URL${urlCount !== 1 ? "s" : ""}):\n${snippet}`
    : ""}

The fix must be server-side (e.g. middleware, route handler, response header, input validation, or web server config).
${snippet
    ? `The attack payloads and evidence above show exactly what the scanner exploited — use them to target the fix precisely.`
    : `Use a realistic filename such as ${guessedFile}.`}

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
  locationIndex?: number,
): Promise<string> {
  const finding = await prisma.finding.findUniqueOrThrow({ where: { id: findingId } });

  // ── Per-location branch (merged SAST sub-issues) ───────────────────────────
  // When `locationIndex` is provided, build a prompt scoped to that specific
  // sub-location's filePath/lineStart/snippet and cache the diff inside
  // `rawOutput.locations[i].aiFixSuggestion` so each sub-issue gets its own
  // targeted fix instead of all sharing the primary location's diff.
  const raw = (finding.rawOutput ?? {}) as Record<string, unknown>;
  const isMergedSast =
    finding.scanType === "SAST" &&
    raw["merged"] === true &&
    Array.isArray(raw["locations"]);

  if (locationIndex != null && isMergedSast) {
    const locations = [...(raw["locations"] as Array<Record<string, unknown>>)];
    const loc = locations[locationIndex];
    if (!loc) throw new Error(`Location index ${locationIndex} out of range`);

    if (!force && typeof loc["aiFixSuggestion"] === "string" && loc["aiFixSuggestion"]) {
      logger.info(`[fix] returning cached fix for ${findingId} location ${locationIndex}`);
      return loc["aiFixSuggestion"] as string;
    }

    // Build a synthetic "finding-like" object scoped to this sub-location.
    // Reuse parent title/description/remediation but override the file/line
    // and use the location's stored snippet directly (skip the GitHub
    // fallback path — locations are already snippet-backfilled by scanWorker).
    const snippetRaw = typeof loc["snippet"] === "string" ? (loc["snippet"] as string).trim() : "";
    const snippet = snippetRaw && !/^requires?\s+login$/i.test(snippetRaw) ? snippetRaw : null;

    const subF: Record<string, unknown> = {
      ...(finding as unknown as Record<string, unknown>),
      filePath:  loc["filePath"],
      lineStart: loc["lineStart"],
      lineEnd:   loc["lineEnd"],
      severity:  loc["severity"] ?? finding.severity,
      // Drop merged rawOutput so prompt builder doesn't re-extract from it
      rawOutput: {},
    };

    const prompt = buildPrompt(subF, snippet);
    logger.info(`[fix] generating per-location fix for ${findingId} loc=${locationIndex} (${loc["filePath"]}:${loc["lineStart"]})`);

    const cleaned = await runFixGeneration(prompt, findingId);

    // Cache inside the locations array
    locations[locationIndex] = { ...loc, aiFixSuggestion: cleaned };
    await prisma.finding.update({
      where: { id: findingId },
      data:  { rawOutput: { ...raw, locations } as object },
    });

    const valid = isValidUnifiedDiff(cleaned);
    logger.info(`[fix] per-location fix cached for ${findingId} loc=${locationIndex} (valid=${valid})`);
    return cleaned;
  }

  // ── Primary-location (default) path ─────────────────────────────────────────
  if (!force && finding.aiFixSuggestion) {
    logger.info(`[fix] returning cached fix suggestion for finding ${findingId}`);
    return finding.aiFixSuggestion;
  }

  const f = finding as unknown as Record<string, unknown>;

  // ── Use scan-time stored code snippet / evidence (no external auth needed) ─
  let snippet: string | null = null;
  snippet = extractFromRawOutput(finding.rawOutput, finding.scanType, finding.lineStart);
  // For SAST/IAC/SECRET also check the dedicated codeSnippet column
  if (!snippet && ["SAST", "IAC", "SECRET"].includes(finding.scanType) && finding.codeSnippet) {
    snippet = finding.codeSnippet;
  }
  logger.info(`[fix] code context for ${findingId}: ${snippet ? "stored snippet/evidence" : "description only"}`);

  const prompt = buildPrompt(f, snippet);
  logger.info(`[fix] generating fix for ${findingId} (${finding.scanType})`);

  const cleaned = await runFixGeneration(prompt, findingId);

  await prisma.finding.update({
    where: { id: findingId },
    data: { aiFixSuggestion: cleaned, aiFixSuggestedAt: new Date() },
  });

  const valid = isValidUnifiedDiff(cleaned);
  logger.info(`[fix] fix suggestion cached for finding ${findingId} (valid=${valid})`);
  return cleaned;
}

/**
 * Shared Ollama call + retry-once-on-invalid-diff loop. Used by both the
 * primary-location path and the per-sub-location path so they share the same
 * model config, validation rules and retry semantics.
 */
async function runFixGeneration(prompt: string, label: string): Promise<string> {
  /** Single Ollama call → cleaned string (markdown fences removed). */
  const callModel = async (p: string): Promise<string> => {
    const resp = await axios.post(
      `${config.OLLAMA_URL}/api/generate`,
      {
        model:  config.OLLAMA_MODEL,
        prompt: p,
        stream: false,
        // num_ctx 6144 (was 4096): SAST snippets + 1KB scanner context can
        // push past 4K tokens on .cs / Java files. Bumped to 6144 (not 8192)
        // because 7B models with full 8K context require ~8 GiB on CPU and
        // cause OOM aborts in the 8 GiB Ollama container.
        options: { temperature: 0.1, num_predict: 1024, num_ctx: 6144 },
      },
      { timeout: 600_000 }, // 10 min — code generation on 7B model can be slow on CPU
    );
    const txt = ((resp.data as { response?: string }).response ?? "").trim();
    return txt
      .replace(/^```(?:diff|patch)?\n?/m, "")
      .replace(/\n?```$/m, "")
      .trim();
  };

  let cleaned: string;
  try {
    cleaned = await callModel(prompt);
  } catch (err: unknown) {
    const msg = err instanceof Error ? err.message : String(err);
    logger.error(`[fix] ollama request failed for ${label}: ${msg}`);
    throw new Error(`AI service unavailable: ${msg}`);
  }
  if (!cleaned) throw new Error("AI returned an empty response — please try again.");

  if (!isValidUnifiedDiff(cleaned)) {
    logger.warn(`[fix] first attempt returned invalid diff for ${label} — retrying`);
    const stricterPrompt =
      prompt +
      "\n\nREMINDER: The previous response was rejected because it was not a valid unified diff. " +
      "Reply with ONLY the diff. No prose, no markdown fences. " +
      "It MUST contain `--- a/<file>`, `+++ b/<file>`, an `@@ ...,... +...,... @@` hunk header, " +
      "and at least one `-` or `+` line.";
    try {
      cleaned = await callModel(stricterPrompt);
    } catch (err: unknown) {
      const msg = err instanceof Error ? err.message : String(err);
      logger.warn(`[fix] retry call failed for ${label}: ${msg}`);
    }
  }

  if (!isValidUnifiedDiff(cleaned)) {
    logger.warn(`[fix] diff still invalid after retry for ${label} — caching with warning`);
  }

  return cleaned;
}
