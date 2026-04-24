/**
 * SyntaxHighlight — language-aware code viewer with line numbers.
 *
 * Features:
 * - Detects language from file extension (.ts → typescript, .py → python, …)
 * - Strips Semgrep's `N: code` line-number prefixes from snippets before
 *   passing to Prism, then re-injects the real line numbers into the gutter
 * - Highlights the vulnerable line range (lineStart…lineEnd) in amber
 * - Dark VS Code–style theme (`themes.vsDark`) matches the rest of the UI
 */
import { Highlight, themes } from "prism-react-renderer";

// Our Prism instance (with Java, Python, Go, Ruby, HCL, … grammars loaded).
// Passed to <Highlight prism={…}> so prism-react-renderer uses this instance
// instead of its vendored one which only ships with markup/css/clike/js/ts.
// Without this override, non-web languages fall back to plain text — which
// in the vsDark theme renders as a single light-blue tone ("no syntax
// highlight, only blue").
import prism from "../lib/prismSetup";

// ── Language detection ────────────────────────────────────────────────────────

const EXT_TO_LANG: Record<string, string> = {
  ts:        "typescript",
  tsx:       "tsx",
  js:        "javascript",
  jsx:       "jsx",
  mjs:       "javascript",
  cjs:       "javascript",
  py:        "python",
  pyi:       "python",
  java:      "java",
  go:        "go",
  rb:        "ruby",
  php:       "php",
  c:         "c",
  h:         "c",
  cpp:       "cpp",
  cc:        "cpp",
  cxx:       "cpp",
  cs:        "csharp",
  yaml:      "yaml",
  yml:       "yaml",
  json:      "json",
  jsonc:     "json",
  xml:       "xml",
  sh:        "bash",
  bash:      "bash",
  zsh:       "bash",
  ps1:       "powershell",
  psm1:      "powershell",
  html:      "html",
  htm:       "html",
  css:       "css",
  scss:      "scss",
  tf:        "hcl",
  tfvars:    "hcl",
  hcl:       "hcl",
  sql:       "sql",
  rs:        "rust",
  kt:        "kotlin",
  kts:       "kotlin",
  swift:     "swift",
  scala:     "scala",
  groovy:    "groovy",
  gradle:    "groovy",
  r:         "r",
  lua:       "lua",
  perl:      "perl",
  pl:        "perl",
  vue:       "markup",         // prism falls back to markup for .vue templates
  svelte:    "markup",
  toml:      "toml",
  md:        "markdown",
  markdown:  "markdown",
  dockerfile:"docker",
  containerfile: "docker",
  proto:     "protobuf",
  dart:      "dart",
  ex:        "elixir",
  exs:       "elixir",
  clj:       "clojure",
  cljs:      "clojure",
  m:         "objectivec",
  mm:        "objectivec",
  env:       "bash",
  properties:"properties",
  ini:       "ini",
};

// Some files have no extension — match on basename instead.
const BASENAME_TO_LANG: Record<string, string> = {
  dockerfile:    "docker",
  containerfile: "docker",
  makefile:      "makefile",
  jenkinsfile:   "groovy",
  vagrantfile:   "ruby",
  gemfile:       "ruby",
  rakefile:      "ruby",
  procfile:      "yaml",
  caddyfile:     "nginx",
};

export function detectLanguage(filePath: string | null | undefined): string {
  if (!filePath) return "text";
  const base = filePath.split(/[\\/]/).pop()?.toLowerCase() ?? "";
  // Extension-less filenames (Dockerfile, Makefile, …)
  const byBase = BASENAME_TO_LANG[base];
  if (byBase) return byBase;
  const ext = base.includes(".") ? base.split(".").pop() ?? "" : "";
  return EXT_TO_LANG[ext] ?? "text";
}

// ── Line parsing ──────────────────────────────────────────────────────────────

/** Parsed line with optional real line number (from Semgrep prefix or offset). */
interface ParsedLine {
  no:   number | null;
  code: string;
}

/**
 * Splits a raw snippet into lines.
 * Detects and strips Semgrep's `N: code` prefix, keeping the real number.
 * Falls back to counting from `baseLineNo` when no prefix is present.
 */
function parseLines(raw: string, baseLineNo: number | null): ParsedLine[] {
  const rawLines = raw.split("\n");
  const hasNums  = rawLines.length > 0 && /^\s*\d+:/.test(rawLines[0] ?? "");

  if (hasNums) {
    return rawLines.map((l) => {
      const m = l.match(/^\s*(\d+):\s?(.*)/s);
      return { no: m ? parseInt(m[1]!, 10) : null, code: m ? m[2]! : l };
    });
  }

  return rawLines.map((l, i) => ({
    no:   baseLineNo != null ? baseLineNo + i : null,
    code: l,
  }));
}

// ── Component ─────────────────────────────────────────────────────────────────

export interface SyntaxHighlightProps {
  code:       string;
  filePath?:  string | null;
  lineStart?: number | null;
  lineEnd?:   number | null;
  /** When true the component shrinks; suitable for the SubissuesPanel preview. */
  compact?: boolean;
  /**
   * Suppresses the amber vulnerable-line highlight. Use when the reported
   * lineStart is approximate (e.g. Semgrep Community taint-mode findings
   * where lineStart points at the taint source rather than the dangerous
   * sink) — a single-line highlight there would mislead the developer.
   */
  suppressHighlight?: boolean;
}

export default function SyntaxHighlight({
  code,
  filePath,
  lineStart,
  lineEnd,
  compact = false,
  suppressHighlight = false,
}: SyntaxHighlightProps) {
  const language    = detectLanguage(filePath) as Parameters<typeof Highlight>[0]["language"];
  const parsedLines = parseLines(code.trimEnd(), lineStart ?? null);
  const cleanCode   = parsedLines.map((l) => l.code).join("\n");

  const isVuln = (no: number | null) =>
    !suppressHighlight &&
    no != null && lineStart != null &&
    no >= lineStart && no <= (lineEnd ?? lineStart);

  return (
    <Highlight prism={prism as Parameters<typeof Highlight>[0]["prism"]} theme={themes.vsDark} code={cleanCode} language={language}>
      {({ style, tokens, getLineProps, getTokenProps }) => (
        <div
          className={[
            "overflow-x-auto rounded-lg border border-gray-700",
            compact ? "text-[11px]" : "text-[12px]",
          ].join(" ")}
          style={{ ...style, background: "#1e1e1e" }}
        >
          <table className="w-full border-collapse leading-5">
            <tbody>
              {tokens.map((line, i) => {
                const no   = parsedLines[i]?.no ?? null;
                const vuln = isVuln(no);
                return (
                  <tr
                    key={i}
                    className={
                      vuln
                        ? "bg-amber-500/10 border-l-2 border-amber-400"
                        : ""
                    }
                  >
                    {/* Line-number gutter */}
                    <td
                      className={[
                        "select-none w-12 pr-3 pl-4 py-0 text-right align-top font-mono leading-5",
                        vuln ? "text-amber-400/80" : "text-gray-600",
                      ].join(" ")}
                    >
                      {no ?? ""}
                    </td>

                    {/* Code cell — getLineProps used only for token context, not spread (avoids className clash) */}
                    <td className="pr-6 py-0 whitespace-pre align-top font-mono leading-5">
                      {line.map((token, key) => (
                        <span key={key} {...getTokenProps({ token })} />
                      ))}
                    </td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        </div>
      )}
    </Highlight>
  );
}
