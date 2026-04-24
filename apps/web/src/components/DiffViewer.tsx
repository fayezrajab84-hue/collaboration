/**
 * DiffViewer — GitHub-style unified diff renderer with syntax highlighting.
 *
 * Handles standard unified diff output:
 *   --- a/file   (file header)
 *   +++ b/file   (file header)
 *   @@ ... @@    (hunk header, with optional function context)
 *   -line        (removed)
 *   +line        (added)
 *    line        (context, space-prefixed)
 *
 * Lines that don't match any prefix are shown as context. Removed/added/
 * context code cells are tokenised by prism-react-renderer using the same
 * Prism instance as <SyntaxHighlight> so colouring matches the rest of the
 * app (Java keywords, strings, comments, …). The +/- gutter and red/teal
 * row tint are preserved.
 */
import { Highlight, themes } from "prism-react-renderer";
import prism from "../lib/prismSetup";
import { detectLanguage } from "./SyntaxHighlight";

interface DiffLine {
  type:    "file-a" | "file-b" | "hunk" | "removed" | "added" | "context" | "empty";
  content: string;
}

function parseDiff(raw: string): DiffLine[] {
  return raw.split("\n").map((line): DiffLine => {
    if (line.startsWith("--- "))  return { type: "file-a",  content: line };
    if (line.startsWith("+++ "))  return { type: "file-b",  content: line };
    if (line.startsWith("@@ "))   return { type: "hunk",    content: line };
    if (line.startsWith("-"))     return { type: "removed", content: line };
    if (line.startsWith("+"))     return { type: "added",   content: line };
    if (line === "")              return { type: "empty",   content: "" };
    return { type: "context", content: line };
  });
}

// Strip the leading diff marker (+, -, or single space) so Prism gets the
// actual source, not an off-by-one version.
function stripPrefix(line: DiffLine): string {
  if (line.type === "removed" || line.type === "added")       return line.content.slice(1);
  if (line.type === "context" && line.content.startsWith(" ")) return line.content.slice(1);
  return line.content;
}

// Extract a file path from the "+++ b/path" (or "--- a/path") header so we
// can detect the grammar. Falls back to the first matching header.
function extractFilePath(lines: DiffLine[]): string {
  const header = lines.find((l) => l.type === "file-b") ?? lines.find((l) => l.type === "file-a");
  if (!header) return "";
  // "+++ b/src/foo/Bar.java" → "src/foo/Bar.java"
  const raw = header.content.slice(4).trim();
  return raw.replace(/^[ab]\//, "");
}

// ── Line styles ───────────────────────────────────────────────────────────────

const LINE_STYLES: Record<DiffLine["type"], { row: string; gutter: string }> = {
  "file-a":  { row: "bg-gray-800",                        gutter: "bg-gray-800 text-gray-500 select-none" },
  "file-b":  { row: "bg-gray-800",                        gutter: "bg-gray-800 text-gray-500 select-none" },
  "hunk":    { row: "bg-gray-800/60",                     gutter: "bg-gray-800 text-gray-500 select-none" },
  "removed": { row: "bg-red-950/50 hover:bg-red-950/70",  gutter: "bg-red-950/80 text-red-500 select-none" },
  "added":   { row: "bg-teal-950/50 hover:bg-teal-950/70", gutter: "bg-teal-950/80 text-teal-500 select-none" },
  "context": { row: "hover:bg-gray-800/40",               gutter: "bg-gray-900 text-gray-600 select-none" },
  "empty":   { row: "",                                    gutter: "bg-gray-900 select-none" },
};

const GUTTER_SYMBOL: Partial<Record<DiffLine["type"], string>> = {
  removed: "-",
  added:   "+",
  context: " ",
};

// ── Component ─────────────────────────────────────────────────────────────────

interface Props {
  diff: string;
}

export default function DiffViewer({ diff }: Props) {
  const lines       = parseDiff(diff);
  const filePath    = extractFilePath(lines);
  const language    = detectLanguage(filePath) as Parameters<typeof Highlight>[0]["language"];
  const hasFileHeaders = lines.some((l) => l.type === "file-a" || l.type === "file-b");

  // Feed Prism the stripped source for every non-header/non-empty line. Lines
  // that are file-a/file-b are skipped entirely (rendered separately in the
  // header block); hunk and empty lines are rendered without tokenisation.
  // We keep a parallel `tokenIndex` counter to zip tokenised output back to
  // the original DiffLine array.
  const tokenisableLines = lines.filter(
    (l) => l.type !== "file-a" && l.type !== "file-b" && l.type !== "hunk" && l.type !== "empty",
  );
  const tokenisableSource = tokenisableLines.map(stripPrefix).join("\n");

  return (
    <div className="overflow-hidden rounded-lg border border-gray-700 font-mono text-xs">
      {/* File header (--- / +++ lines) */}
      {hasFileHeaders && (
        <div className="border-b border-gray-700 bg-gray-800 px-3 py-2">
          {lines
            .filter((l) => l.type === "file-a" || l.type === "file-b")
            .map((l, i) => (
              <div key={i} className="text-gray-400">
                <span className="text-gray-600">{l.type === "file-a" ? "---" : "+++"} </span>
                {l.content.slice(4)}
              </div>
            ))}
        </div>
      )}

      {/* Diff body — prism-react-renderer tokenises the stripped source once;
          we then zip tokens back with diff metadata for per-row styling. */}
      <Highlight
        prism={prism as Parameters<typeof Highlight>[0]["prism"]}
        theme={themes.vsDark}
        code={tokenisableSource}
        language={language}
      >
        {({ style: themeStyle, tokens, getTokenProps }) => (
          <div className="overflow-x-auto" style={{ background: themeStyle.background }}>
            <table className="w-full border-collapse">
              <tbody>
                {(() => {
                  let ti = 0; // cursor into tokens[] (one entry per source line)
                  return lines
                    .filter((l) => l.type !== "file-a" && l.type !== "file-b")
                    .map((line, i) => {
                      const s   = LINE_STYLES[line.type];
                      const sym = GUTTER_SYMBOL[line.type] ?? "";

                      if (line.type === "empty") {
                        return (
                          <tr key={i} className="h-2">
                            <td className="w-8 border-r border-gray-800 bg-gray-900" />
                            <td className="bg-gray-900" />
                          </tr>
                        );
                      }

                      if (line.type === "hunk") {
                        return (
                          <tr key={i} className={s.row}>
                            <td className={`w-8 border-r border-gray-800 px-2 py-0.5 text-center ${s.gutter}`}>
                              ···
                            </td>
                            <td className="px-4 py-0.5 text-gray-400">
                              {line.content}
                            </td>
                          </tr>
                        );
                      }

                      // Consume one tokenised line for this diff row.
                      const lineTokens = tokens[ti++] ?? [];

                      return (
                        <tr key={i} className={s.row}>
                          {/* Gutter — +/−/space symbol */}
                          <td className={`w-8 border-r border-gray-800 px-2 py-0.5 text-center font-bold ${s.gutter}`}>
                            {sym}
                          </td>
                          {/* Code — Prism-tokenised */}
                          <td className="whitespace-pre px-4 py-0.5 leading-5">
                            {lineTokens.map((token, k) => (
                              <span key={k} {...getTokenProps({ token })} />
                            ))}
                          </td>
                        </tr>
                      );
                    });
                })()}
              </tbody>
            </table>
          </div>
        )}
      </Highlight>
    </div>
  );
}
