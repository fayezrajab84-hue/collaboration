/**
 * DiffViewer — GitHub-style unified diff renderer.
 *
 * Handles standard unified diff output:
 *   --- a/file   (file header)
 *   +++ b/file   (file header)
 *   @@ ... @@    (hunk header, with optional function context)
 *   -line        (removed)
 *   +line        (added)
 *    line        (context, space-prefixed)
 *
 * Lines that don't match any prefix are shown as context.
 */

interface DiffLine {
  type:    "file-a" | "file-b" | "hunk" | "removed" | "added" | "context" | "empty";
  content: string;
  lineNo?: number; // simplified: not tracking per-side line numbers
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

// ── Line styles ───────────────────────────────────────────────────────────────

const LINE_STYLES: Record<DiffLine["type"], { row: string; gutter: string; code: string }> = {
  "file-a":  { row: "bg-gray-800",               gutter: "bg-gray-800 text-gray-500 select-none",   code: "text-gray-400 font-semibold" },
  "file-b":  { row: "bg-gray-800",               gutter: "bg-gray-800 text-gray-500 select-none",   code: "text-gray-400 font-semibold" },
  "hunk":    { row: "bg-blue-950/50",             gutter: "bg-blue-950/70 text-blue-500 select-none", code: "text-blue-400" },
  "removed": { row: "bg-red-950/50 hover:bg-red-950/70",   gutter: "bg-red-950/80 text-red-500 select-none",   code: "text-red-300" },
  "added":   { row: "bg-green-950/50 hover:bg-green-950/70", gutter: "bg-green-950/80 text-green-500 select-none", code: "text-green-300" },
  "context": { row: "hover:bg-gray-800/40",       gutter: "bg-gray-900 text-gray-600 select-none",   code: "text-gray-400" },
  "empty":   { row: "",                           gutter: "bg-gray-900 select-none",                 code: "" },
};

// Gutter symbol per line type
const GUTTER_SYMBOL: Partial<Record<DiffLine["type"], string>> = {
  removed: "-",
  added:   "+",
  context: " ",
  "file-a":"",
  "file-b":"",
  hunk:    "",
  empty:   "",
};

// ── Component ─────────────────────────────────────────────────────────────────

interface Props {
  diff: string;
}

export default function DiffViewer({ diff }: Props) {
  const lines = parseDiff(diff);

  // Group consecutive file-a + file-b into a single file header block
  const hasFileHeaders = lines.some((l) => l.type === "file-a" || l.type === "file-b");

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

      {/* Diff body */}
      <div className="overflow-x-auto">
        <table className="w-full border-collapse">
          <tbody>
            {lines
              .filter((l) => l.type !== "file-a" && l.type !== "file-b")
              .map((line, i) => {
                const s = LINE_STYLES[line.type];
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
                      <td className={`px-4 py-0.5 ${s.code}`}>
                        {line.content}
                      </td>
                    </tr>
                  );
                }

                return (
                  <tr key={i} className={s.row}>
                    {/* Gutter — +/−/space symbol */}
                    <td className={`w-8 border-r border-gray-800 px-2 py-0.5 text-center font-bold ${s.gutter}`}>
                      {sym}
                    </td>
                    {/* Code */}
                    <td className={`whitespace-pre px-4 py-0.5 leading-5 ${s.code}`}>
                      {/* Strip the leading +/- from the content since gutter shows it */}
                      {(line.type === "removed" || line.type === "added")
                        ? line.content.slice(1)
                        : line.content.startsWith(" ")
                          ? line.content.slice(1)
                          : line.content}
                    </td>
                  </tr>
                );
              })}
          </tbody>
        </table>
      </div>
    </div>
  );
}
