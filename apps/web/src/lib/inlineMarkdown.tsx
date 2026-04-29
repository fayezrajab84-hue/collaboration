/**
 * Tiny inline-markdown renderer.
 *
 * Why we don't pull in `react-markdown`:
 *   The only fields that need formatting are CSPM `description` /
 *   `remediation` strings — Prowler ships these with `**bold**` and
 *   `` `code` `` markers in the source data. Pulling a 50KB markdown
 *   parser + sanitiser for two inline patterns is not worth the bundle
 *   weight. This module is ~30 LOC, no deps, no HTML parsing — only
 *   the three inline tokens that actually appear in Prowler output.
 *
 * Supported tokens (inline only — no headings, lists, links, blocks):
 *   **bold**   → <strong>
 *   *italic*   → <em>           (won't fire on `*` inside words)
 *   `code`     → <code> with subtle dark-bg pill styling
 *   \n         → <br/>           (preserves Prowler's line breaks in
 *                                 multi-paragraph remediations)
 *
 * Anything else passes through as plain text. Unmatched markers
 * (e.g. orphan `**` from a malformed source) are left in place rather
 * than silently dropped — better to surface bad data than hide it.
 */
import { Fragment, type ReactNode } from "react";

// Single regex captures all three inline tokens at once — split() lets
// us interleave the matched groups with the surrounding plain text in
// one pass instead of three sequential replaces.
//
//   group 1: **bold**     content
//   group 2: *italic*     content   (single-char delim, must NOT be **)
//   group 3: `code`       content
//
// The negative lookarounds on the *italic* alternative prevent it from
// chewing up the inner content of a **bold** token (which would render
// "bold" as italic-of-empty if we ran italic before bold).
const TOKEN_RE = /\*\*([^*]+)\*\*|(?<!\*)\*([^*\n]+)\*(?!\*)|`([^`\n]+)`/g;

export function renderInlineMarkdown(text: string | null | undefined): ReactNode {
  if (!text) return null;

  const parts: ReactNode[] = [];
  let lastIndex = 0;
  let match: RegExpExecArray | null;
  let key = 0;

  // Reset lastIndex defensively — TOKEN_RE is a module-level regex
  // with the /g flag, so its state persists between calls.
  TOKEN_RE.lastIndex = 0;

  while ((match = TOKEN_RE.exec(text)) !== null) {
    // Plain text between the previous match and this one.
    if (match.index > lastIndex) {
      parts.push(
        <Fragment key={`t-${key++}`}>
          {renderLineBreaks(text.slice(lastIndex, match.index), key)}
        </Fragment>,
      );
    }

    if (match[1] !== undefined) {
      // **bold**
      parts.push(
        <strong key={`b-${key++}`} className="font-semibold text-gray-100">
          {match[1]}
        </strong>,
      );
    } else if (match[2] !== undefined) {
      // *italic*
      parts.push(
        <em key={`i-${key++}`} className="italic">
          {match[2]}
        </em>,
      );
    } else if (match[3] !== undefined) {
      // `code`
      parts.push(
        <code
          key={`c-${key++}`}
          className="rounded bg-gray-800 px-1 py-0.5 font-mono text-[0.85em] text-indigo-300"
        >
          {match[3]}
        </code>,
      );
    }

    lastIndex = match.index + match[0].length;
  }

  // Trailing plain text after the last match.
  if (lastIndex < text.length) {
    parts.push(
      <Fragment key={`t-${key++}`}>
        {renderLineBreaks(text.slice(lastIndex), key)}
      </Fragment>,
    );
  }

  return parts;
}

/** Convert `\n` to <br/> elements, preserving paragraph structure for
 * multi-line CSPM remediations (Prowler ships these with `\n\n` between
 * the main fix and the operational note we appended). */
function renderLineBreaks(text: string, baseKey: number): ReactNode {
  if (!text.includes("\n")) return text;
  const lines = text.split("\n");
  return lines.map((line, i) => (
    <Fragment key={`ln-${baseKey}-${i}`}>
      {line}
      {i < lines.length - 1 && <br />}
    </Fragment>
  ));
}
