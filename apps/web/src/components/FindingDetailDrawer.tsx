import { useState, useEffect } from "react";
import {
  X, ChevronDown, ChevronUp, ShieldCheck, Loader2,
  Sparkles, RefreshCw, AlertTriangle, Wrench, BookOpen, Info,
  CheckCircle2, XCircle, HelpCircle, Link, Check, GitCommit, Layers,
  Code2, ExternalLink, Copy, Globe, KeyRound,
} from "lucide-react";
import { useMutation, useQueryClient } from "@tanstack/react-query";
import type { Finding, FpAnalysis } from "@devsecops/types";
import { findingsApi, ticketsApi } from "../lib/api";
import SeverityBadge from "./SeverityBadge";
import ConfidenceBadge from "./ConfidenceBadge";
import DiffViewer from "./DiffViewer";
import SyntaxHighlight from "./SyntaxHighlight";
import { formatDate } from "../lib/utils";

// ── Types ─────────────────────────────────────────────────────────────────────

interface SastLocation {
  filePath:  string | null;
  lineStart: number | null;
  lineEnd:   number | null;
  severity:  string;
  message:   string;
  snippet:   string | null;
}

interface MergedRawOutput {
  merged:    boolean;
  count:     number;
  ruleId:    string;
  locations: SastLocation[];
}

// ── SCA subissues types ───────────────────────────────────────────────────────

/** Structured per-CVE entry — produced by mergePackageFindings() */
interface StructuredScaCve {
  cveId:      string | null;
  severity:   string;
  cvssScore:  number | null;
  fixVersion: string | null;
  filePath:   string | null;
  title:      string | null;
  primaryUrl: string | null;
}

/** Raw Trivy vulnerability object — stored by the old merge path */
interface LegacyTrivyCve {
  VulnerabilityID?: string;
  Severity?:        string;
  FixedVersion?:    string;
  Title?:           string;
  PrimaryURL?:      string;
  CVSS?:            Record<string, { V3Score?: number; V2Score?: number }>;
}

type ScaCve = StructuredScaCve | LegacyTrivyCve;

interface ScaMergedRawOutput {
  merged:            boolean;
  count:             number;
  installedVersion?: string;
  fixVersion?:       string | null;
  cves:              ScaCve[];
}

// ── DAST / Pentest subissues types ────────────────────────────────────────────

interface DastOccurrence {
  url:            string;
  param:          string | null;
  severity:       string;
  confidence:     string;
  zapConfidence:  string;
  responseStatus: string | number | null;
  evidence:       string | null;
  attack:         string | null;
  other:          string | null;
}

interface DastMergedRawOutput {
  merged:      boolean;
  count:       number;
  ruleId:      string;
  scanner:     string;
  occurrences: DastOccurrence[];
}

/** Normalise both the new structured format and old raw Trivy format. */
function normalizeScaCve(raw: ScaCve): StructuredScaCve {
  // Structured format: has "cveId" key
  if ("cveId" in raw) return raw as StructuredScaCve;

  // Legacy: raw Trivy vulnerability object — coerce to access known fields
  const t = raw as LegacyTrivyCve;
  let cvssScore: number | null = null;
  if (t.CVSS) {
    for (const scores of Object.values(t.CVSS)) {
      const s = scores?.V3Score ?? scores?.V2Score ?? null;
      if (s != null) { cvssScore = s; break; }
    }
  }
  return {
    cveId:      t.VulnerabilityID ?? null,
    severity:   (t.Severity ?? "MEDIUM").toUpperCase(),
    cvssScore,
    fixVersion: t.FixedVersion ?? null,
    filePath:   null,
    title:      t.Title         ?? null,
    primaryUrl: t.PrimaryURL    ?? null,
  };
}

// ── DAST / Pentest Subissues Panel ────────────────────────────────────────────

const CONF_LABEL: Record<string, { label: string; cls: string }> = {
  CONFIRMED: { label: "Confirmed",  cls: "bg-emerald-900/60 text-emerald-300 border border-emerald-700/50" },
  LIKELY:    { label: "Likely",     cls: "bg-blue-900/60 text-blue-300 border border-blue-700/50" },
  POSSIBLE:  { label: "Possible",   cls: "bg-gray-800 text-gray-400 border border-gray-700" },
};

interface DastSubissuesPanelProps {
  rawOut:      DastMergedRawOutput;
  onViewCode?: (occ: DastOccurrence) => void;
}

function DastSubissuesPanel({ rawOut, onViewCode }: DastSubissuesPanelProps) {
  const [expanded, setExpanded] = useState(false);
  const LIMIT = 10;
  const all   = rawOut.occurrences ?? [];
  const shown = expanded ? all : all.slice(0, LIMIT);

  return (
    <div className="overflow-hidden rounded-xl border border-gray-700">

      {/* ── Header ──────────────────────────────────────────────────── */}
      <div className="flex items-center gap-2 border-b border-gray-700 bg-gray-800/70 px-4 py-2.5">
        <Globe className="h-3.5 w-3.5 text-indigo-400" />
        <span className="text-xs font-semibold uppercase tracking-wider text-indigo-300">
          Affected URLs
        </span>
        <span className="ml-1 rounded-full bg-gray-700 px-2 py-0.5 text-xs font-bold text-gray-200">
          {all.length}
        </span>
        <span className="ml-auto text-[11px] font-semibold uppercase tracking-wider text-gray-600">
          Subissue
        </span>
      </div>

      {/* ── Scanner badge row ────────────────────────────────────────── */}
      {rawOut.scanner && (
        <div className="flex items-center gap-2 border-b border-gray-700/50 bg-gray-800/30 px-4 py-1.5">
          <span className="rounded bg-gray-700/60 px-2 py-0.5 text-[10px] font-mono text-gray-400">
            {rawOut.scanner}
          </span>
          <span className="text-[10px] text-gray-600">
            rule: <span className="font-mono text-gray-500">{rawOut.ruleId}</span>
          </span>
        </div>
      )}

      {/* ── Occurrence rows ──────────────────────────────────────────── */}
      <div className="divide-y divide-gray-800/60">
        {shown.map((occ, i) => {
          const sev  = occ.severity?.toUpperCase()  ?? "INFO";
          const conf = occ.confidence?.toUpperCase() ?? "POSSIBLE";
          const confMeta = CONF_LABEL[conf] ?? CONF_LABEL.POSSIBLE;

          return (
            <div key={i} className="px-4 py-3 hover:bg-gray-800/20 transition-colors">

              {/* URL + severity pill */}
              <div className="mb-1.5 flex items-start justify-between gap-3">
                <p
                  className="min-w-0 break-all font-mono text-[11px] leading-relaxed text-blue-300"
                  title={occ.url}
                >
                  {occ.url || "—"}
                </p>
                <span className={`shrink-0 rounded-full px-2 py-0.5 text-[10px] font-semibold ${SEV_BADGE[sev] ?? SEV_BADGE.INFO}`}>
                  {sev.charAt(0) + sev.slice(1).toLowerCase()}
                </span>
              </div>

              {/* Metadata chips: param / confidence / HTTP status */}
              <div className="flex flex-wrap items-center gap-1.5 text-[10px]">
                {occ.param && (
                  <span className="rounded bg-gray-800 px-1.5 py-0.5 font-mono text-gray-300">
                    param: <span className="text-yellow-300">{occ.param}</span>
                  </span>
                )}
                <span className={`rounded px-1.5 py-0.5 text-[10px] font-semibold ${confMeta.cls}`}>
                  {confMeta.label}
                </span>
                {occ.zapConfidence && occ.zapConfidence !== occ.confidence && (
                  <span className="rounded bg-gray-800 px-1.5 py-0.5 text-gray-500">
                    ZAP: {occ.zapConfidence}
                  </span>
                )}
                {occ.responseStatus != null && (
                  <span className="rounded bg-gray-800 px-1.5 py-0.5 text-gray-500">
                    HTTP {occ.responseStatus}
                  </span>
                )}
              </div>

              {/* Attack payload / evidence fragment */}
              {(occ.attack || occ.evidence) && (
                <pre className="mt-2 overflow-x-auto rounded-lg border border-gray-700/60 bg-gray-950 px-3 py-2 font-mono text-[10px] leading-relaxed text-gray-300 whitespace-pre-wrap">
                  {(occ.attack || occ.evidence)!.slice(0, 300)}
                </pre>
              )}

              {/* View Code + AI Analysis button */}
              {onViewCode && (
                <div className="mt-2 flex justify-end">
                  <button
                    onClick={() => onViewCode(occ)}
                    className="inline-flex items-center gap-1.5 rounded-md border border-indigo-700/40 bg-indigo-900/20 px-2.5 py-1 text-[10px] font-medium text-indigo-300 hover:bg-indigo-900/40 hover:text-indigo-200 transition-colors"
                  >
                    <Sparkles className="h-3 w-3" />
                    View Evidence + AI Analysis
                  </button>
                </div>
              )}
            </div>
          );
        })}
      </div>

      {/* ── Expand / collapse ────────────────────────────────────────── */}
      {all.length > LIMIT && (
        <button
          onClick={() => setExpanded((v) => !v)}
          className="flex w-full items-center justify-center gap-1.5 border-t border-gray-700 bg-gray-800/50 py-2 text-xs text-gray-400 hover:bg-gray-800 hover:text-gray-200 transition-colors"
        >
          {expanded
            ? <><ChevronUp   className="h-3.5 w-3.5" /> Show less</>
            : <><ChevronDown className="h-3.5 w-3.5" /> Show all {all.length} affected URLs</>}
        </button>
      )}
    </div>
  );
}

// ── Secret Subissues Panel ────────────────────────────────────────────────────

interface SecretOccurrence {
  filePath:  string | null;
  lineStart: number | null;
  snippet:   string | null;
  verified:  boolean;
  severity:  string;
  scanner:   string;
}

interface SecretMergedRawOutput {
  merged:      boolean;
  count:       number;
  ruleId:      string;
  scanner:     string;
  occurrences: SecretOccurrence[];
}

/** Strip /tmp/scan_workspace/<uuid>/repo/ prefix left by the scanner workspace. */
function cleanSecretPath(p: string | null): string | null {
  if (!p) return null;
  return p.replace(/^\/tmp\/scan_workspace\/[^/]+\/repo\//, "").replace(/^\/+/, "") || p;
}

/**
 * Strip legacy "42: code" line-number prefixes written by an older version of
 * the scanner. New scans emit clean code; this handles historical data.
 */
function stripSecretLinePrefixes(snippet: string): string {
  const lines = snippet.split("\n");
  const allHavePrefix = lines.every((l) => l.trim() === "" || /^\s*\d+:\s?/.test(l));
  if (!allHavePrefix) return snippet;
  return lines.map((l) => l.replace(/^\s*\d+:\s?/, "")).join("\n");
}

/**
 * Redact credential values on the secret line (lineStart).
 *
 * Strategy:
 *  - The snippet contains ±2 lines of context around lineStart.
 *  - We find which line in the snippet corresponds to lineStart and apply a
 *    regex that replaces token-looking values with  ••••••••
 *  - Patterns covered: JWT (eyJ…), AWS keys (AKIA…), quoted/unquoted values
 *    after = or : that look like credentials (20+ non-space chars).
 */
function redactSecretLine(snippet: string, lineStart: number | null): string {
  if (!lineStart) return snippet;

  const lines = snippet.split("\n");

  // Determine 0-based index of the secret line inside the snippet.
  // _read_snippet captures max(0, lineStart-3) … lineStart+2 (1-based lines →
  // context of 2 before). So the secret line is at index min(2, lineStart-1).
  const secretIdx = Math.min(2, lineStart - 1);

  return lines
    .map((line, idx) => {
      if (idx !== secretIdx) return line;
      return line
        // JWT: eyJxxx.yyy.zzz
        .replace(/eyJ[A-Za-z0-9_-]{10,}(?:\.[A-Za-z0-9_-]{10,}){1,2}/g, "eyJ[••••••••]")
        // AWS key ID
        .replace(/AKIA[A-Z0-9]{16}/g, "AKIA[••••••••]")
        // Quoted values after = or : that look like tokens (≥20 chars)
        .replace(/([:=]\s*["'`]?)([A-Za-z0-9+/=_\-]{20,})(["'`]?)/g, "$1••••••••$3")
        // Unquoted long tokens (fallback — 30+ chars to avoid false positives)
        .replace(/\b([A-Za-z0-9+/=_\-]{30,})\b/g, "••••••••");
    })
    .join("\n");
}

interface SecretSubissuesPanelProps {
  rawOut:   SecretMergedRawOutput;
  repoInfo: { fullName: string; defaultBranch: string } | null;
}

function SecretSubissuesPanel({ rawOut, repoInfo }: SecretSubissuesPanelProps) {
  const [expanded, setExpanded] = useState(false);
  const LIMIT = 10;
  const all   = rawOut.occurrences ?? [];
  const shown = expanded ? all : all.slice(0, LIMIT);

  return (
    <div className="overflow-hidden rounded-xl border border-gray-700">

      {/* ── Header ──────────────────────────────────────────────────── */}
      <div className="flex items-center gap-2 border-b border-gray-700 bg-gray-800/70 px-4 py-2.5">
        <KeyRound className="h-3.5 w-3.5 text-amber-400" />
        <span className="text-xs font-semibold uppercase tracking-wider text-amber-300">
          Affected Files
        </span>
        <span className="ml-1 rounded-full bg-gray-700 px-2 py-0.5 text-xs font-bold text-gray-200">
          {all.length}
        </span>
        <span className="ml-auto text-[11px] font-semibold uppercase tracking-wider text-gray-600">
          Subissue
        </span>
      </div>

      {/* ── Scanner / detector badge row ─────────────────────────────── */}
      {rawOut.scanner && (
        <div className="flex items-center gap-2 border-b border-gray-700/50 bg-gray-800/30 px-4 py-1.5">
          <span className="rounded bg-gray-700/60 px-2 py-0.5 text-[10px] font-mono text-gray-400">
            {rawOut.scanner}
          </span>
          <span className="text-[10px] text-gray-600">
            detector: <span className="font-mono text-gray-500">{rawOut.ruleId}</span>
          </span>
        </div>
      )}

      {/* ── Occurrence rows ──────────────────────────────────────────── */}
      <div className="divide-y divide-gray-800/60">
        {shown.map((occ, i) => {
          const sev         = occ.severity?.toUpperCase() ?? "HIGH";
          const cleanedPath = cleanSecretPath(occ.filePath);

          // Build GitHub URL for this occurrence
          const githubUrl = repoInfo && cleanedPath
            ? `https://github.com/${repoInfo.fullName}/blob/${repoInfo.defaultBranch}/${cleanedPath}${occ.lineStart ? `#L${occ.lineStart}` : ""}`
            : null;

          // Clean + redact snippet: strip legacy N: prefixes, then hide secret value
          const rawSnippet   = occ.snippet ? stripSecretLinePrefixes(occ.snippet) : null;
          const safeSnippet  = rawSnippet   ? redactSecretLine(rawSnippet, occ.lineStart) : null;

          return (
            <div key={i} className="px-4 py-3 hover:bg-gray-800/20 transition-colors">

              {/* File path + GitHub link + severity + verified badge */}
              <div className="mb-1.5 flex items-start justify-between gap-3">
                <div className="flex min-w-0 items-center gap-1.5">
                  <p className="min-w-0 break-all font-mono text-[11px] leading-relaxed text-indigo-300">
                    {cleanedPath ?? "—"}
                    {occ.lineStart != null && (
                      <span className="text-gray-500">:{occ.lineStart}</span>
                    )}
                  </p>
                  {githubUrl && (
                    <a
                      href={githubUrl}
                      target="_blank"
                      rel="noopener noreferrer"
                      title="View on GitHub"
                      className="shrink-0 text-gray-600 hover:text-blue-400 transition-colors"
                    >
                      <ExternalLink className="h-3 w-3" />
                    </a>
                  )}
                </div>
                <div className="flex shrink-0 items-center gap-1.5">
                  {occ.verified && (
                    <span className="rounded-full bg-red-900/60 px-2 py-0.5 text-[10px] font-semibold text-red-300 border border-red-700/50">
                      ⚠ Verified
                    </span>
                  )}
                  <span className={`rounded-full px-2 py-0.5 text-[10px] font-semibold ${SEV_BADGE[sev] ?? SEV_BADGE.INFO}`}>
                    {sev.charAt(0) + sev.slice(1).toLowerCase()}
                  </span>
                </div>
              </div>

              {/* Scanner chip */}
              <div className="mb-2 flex items-center gap-1.5 text-[10px]">
                <span className="rounded bg-gray-800 px-1.5 py-0.5 font-mono text-gray-400">
                  {occ.scanner}
                </span>
                <span className="text-gray-600 italic">secret value redacted</span>
              </div>

              {/* Code snippet — secret line is redacted */}
              {safeSnippet ? (
                <pre className="overflow-x-auto rounded-lg border border-amber-900/30 bg-gray-950 px-3 py-2 font-mono text-[10px] leading-relaxed text-gray-300 whitespace-pre-wrap">
                  {safeSnippet.slice(0, 800)}
                </pre>
              ) : (
                <div className="flex items-center gap-1.5 rounded-lg border border-gray-700/40 bg-gray-900/50 px-3 py-2 text-[10px] text-gray-600">
                  <Code2 className="h-3 w-3" />
                  <span>Code snippet unavailable — view on GitHub</span>
                </div>
              )}
            </div>
          );
        })}
      </div>

      {/* ── Expand / collapse ────────────────────────────────────────── */}
      {all.length > LIMIT && (
        <button
          onClick={() => setExpanded((v) => !v)}
          className="flex w-full items-center justify-center gap-1.5 border-t border-gray-700 bg-gray-800/50 py-2 text-xs text-gray-400 hover:bg-gray-800 hover:text-gray-200 transition-colors"
        >
          {expanded
            ? <><ChevronUp   className="h-3.5 w-3.5" /> Show less</>
            : <><ChevronDown className="h-3.5 w-3.5" /> Show all {all.length} affected files</>}
        </button>
      )}
    </div>
  );
}

// ── IAC Resources Panel ───────────────────────────────────────────────────────

interface IacResource {
  filePath:  string | null;
  lineStart: number | null;
  lineEnd:   number | null;
  resource:  string | null;
  snippet:   string | null;
  severity:  string;
  checkType: string | null;
}

interface IacMergedRawOutput {
  merged:    boolean;
  count:     number;
  ruleId:    string;
  scanner:   string;
  resources: IacResource[];
}

interface IacResourcesPanelProps {
  rawOut:      IacMergedRawOutput;
  repoInfo:    { fullName: string; defaultBranch: string } | null;
  onViewCode?: (res: IacResource, ghUrl: string | null) => void;
}

function IacResourcesPanel({ rawOut, repoInfo, onViewCode }: IacResourcesPanelProps) {
  const [expanded, setExpanded] = useState(false);
  const LIMIT = 10;
  const all   = rawOut.resources ?? [];
  const shown = expanded ? all : all.slice(0, LIMIT);

  return (
    <div className="overflow-hidden rounded-xl border border-gray-700">

      {/* ── Header ──────────────────────────────────────────────────── */}
      <div className="flex items-center gap-2 border-b border-gray-700 bg-gray-800/70 px-4 py-2.5">
        <Layers className="h-3.5 w-3.5 text-violet-400" />
        <span className="text-xs font-semibold uppercase tracking-wider text-violet-300">
          Failing Resources
        </span>
        <span className="ml-1 rounded-full bg-gray-700 px-2 py-0.5 text-xs font-bold text-gray-200">
          {all.length}
        </span>
        <span className="ml-auto text-[11px] font-semibold uppercase tracking-wider text-gray-600">
          Subissue
        </span>
      </div>

      {/* ── Scanner / rule badge row ─────────────────────────────────── */}
      {rawOut.scanner && (
        <div className="flex items-center gap-2 border-b border-gray-700/50 bg-gray-800/30 px-4 py-1.5">
          <span className="rounded bg-gray-700/60 px-2 py-0.5 text-[10px] font-mono text-gray-400">
            {rawOut.scanner}
          </span>
          <span className="text-[10px] text-gray-600">
            rule: <span className="font-mono text-gray-500">{rawOut.ruleId}</span>
          </span>
        </div>
      )}

      {/* ── Resource rows ────────────────────────────────────────────── */}
      <div className="divide-y divide-gray-800/60">
        {shown.map((res, i) => {
          const sev         = res.severity?.toUpperCase() ?? "MEDIUM";
          const cleanedPath = res.filePath?.replace(/^\/+/, "") ?? null;

          const githubUrl = repoInfo && cleanedPath
            ? `https://github.com/${repoInfo.fullName}/blob/${repoInfo.defaultBranch}/${cleanedPath}${res.lineStart ? `#L${res.lineStart}` : ""}`
            : null;

          // IAC snippets use "N: code" format (Checkov line numbers) — strip for display
          const rawSnippet = res.snippet ?? null;
          const lines = rawSnippet ? rawSnippet.split("\n") : [];
          const allHavePrefix = lines.length > 0 && lines.every((l) => l.trim() === "" || /^\s*\d+:\s?/.test(l));
          const displaySnippet = allHavePrefix
            ? lines.map((l) => l.replace(/^\s*\d+:\s?/, "")).join("\n")
            : rawSnippet;

          return (
            <div key={i} className="px-4 py-3 hover:bg-gray-800/20 transition-colors">

              {/* Resource name + severity */}
              <div className="mb-1 flex items-start justify-between gap-3">
                <div className="flex min-w-0 flex-col gap-0.5">
                  {res.resource && (
                    <p className="font-mono text-[11px] font-semibold text-violet-300">
                      {res.resource}
                    </p>
                  )}
                  <div className="flex items-center gap-1.5">
                    <p className="min-w-0 break-all font-mono text-[10px] leading-relaxed text-gray-500">
                      {cleanedPath ?? "—"}
                      {res.lineStart != null && (
                        <span>:{res.lineStart}{res.lineEnd && res.lineEnd !== res.lineStart ? `–${res.lineEnd}` : ""}</span>
                      )}
                    </p>
                    {githubUrl && (
                      <a
                        href={githubUrl}
                        target="_blank"
                        rel="noopener noreferrer"
                        title="View on GitHub"
                        className="shrink-0 text-gray-600 hover:text-blue-400 transition-colors"
                      >
                        <ExternalLink className="h-3 w-3" />
                      </a>
                    )}
                  </div>
                </div>
                <div className="flex shrink-0 items-center gap-1.5">
                  {res.checkType && (
                    <span className="rounded bg-gray-800 px-1.5 py-0.5 text-[10px] font-mono text-gray-500">
                      {res.checkType}
                    </span>
                  )}
                  <span className={`rounded-full px-2 py-0.5 text-[10px] font-semibold ${SEV_BADGE[sev] ?? SEV_BADGE.INFO}`}>
                    {sev.charAt(0) + sev.slice(1).toLowerCase()}
                  </span>
                </div>
              </div>

              {/* Code snippet */}
              {displaySnippet && (
                <pre className="mt-2 overflow-x-auto rounded-lg border border-gray-700/60 bg-gray-950 px-3 py-2 font-mono text-[10px] leading-relaxed text-gray-300 whitespace-pre-wrap">
                  {displaySnippet.slice(0, 600)}
                </pre>
              )}

              {/* View Code + AI Analysis button */}
              {onViewCode && (
                <div className="mt-2 flex justify-end">
                  <button
                    onClick={() => onViewCode(res, githubUrl)}
                    className="inline-flex items-center gap-1.5 rounded-md border border-violet-700/40 bg-violet-900/20 px-2.5 py-1 text-[10px] font-medium text-violet-300 hover:bg-violet-900/40 hover:text-violet-200 transition-colors"
                  >
                    <Sparkles className="h-3 w-3" />
                    View Code + AI Analysis
                  </button>
                </div>
              )}
            </div>
          );
        })}
      </div>

      {/* ── Expand / collapse ────────────────────────────────────────── */}
      {all.length > LIMIT && (
        <button
          onClick={() => setExpanded((v) => !v)}
          className="flex w-full items-center justify-center gap-1.5 border-t border-gray-700 bg-gray-800/50 py-2 text-xs text-gray-400 hover:bg-gray-800 hover:text-gray-200 transition-colors"
        >
          {expanded
            ? <><ChevronUp   className="h-3.5 w-3.5" /> Show less</>
            : <><ChevronDown className="h-3.5 w-3.5" /> Show all {all.length} failing resources</>}
        </button>
      )}
    </div>
  );
}

// ── Code Evidence Panel ───────────────────────────────────────────────────────

interface CodeEvidenceProps {
  snippet:    string | null;   // null → header-only (link + Analyse button, no code body)
  filePath:   string;
  lineStart:  number | null;
  lineEnd:    number | null;
  githubUrl:  string | null;
  onAnalyse:  () => void;
}

function CodeEvidencePanel({ snippet, filePath, lineStart, lineEnd, githubUrl, onAnalyse }: CodeEvidenceProps) {
  const [copied, setCopied] = useState(false);

  // Attach line numbers: if snippet already has "N: code" lines keep them,
  // otherwise prefix starting from lineStart.
  const lines = snippet ? snippet.split("\n") : [];
  const alreadyNumbered = lines.length > 0 && /^\s*\d+:/.test(lines[0] ?? "");

  const numbered = alreadyNumbered
    ? lines.map((l) => {
        const m = l.match(/^\s*(\d+):\s?(.*)/s);
        return { no: m ? parseInt(m[1]) : null, code: m ? m[2] : l };
      })
    : lines.map((l, i) => ({ no: lineStart != null ? lineStart + i : null, code: l }));

  // Which line numbers are in the "vulnerable" range
  const isVulnerable = (no: number | null) =>
    no != null && lineStart != null &&
    no >= lineStart && no <= (lineEnd ?? lineStart);

  const filename = filePath.split("/").pop() ?? filePath;

  function handleCopy() {
    if (!snippet) return;
    navigator.clipboard.writeText(snippet).then(() => {
      setCopied(true);
      setTimeout(() => setCopied(false), 2000);
    });
  }

  function openGitHub() {
    if (!githubUrl) return;
    window.open(githubUrl, "gh-code-popup", "width=1200,height=780,scrollbars=yes,resizable=yes");
  }

  return (
    <div className="rounded-xl border border-gray-700 overflow-hidden">
      {/* Header bar — always shown */}
      <div className="flex items-center gap-2 border-b border-gray-700 bg-gray-800/70 px-3 py-2">
        <Code2 className="h-3.5 w-3.5 shrink-0 text-indigo-400" />
        <span
          className="flex-1 truncate font-mono text-[11px] text-indigo-300"
          title={filePath}
        >
          {filePath}
        </span>
        {lineStart && (
          <span className="shrink-0 rounded bg-gray-700 px-1.5 py-0.5 font-mono text-[10px] text-gray-400">
            L{lineStart}{lineEnd && lineEnd !== lineStart ? `–${lineEnd}` : ""}
          </span>
        )}
        {/* Copy — only when snippet is present */}
        {snippet && (
          <button
            onClick={handleCopy}
            title="Copy snippet"
            className="ml-1 flex items-center gap-1 rounded px-1.5 py-0.5 text-[11px] text-gray-500 hover:bg-gray-700 hover:text-gray-200 transition-colors"
          >
            {copied ? <Check className="h-3 w-3 text-green-400" /> : <Copy className="h-3 w-3" />}
          </button>
        )}
        {/* GitHub link — opens file at the vulnerable line in a popup */}
        {githubUrl && (
          <button
            onClick={openGitHub}
            title="View vulnerable line on GitHub"
            className="flex items-center gap-1 rounded px-2 py-0.5 text-[11px] font-medium text-gray-400 hover:bg-gray-700 hover:text-gray-100 transition-colors"
          >
            <ExternalLink className="h-3 w-3" />
            <span>View on GitHub</span>
          </button>
        )}
        {/* View Code + AI Analysis → opens full two-panel modal */}
        <button
          onClick={onAnalyse}
          className="flex items-center gap-1.5 rounded-md border border-indigo-700/40 bg-indigo-900/30 px-2.5 py-1 text-[11px] font-semibold text-indigo-300 hover:bg-indigo-800/50 hover:text-indigo-100 transition-colors"
        >
          <Sparkles className="h-3 w-3" />
          <span>View Code + AI Analysis</span>
        </button>
      </div>

      {/* Code block — only when snippet is available */}
      {snippet ? (
        <div className="overflow-x-auto bg-gray-950">
          <table className="w-full border-collapse font-mono text-[12px] leading-5">
            <tbody>
              {numbered.map((row, i) => {
                const vuln = isVulnerable(row.no);
                return (
                  <tr
                    key={i}
                    className={vuln ? "bg-yellow-500/10 border-l-2 border-yellow-400" : ""}
                  >
                    {/* Line number gutter */}
                    <td
                      className={`select-none pr-3 pl-3 text-right align-top w-[3rem] ${
                        vuln ? "text-yellow-400/80" : "text-gray-600"
                      }`}
                    >
                      {row.no ?? ""}
                    </td>
                    {/* Code */}
                    <td className={`pr-4 py-0.5 whitespace-pre ${vuln ? "text-yellow-100" : "text-gray-300"}`}>
                      {row.code}
                    </td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        </div>
      ) : (
        /* No snippet stored — show a hint row */
        <div className="flex items-center gap-2 bg-gray-900/60 px-3 py-2.5">
          <span className="text-[11px] text-gray-500">
            No code preview available at scan time
            {githubUrl && <> · use <span className="text-indigo-400">View on GitHub</span> to see the source</>}
          </span>
        </div>
      )}

      {/* Footer hint (no GitHub URL) */}
      {snippet && !githubUrl && (
        <div className="border-t border-gray-800 bg-gray-900/60 px-3 py-1.5">
          <p className="text-[10px] text-gray-600">
            Code snippet captured at scan time · {filename}
          </p>
        </div>
      )}
    </div>
  );
}

interface AIAnalysis {
  summary:      string;
  impact:       string;
  remediation:  string[];
  risk_context: string;
}

// ── SCA Subissues Panel ───────────────────────────────────────────────────────

const SEV_BADGE: Record<string, string> = {
  CRITICAL: "bg-red-900/60 text-red-300 border border-red-700/50",
  HIGH:     "bg-orange-900/60 text-orange-300 border border-orange-700/50",
  MEDIUM:   "bg-yellow-900/60 text-yellow-300 border border-yellow-700/50",
  LOW:      "bg-blue-900/60 text-blue-300 border border-blue-700/50",
  INFO:     "bg-gray-800 text-gray-400 border border-gray-700",
};

function ScaSubissuesPanel({
  rawOut,
  pkg,
  ver,
}: {
  rawOut: ScaMergedRawOutput;
  pkg:    string;
  ver:    string;
}) {
  const [expanded, setExpanded] = useState(false);
  const allCves  = (rawOut.cves ?? []).map(normalizeScaCve);
  const fixVer   = rawOut.fixVersion ?? allCves.find((c) => c.fixVersion)?.fixVersion ?? null;
  const LIMIT    = 8;
  const shown    = expanded ? allCves : allCves.slice(0, LIMIT);

  return (
    <div className="rounded-xl border border-gray-700 overflow-hidden">

      {/* ── How do I fix it? ─────────────────────────────────────────── */}
      {fixVer && (
        <div className="border-b border-gray-700 bg-gray-800/40 px-4 py-3">
          <div className="mb-1.5 flex items-center gap-2">
            <Wrench className="h-3.5 w-3.5 text-green-400" />
            <span className="text-xs font-semibold uppercase tracking-wider text-green-300">
              How do I fix it?
            </span>
          </div>
          <p className="text-sm text-gray-300 leading-relaxed">
            Update{" "}
            <code className="rounded bg-gray-800 px-1.5 py-0.5 font-mono text-indigo-300">
              {pkg}
            </code>{" "}
            from{" "}
            <code className="font-mono text-gray-400">{ver}</code>
            {" "}to{" "}
            <code className="font-mono text-green-400">{fixVer}</code>
            {" "}to resolve all {allCves.length} {allCves.length === 1 ? "vulnerability" : "vulnerabilities"}.
          </p>
        </div>
      )}

      {/* ── Subissues header row ──────────────────────────────────────── */}
      <div className="flex items-center gap-2 border-b border-gray-700 bg-gray-800/70 px-4 py-2.5">
        <Layers className="h-3.5 w-3.5 text-indigo-400" />
        <span className="text-xs font-semibold uppercase tracking-wider text-indigo-300">
          Subissues
        </span>
        <span className="ml-1 rounded-full bg-gray-700 px-2 py-0.5 text-xs font-bold text-gray-200">
          {allCves.length}
        </span>
        {/* Column labels */}
        <div className="ml-auto flex gap-8 pr-1 text-[11px] font-semibold uppercase tracking-wider text-gray-600">
          <span>Subissue</span>
          <span>Fix</span>
        </div>
      </div>

      {/* ── CVE rows ─────────────────────────────────────────────────── */}
      <div className="divide-y divide-gray-800/60">
        {shown.map((cve, i) => {
          const rowFix = cve.fixVersion ?? fixVer;
          return (
            <div
              key={i}
              className="flex items-start gap-3 px-4 py-2.5 hover:bg-gray-800/30 transition-colors"
            >
              {/* Left — CVE info */}
              <div className="min-w-0 flex-1">
                <div className="flex flex-wrap items-center gap-1.5">
                  {cve.cveId ? (
                    cve.primaryUrl ? (
                      <a
                        href={cve.primaryUrl}
                        target="_blank"
                        rel="noopener noreferrer"
                        className="font-mono text-xs text-indigo-300 hover:text-indigo-200 hover:underline"
                      >
                        {cve.cveId}
                      </a>
                    ) : (
                      <span className="font-mono text-xs text-indigo-300">{cve.cveId}</span>
                    )
                  ) : null}
                  <span
                    className={`rounded px-1.5 py-0.5 text-[10px] font-semibold ${SEV_BADGE[cve.severity] ?? SEV_BADGE.INFO}`}
                  >
                    {cve.severity.charAt(0) + cve.severity.slice(1).toLowerCase()}
                  </span>
                  {cve.cvssScore != null && (
                    <span className="text-[10px] text-gray-500">
                      CVSS {cve.cvssScore.toFixed(1)}
                    </span>
                  )}
                </div>
                {cve.filePath && (
                  <p className="mt-0.5 font-mono text-[11px] text-gray-500">{cve.filePath}</p>
                )}
                {cve.title && (
                  <p className="mt-0.5 text-[11px] text-gray-500 truncate" title={cve.title}>
                    {cve.title}
                  </p>
                )}
              </div>

              {/* Right — version arrow */}
              <div className="shrink-0 flex items-center gap-1.5 pt-0.5 text-xs">
                <span className="font-mono text-gray-500">{ver}</span>
                <span className="text-gray-600">→</span>
                <span className={`font-mono font-semibold ${rowFix ? "text-green-400" : "text-gray-600"}`}>
                  {rowFix ?? "no fix"}
                </span>
              </div>
            </div>
          );
        })}
      </div>

      {/* ── Expand / collapse ────────────────────────────────────────── */}
      {allCves.length > LIMIT && (
        <button
          onClick={() => setExpanded((v) => !v)}
          className="flex w-full items-center justify-center gap-1.5 border-t border-gray-700 bg-gray-800/50 py-2 text-xs text-gray-400 hover:bg-gray-800 hover:text-gray-200 transition-colors"
        >
          {expanded ? (
            <><ChevronUp className="h-3.5 w-3.5" /> Show less</>
          ) : (
            <><ChevronDown className="h-3.5 w-3.5" /> Show all {allCves.length} CVEs</>
          )}
        </button>
      )}
    </div>
  );
}

// ── Subissues Panel (merged SAST findings) ────────────────────────────────────

const SEV_PILL_SAST: Record<string, string> = {
  CRITICAL: "bg-red-900/70 text-red-300 border border-red-700/60",
  HIGH:     "bg-orange-900/70 text-orange-300 border border-orange-700/60",
  MEDIUM:   "bg-yellow-900/70 text-yellow-300 border border-yellow-700/60",
  LOW:      "bg-blue-900/70 text-blue-300 border border-blue-700/60",
  INFO:     "bg-gray-800 text-gray-400 border border-gray-700",
};

function SubissuesPanel({
  locations,
  repoFullName,
  defaultBranch,
  onViewCode,
}: {
  locations:      SastLocation[];
  repoFullName?:  string | null;
  defaultBranch?: string | null;
  onViewCode:     (loc: SastLocation, ghUrl: string | null) => void;
}) {
  const [expanded, setExpanded] = useState(false);
  const LIMIT = 5;
  const shown = expanded ? locations : locations.slice(0, LIMIT);

  // "owner/repo" → "repo"
  const repoName = repoFullName?.split("/").pop() ?? null;

  function locGitHubUrl(loc: SastLocation): string | null {
    if (!repoFullName || !defaultBranch || !loc.filePath) return null;
    const path   = loc.filePath.replace(/^\/+/, "");
    const anchor = loc.lineStart ? `#L${loc.lineStart}` : "";
    return `https://github.com/${repoFullName}/blob/${defaultBranch}/${path}${anchor}`;
  }

  return (
    <div className="overflow-hidden rounded-xl border border-gray-700">

      {/* ── Header ────────────────────────────────────────────────────── */}
      <div className="flex items-center gap-2 border-b border-gray-700 bg-gray-800/70 px-4 py-2.5">
        <Layers className="h-3.5 w-3.5 text-indigo-400" />
        <span className="text-xs font-semibold uppercase tracking-wider text-indigo-300">
          Subissues
        </span>
        <span className="ml-1 rounded-full bg-gray-700 px-2 py-0.5 text-xs font-bold text-gray-200">
          {locations.length}
        </span>
        <span className="ml-auto text-[11px] font-semibold uppercase tracking-wider text-gray-600">
          Subissue
        </span>
      </div>

      {/* ── Repo grouping row ─────────────────────────────────────────── */}
      {repoName && (
        <div className="flex items-center gap-2 border-b border-indigo-900/50 bg-indigo-900/30 px-4 py-2">
          <span className="rounded bg-indigo-800/60 px-1.5 py-0.5 text-[10px] font-semibold text-indigo-300">
            {repoName}
          </span>
          {repoFullName && (
            <span className="text-[11px] text-indigo-400/70">{repoFullName.split("/")[0]}</span>
          )}
        </div>
      )}

      {/* ── Location rows ─────────────────────────────────────────────── */}
      <div className="divide-y divide-gray-800/60">
        {shown.map((loc, i) => {
          const filename  = loc.filePath?.split("/").pop() ?? "unknown";
          const lineLabel = loc.lineStart
            ? `Line ${loc.lineStart}${loc.lineEnd && loc.lineEnd !== loc.lineStart ? `–${loc.lineEnd}` : ""} in ${filename}`
            : null;
          const ghUrl = locGitHubUrl(loc);
          const sev   = loc.severity?.toUpperCase() ?? "INFO";

          return (
            <div key={i} className="p-4 hover:bg-gray-800/20 transition-colors">

              {/* File path + severity pill */}
              <div className="mb-1 flex items-start justify-between gap-3">
                <p
                  className="break-all font-mono text-[11px] leading-relaxed text-gray-300"
                  title={loc.filePath ?? ""}
                >
                  {loc.filePath ?? "unknown file"}
                </p>
                <span className={`shrink-0 rounded-full px-2 py-0.5 text-[10px] font-semibold ${SEV_PILL_SAST[sev] ?? SEV_PILL_SAST.INFO}`}>
                  • {sev.charAt(0) + sev.slice(1).toLowerCase()}
                </span>
              </div>

              {/* Line label */}
              {lineLabel && (
                <p className="mb-2 text-[11px] text-indigo-400">{lineLabel}</p>
              )}

              {/* Code snippet — skip Semgrep "requires login" placeholder */}
              {(() => {
                const s = loc.snippet?.trim();
                const clean = s && !/^requires?\s+login$/i.test(s) ? s : null;
                return clean ? (
                  <SyntaxHighlight
                    code={clean}
                    filePath={loc.filePath}
                    lineStart={loc.lineStart}
                    lineEnd={loc.lineEnd}
                    compact
                  />
                ) : ghUrl ? (
                  <p className="text-[11px] text-gray-500">
                    No code preview — use <span className="text-indigo-400">View on GitHub</span> to see the source
                  </p>
                ) : null;
              })()}

              {/* Actions row */}
              <div className="mt-2 flex items-center gap-3">
                {ghUrl && (
                  <button
                    onClick={() => window.open(ghUrl, "gh-subissue", "width=1200,height=780,scrollbars=yes")}
                    className="flex items-center gap-1 text-[11px] text-indigo-400 hover:text-indigo-300 transition-colors"
                  >
                    <ExternalLink className="h-3 w-3" />
                    View on GitHub
                  </button>
                )}
                <button
                  onClick={() => onViewCode(loc, ghUrl)}
                  className="flex items-center gap-1.5 rounded-md border border-indigo-700/40 bg-indigo-900/30 px-2 py-0.5 text-[11px] font-semibold text-indigo-300 hover:bg-indigo-800/50 hover:text-indigo-100 transition-colors"
                >
                  <Sparkles className="h-3 w-3" />
                  View Code + AI Analysis
                </button>
              </div>
            </div>
          );
        })}
      </div>

      {/* ── Expand / collapse ─────────────────────────────────────────── */}
      {locations.length > LIMIT && (
        <button
          onClick={() => setExpanded((v) => !v)}
          className="flex w-full items-center justify-center gap-1.5 border-t border-gray-700 bg-gray-800/50 py-2 text-xs text-gray-400 hover:bg-gray-800 hover:text-gray-200 transition-colors"
        >
          {expanded
            ? <><ChevronUp className="h-3.5 w-3.5" /> Show less</>
            : <><ChevronDown className="h-3.5 w-3.5" /> Show all {locations.length} locations</>}
        </button>
      )}
    </div>
  );
}

// ── Code Analysis Modal ───────────────────────────────────────────────────────

/** When a sub-location is opened, override the code panel with that location's data. */
interface LocationOverride {
  filePath:  string | null;
  lineStart: number | null;
  lineEnd:   number | null;
  snippet:   string | null;
  githubUrl: string | null;
}

interface CodeAnalysisModalProps {
  finding:          Finding & Record<string, unknown>;
  snippet:          string | null;
  githubUrl:        string | null;
  repoInfo:         { fullName: string; defaultBranch: string } | null;
  locationOverride?: LocationOverride | null;  // when set, code panel shows this location
  onClose:          () => void;
}

function CodeAnalysisModal({ finding, snippet, githubUrl, repoInfo, locationOverride, onClose }: CodeAnalysisModalProps) {
  const qc = useQueryClient();
  const f  = finding as Finding & {
    aiAnalysis?:      AIAnalysis;
    aiFixSuggestion?: string | null;
  };

  const [localAnalysis, setLocalAnalysis] = useState<{ analysis: AIAnalysis; aiAnalysedAt: string } | null>(null);
  const [localFix, setLocalFix]           = useState<{ diff: string; aiFixSuggestedAt: string } | null>(null);

  const analyse    = useMutation({
    mutationFn: (force: boolean) => findingsApi.analyse(finding.id, force),
    onSuccess:  (data) => { setLocalAnalysis(data); qc.invalidateQueries({ queryKey: ["findings"] }); },
  });
  const suggestFix = useMutation({
    mutationFn: (force: boolean) => findingsApi.fixSuggestion(finding.id, force),
    onSuccess:  (data) => { setLocalFix(data); qc.invalidateQueries({ queryKey: ["findings"] }); },
  });

  // Auto-trigger on open
  useEffect(() => {
    if (!f.aiAnalysis) analyse.mutate(false);
    if (!f.aiFixSuggestion) suggestFix.mutate(false);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  const shownAnalysis = localAnalysis?.analysis   ?? f.aiAnalysis        ?? null;
  const shownFix      = localFix?.diff             ?? f.aiFixSuggestion   ?? null;

  // Code panel resolves from locationOverride first, then primary finding
  const codeFilePath  = locationOverride?.filePath  ?? (finding.filePath  as string | null) ?? null;
  const codeLineStart = locationOverride?.lineStart  ?? (finding.lineStart as number | null) ?? null;
  const codeLineEnd   = locationOverride?.lineEnd    ?? (finding.lineEnd   as number | null) ?? null;
  const codeSnippet   = locationOverride?.snippet    ?? snippet;
  const codeGithubUrl = locationOverride?.githubUrl  ?? githubUrl;

  // (line parsing and vuln highlighting is handled by <SyntaxHighlight>)

  return (
    <div className="fixed inset-0 z-[60] flex items-center justify-center p-4">
      {/* Backdrop */}
      <div className="absolute inset-0 bg-black/75 backdrop-blur-sm" onClick={onClose} />

      {/* Modal shell */}
      <div className="relative z-10 flex h-[92vh] w-full max-w-6xl overflow-hidden rounded-2xl border border-gray-700 bg-gray-900 shadow-2xl">

        {/* ── Left panel — AI info ──────────────────────────────────────── */}
        <div className="flex w-[36%] shrink-0 flex-col overflow-y-auto border-r border-gray-700 p-5 space-y-4">

          {/* Finding title + meta */}
          <div className="space-y-2">
            <div className="flex flex-wrap gap-1.5">
              <SeverityBadge severity={finding.severity} />
              <span className="rounded bg-gray-800 px-2 py-0.5 text-xs text-gray-400">{finding.scanType}</span>
              <span className="rounded bg-gray-800 px-2 py-0.5 text-xs text-gray-400">{finding.scanner as string}</span>
            </div>
            <h2 className="text-sm font-semibold leading-snug text-white">{finding.title}</h2>
            <p className="text-xs text-gray-500">First seen {formatDate(finding.firstSeen)}</p>
          </div>

          {/* Description */}
          <div className="rounded-lg bg-gray-800/50 p-3">
            <p className="text-xs text-gray-300 leading-relaxed">{finding.description as string}</p>
          </div>

          {/* AI Autotriage Summary */}
          <div className="rounded-xl border border-indigo-800/40 bg-indigo-950/30 overflow-hidden">
            <div className="flex items-center gap-2 border-b border-indigo-800/30 bg-indigo-950/40 px-4 py-2.5">
              <Sparkles className="h-3.5 w-3.5 text-indigo-400" />
              <span className="flex-1 text-xs font-semibold uppercase tracking-wider text-indigo-300">
                AI Autotriage Summary
              </span>
              {/* Auto-triage badge — shown when pre-populated by the background worker */}
              {!analyse.isPending && shownAnalysis && (finding as Record<string, unknown>)["aiAnalysedAt"] && !localAnalysis && (
                <span title="Pre-analysed automatically after scan" className="inline-flex items-center gap-1 rounded-full bg-emerald-900/50 px-1.5 py-0.5 text-[10px] font-semibold text-emerald-400 border border-emerald-800/50">
                  <Sparkles className="h-2.5 w-2.5" /> Auto
                </span>
              )}
              {analyse.isPending && <Loader2 className="h-3 w-3 text-indigo-400 animate-spin" />}
            </div>
            <div className="p-4">
              {analyse.isPending && !shownAnalysis ? (
                <div className="flex items-center gap-2 text-xs text-indigo-400">
                  <Loader2 className="h-3.5 w-3.5 animate-spin" />
                  Analysing…
                </div>
              ) : shownAnalysis ? (
                <div className="space-y-3 text-xs">
                  <p className="text-gray-300 leading-relaxed">{shownAnalysis.summary}</p>
                  <div>
                    <p className="mb-1 font-semibold text-amber-400">Impact</p>
                    <p className="text-gray-400 leading-relaxed">{shownAnalysis.impact}</p>
                  </div>
                  {shownAnalysis.remediation?.length > 0 && (
                    <div>
                      <p className="mb-1.5 font-semibold text-green-400">How to fix</p>
                      <ol className="space-y-1.5">
                        {shownAnalysis.remediation.map((step, i) => (
                          <li key={i} className="flex gap-2 text-gray-400">
                            <span className="shrink-0 font-bold text-green-500">{i + 1}.</span>
                            {step}
                          </li>
                        ))}
                      </ol>
                    </div>
                  )}
                  <div className="rounded bg-gray-900/70 px-2.5 py-2 text-gray-500 italic">
                    {shownAnalysis.risk_context}
                  </div>
                </div>
              ) : (
                <button
                  onClick={() => analyse.mutate(false)}
                  className="text-xs text-indigo-400 hover:text-indigo-300"
                >
                  Run analysis →
                </button>
              )}
            </div>
          </div>
        </div>

        {/* ── Right panel — code + autofix ─────────────────────────────── */}
        <div className="flex flex-1 flex-col overflow-hidden">

          {/* Code panel header */}
          <div className="flex items-center gap-2 border-b border-gray-700 bg-gray-800/60 px-4 py-2.5">
            <Code2 className="h-3.5 w-3.5 shrink-0 text-indigo-400" />
            <span className="flex-1 truncate font-mono text-[11px] text-indigo-300" title={codeFilePath ?? ""}>
              {codeFilePath ?? "—"}
            </span>
            {codeLineStart != null && (
              <span className="shrink-0 rounded bg-gray-700 px-1.5 py-0.5 font-mono text-[10px] text-gray-400">
                L{codeLineStart}{codeLineEnd && codeLineEnd !== codeLineStart ? `–${codeLineEnd}` : ""}
              </span>
            )}
            {locationOverride && (
              <span className="shrink-0 rounded-full bg-indigo-900/50 border border-indigo-700/40 px-2 py-0.5 text-[10px] font-medium text-indigo-400">
                sub-location
              </span>
            )}
            {/* Generating AutoFix pill */}
            {suggestFix.isPending && (
              <span className="flex items-center gap-1.5 rounded-full border border-green-700/40 bg-green-900/40 px-2.5 py-1 text-[11px] font-medium text-green-300">
                <Loader2 className="h-3 w-3 animate-spin" />
                Generating AutoFix…
              </span>
            )}
            {codeGithubUrl && (
              <button
                onClick={() => window.open(codeGithubUrl, "gh-popup", "width=1200,height=780,scrollbars=yes")}
                className="flex items-center gap-1 rounded px-2 py-0.5 text-[11px] text-gray-400 hover:text-gray-200 transition-colors"
              >
                <ExternalLink className="h-3 w-3" />
                GitHub
              </button>
            )}
            <button onClick={onClose} className="ml-1 text-gray-500 hover:text-gray-200">
              <X className="h-4 w-4" />
            </button>
          </div>

          {/* Scrollable code + diff area */}
          <div className="flex-1 overflow-auto bg-gray-950">
            {codeSnippet ? (
              <div>
                {/* ── Syntax-highlighted code ──────────────────────── */}
                <SyntaxHighlight
                  code={codeSnippet}
                  filePath={codeFilePath}
                  lineStart={codeLineStart}
                  lineEnd={codeLineEnd}
                />

                {/* ── Inline AutoFix ──────────────────────────────── */}
                {shownFix && (
                  <div className="px-4 py-4">
                    <div className="overflow-hidden rounded-xl border border-green-800/50">
                      {/* AutoFix header */}
                      <div className="flex items-center gap-3 bg-green-950/50 px-4 py-2.5 border-b border-green-800/40">
                        <span className="rounded bg-green-800/60 px-2 py-0.5 text-[11px] font-bold text-green-300">
                          AutoFix
                        </span>
                        <span className="text-[11px] text-green-400/80 truncate">
                          AI-generated patch for {(finding.title as string).toLowerCase()}
                        </span>
                        {/* Auto badge when pre-generated by background triage worker */}
                        {!localFix && (finding as Record<string, unknown>)["aiFixSuggestedAt"] && (
                          <span title="Pre-generated automatically after scan" className="shrink-0 inline-flex items-center gap-1 rounded-full bg-emerald-900/50 px-1.5 py-0.5 text-[10px] font-semibold text-emerald-400 border border-emerald-800/50">
                            <Sparkles className="h-2.5 w-2.5" /> Auto
                          </span>
                        )}
                        <button
                          onClick={() => suggestFix.mutate(true)}
                          disabled={suggestFix.isPending}
                          className="ml-auto flex items-center gap-1 rounded px-2 py-0.5 text-[11px] text-green-500 hover:text-green-300 transition-colors disabled:opacity-40"
                        >
                          <RefreshCw className={`h-3 w-3 ${suggestFix.isPending ? "animate-spin" : ""}`} />
                          Regenerate
                        </button>
                      </div>
                      <DiffViewer diff={shownFix} />
                    </div>
                  </div>
                )}

                {/* Placeholder while fix is generating */}
                {suggestFix.isPending && !shownFix && (
                  <div className="px-4 py-4">
                    <div className="flex items-center gap-3 rounded-xl border border-green-800/30 bg-green-950/20 px-4 py-4">
                      <Loader2 className="h-4 w-4 animate-spin text-green-400" />
                      <span className="text-sm text-green-400">Generating AutoFix patch…</span>
                    </div>
                  </div>
                )}
              </div>
            ) : (
              <div className="flex h-32 items-center justify-center text-sm text-gray-500">
                No code snippet available
              </div>
            )}
          </div>
        </div>
      </div>
    </div>
  );
}

interface Props {
  finding: Finding | null;
  onClose: () => void;
}

// ── AI Analysis Panel ─────────────────────────────────────────────────────────

function AIAnalysisPanel({
  analysis,
  analysedAt,
  onReanalyse,
  isPending,
}: {
  analysis: AIAnalysis;
  analysedAt: string;
  onReanalyse: () => void;
  isPending: boolean;
}) {
  return (
    <div className="rounded-xl border border-indigo-800/50 bg-indigo-950/40 overflow-hidden">
      {/* Header */}
      <div className="flex items-center justify-between border-b border-indigo-800/40 px-4 py-2.5">
        <div className="flex items-center gap-2">
          <Sparkles className="h-3.5 w-3.5 text-indigo-400" />
          <span className="text-xs font-semibold text-indigo-300 uppercase tracking-wider">
            AI Analysis
          </span>
        </div>
        <div className="flex items-center gap-3">
          <span className="text-[10px] text-indigo-500">{formatDate(analysedAt)}</span>
          <button
            onClick={onReanalyse}
            disabled={isPending}
            className="flex items-center gap-1 rounded px-2 py-0.5 text-[11px] text-indigo-400 hover:text-indigo-200 hover:bg-indigo-900/50 transition-colors disabled:opacity-40"
            title="Re-analyse with AI"
          >
            <RefreshCw className={`h-3 w-3 ${isPending ? "animate-spin" : ""}`} />
            Re-analyse
          </button>
        </div>
      </div>

      <div className="space-y-4 p-4">
        {/* Summary */}
        <div>
          <div className="mb-1.5 flex items-center gap-1.5">
            <Info className="h-3.5 w-3.5 text-blue-400" />
            <span className="text-xs font-semibold text-blue-300">What this is</span>
          </div>
          <p className="text-sm text-gray-300 leading-relaxed">{analysis.summary}</p>
        </div>

        {/* Impact */}
        <div>
          <div className="mb-1.5 flex items-center gap-1.5">
            <AlertTriangle className="h-3.5 w-3.5 text-amber-400" />
            <span className="text-xs font-semibold text-amber-300">Business impact</span>
          </div>
          <p className="text-sm text-gray-300 leading-relaxed">{analysis.impact}</p>
        </div>

        {/* Remediation steps */}
        <div>
          <div className="mb-2 flex items-center gap-1.5">
            <Wrench className="h-3.5 w-3.5 text-green-400" />
            <span className="text-xs font-semibold text-green-300">How to fix it</span>
          </div>
          <ol className="space-y-1.5">
            {analysis.remediation.map((step, i) => (
              <li key={i} className="flex gap-2.5 text-sm text-gray-300">
                <span className="mt-0.5 flex h-5 w-5 flex-shrink-0 items-center justify-center rounded-full bg-green-900/50 text-[10px] font-bold text-green-400">
                  {i + 1}
                </span>
                <span className="leading-relaxed">{step}</span>
              </li>
            ))}
          </ol>
        </div>

        {/* Risk context */}
        <div className="rounded-lg bg-gray-900/60 px-3 py-2.5">
          <div className="mb-1.5 flex items-center gap-1.5">
            <BookOpen className="h-3.5 w-3.5 text-gray-400" />
            <span className="text-xs font-semibold text-gray-400">Risk context</span>
          </div>
          <p className="text-xs text-gray-400 leading-relaxed">{analysis.risk_context}</p>
        </div>
      </div>
    </div>
  );
}

// ── Loading state ─────────────────────────────────────────────────────────────

function AILoadingPanel() {
  return (
    <div className="flex flex-col items-center justify-center gap-3 rounded-xl border border-indigo-800/30 bg-indigo-950/20 py-8">
      <div className="relative">
        <Sparkles className="h-6 w-6 text-indigo-400" />
        <span className="absolute -top-1 -right-1 flex h-2.5 w-2.5">
          <span className="animate-ping absolute inline-flex h-full w-full rounded-full bg-indigo-400 opacity-75" />
          <span className="relative inline-flex rounded-full h-2.5 w-2.5 bg-indigo-500" />
        </span>
      </div>
      <div className="text-center">
        <p className="text-sm font-medium text-indigo-300">AI is analysing this finding…</p>
        <p className="mt-0.5 text-xs text-indigo-500">May take 20–60 seconds on CPU</p>
      </div>
      <div className="flex gap-1">
        {[0, 1, 2].map((i) => (
          <span
            key={i}
            className="h-1.5 w-1.5 rounded-full bg-indigo-500 animate-bounce"
            style={{ animationDelay: `${i * 150}ms` }}
          />
        ))}
      </div>
    </div>
  );
}

// ── FP Panel ──────────────────────────────────────────────────────────────────

const VERDICT_CFG = {
  LIKELY_FP: {
    icon: CheckCircle2,
    label: "Likely False Positive",
    color: "text-green-400",
    bg:    "border-green-800/40 bg-green-950/20",
    headerBg: "border-b border-green-800/30",
  },
  LIKELY_REAL: {
    icon: XCircle,
    label: "Likely Real Threat",
    color: "text-red-400",
    bg:    "border-red-800/40 bg-red-950/20",
    headerBg: "border-b border-red-800/30",
  },
  UNCERTAIN: {
    icon: HelpCircle,
    label: "Uncertain — Needs Review",
    color: "text-yellow-400",
    bg:    "border-yellow-800/40 bg-yellow-950/20",
    headerBg: "border-b border-yellow-800/30",
  },
} as const;

const CONF_COLOR: Record<string, string> = {
  HIGH:   "text-white bg-gray-700",
  MEDIUM: "text-gray-300 bg-gray-800",
  LOW:    "text-gray-500 bg-gray-800",
};

function FpPanel({
  analysis,
  analysedAt,
  onRecheck,
  isPending,
  onMarkFp,
  isMarkingFp,
}: {
  analysis:    FpAnalysis;
  analysedAt:  string;
  onRecheck:   () => void;
  isPending:   boolean;
  onMarkFp:    () => void;
  isMarkingFp: boolean;
}) {
  const cfg = VERDICT_CFG[analysis.verdict];
  const VerdictIcon = cfg.icon;

  return (
    <div className={`rounded-xl border overflow-hidden ${cfg.bg}`}>
      {/* Header */}
      <div className={`flex items-center justify-between px-4 py-2.5 ${cfg.headerBg}`}>
        <div className="flex items-center gap-2">
          <Sparkles className="h-3.5 w-3.5 text-indigo-400" />
          <span className="text-xs font-semibold text-indigo-300 uppercase tracking-wider">
            AI False Positive Check
          </span>
        </div>
        <div className="flex items-center gap-3">
          <span className="text-[10px] text-gray-500">{formatDate(analysedAt)}</span>
          <button
            onClick={onRecheck}
            disabled={isPending}
            className="flex items-center gap-1 rounded px-2 py-0.5 text-[11px] text-indigo-400 hover:text-indigo-200 hover:bg-indigo-900/40 transition-colors disabled:opacity-40"
          >
            <RefreshCw className={`h-3 w-3 ${isPending ? "animate-spin" : ""}`} />
            Re-check
          </button>
        </div>
      </div>

      <div className="p-4 space-y-3">
        {/* Verdict row */}
        <div className="flex items-center justify-between">
          <div className="flex items-center gap-2">
            <VerdictIcon className={`h-5 w-5 ${cfg.color}`} />
            <span className={`text-sm font-semibold ${cfg.color}`}>{cfg.label}</span>
          </div>
          <span className={`rounded px-2 py-0.5 text-[11px] font-semibold ${CONF_COLOR[analysis.confidence]}`}>
            {analysis.confidence} confidence
          </span>
        </div>

        {/* Reasoning */}
        <p className="text-sm text-gray-300 leading-relaxed">{analysis.reasoning}</p>

        {/* Indicators */}
        {analysis.indicators.length > 0 && (
          <ul className="space-y-1">
            {analysis.indicators.map((ind, i) => (
              <li key={i} className="flex items-start gap-2 text-xs text-gray-400">
                <span className={`mt-0.5 h-1.5 w-1.5 flex-shrink-0 rounded-full ${cfg.color}`} />
                {ind}
              </li>
            ))}
          </ul>
        )}

        {/* Action — only offered for FP verdict */}
        {analysis.verdict === "LIKELY_FP" && (
          <button
            onClick={onMarkFp}
            disabled={isMarkingFp}
            className="flex w-full items-center justify-center gap-2 rounded-lg bg-green-900/40 border border-green-800/50 px-3 py-2 text-xs font-semibold text-green-300 hover:bg-green-900/60 disabled:opacity-50 transition-colors"
          >
            <CheckCircle2 className="h-3.5 w-3.5" />
            {isMarkingFp ? "Ignoring…" : "Accept AI verdict — Ignore this finding"}
          </button>
        )}
      </div>
    </div>
  );
}

// ── Main Drawer ───────────────────────────────────────────────────────────────

export default function FindingDetailDrawer({ finding, onClose }: Props) {
  const [showRaw, setShowRaw]             = useState(false);
  const [showCodeModal, setShowCodeModal] = useState(false);
  const [codeModalOverride, setCodeModalOverride] = useState<LocationOverride | null>(null);
  const [showEvidence, setShowEvidence]   = useState(false);
  const [linkCopied, setLinkCopied] = useState(false);
  const [verifyResult, setVerifyResult] = useState<{
    confirmed: boolean;
    confidence: string;
    evidence: Record<string, unknown>;
  } | null>(null);

  // Local AI state overrides what's cached in the finding record
  const [localAnalysis, setLocalAnalysis] = useState<{
    analysis: AIAnalysis;
    aiAnalysedAt: string;
  } | null>(null);

  // Local FP analysis state
  const [localFp, setLocalFp] = useState<{
    analysis: FpAnalysis;
    aiFpAnalysedAt: string;
  } | null>(null);

  const qc = useQueryClient();

  const updateStatus = useMutation({
    mutationFn: (status: string) =>
      findingsApi.update(finding!.id, { status: status as never }),
    onSuccess: () => qc.invalidateQueries({ queryKey: ["findings"] }),
  });

  const createTicket = useMutation({
    mutationFn: () =>
      ticketsApi.create({
        findingId: finding!.id,
        title: finding!.title,
        priority: finding!.severity as never,
        createJiraIssue: false,
      }),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ["tickets"] });
      qc.invalidateQueries({ queryKey: ["findings"] });
    },
  });

  const verify = useMutation({
    mutationFn: () => findingsApi.verify(finding!.id),
    onSuccess: (data) => {
      setVerifyResult({ confirmed: data.confirmed, confidence: data.confidence, evidence: data.evidence });
      qc.invalidateQueries({ queryKey: ["findings"] });
    },
  });

  const analyse = useMutation({
    mutationFn: (force: boolean) => findingsApi.analyse(finding!.id, force),
    onSuccess: (data) => {
      setLocalAnalysis(data);
      qc.invalidateQueries({ queryKey: ["findings"] });
    },
  });

  const checkFp = useMutation({
    mutationFn: (force: boolean) => findingsApi.checkFp(finding!.id, force),
    onSuccess: (data) => {
      setLocalFp(data);
      qc.invalidateQueries({ queryKey: ["findings"] });
    },
  });

  if (!finding) return null;

  // Auto-load AI analysis when the drawer opens for this finding
  // eslint-disable-next-line react-hooks/rules-of-hooks
  useEffect(() => {
    const cached = (finding as Finding & { aiAnalysis?: AIAnalysis }).aiAnalysis;
    if (!cached && !localAnalysis) analyse.mutate(false);
  // finding.id changing means a different finding was opened
  // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [finding.id]);

  const canVerify = ["DAST", "PENTEST_FULL"].includes(finding.scanType);

  // ── Detect merged findings ────────────────────────────────────────────────
  const rawOut          = finding.rawOutput as unknown as (MergedRawOutput & ScaMergedRawOutput & DastMergedRawOutput & SecretMergedRawOutput & IacMergedRawOutput) | undefined;
  const isMerged        = rawOut?.merged === true && finding.scanType === "SAST" && Array.isArray(rawOut?.locations);
  const isScaMerged     = rawOut?.merged === true && (finding.scanType === "SCA" || finding.scanType === "CONTAINER") && Array.isArray(rawOut?.cves);
  const isDastMerged    = rawOut?.merged === true
    && ["DAST", "PENTEST", "PENTEST_FULL"].includes(finding.scanType)
    && Array.isArray(rawOut?.occurrences);
  const isSecretMerged  = rawOut?.merged === true
    && finding.scanType === "SECRET"
    && Array.isArray(rawOut?.occurrences);
  const isIacMerged     = rawOut?.merged === true
    && finding.scanType === "IAC"
    && Array.isArray((rawOut as unknown as IacMergedRawOutput)?.resources);
  const locations: SastLocation[] = isMerged ? rawOut!.locations : [];
  const dastOccurrences: DastOccurrence[] = isDastMerged ? rawOut!.occurrences : [];
  const secretOccurrences: SecretOccurrence[] = isSecretMerged ? (rawOut!.occurrences as unknown as SecretOccurrence[]) : [];
  const iacResources: IacResource[] = isIacMerged ? (rawOut as unknown as IacMergedRawOutput).resources : [];

  // ── Build GitHub URL ──────────────────────────────────────────────────────
  const repoInfo = finding.repository ?? null;
  const githubUrl = (() => {
    if (!repoInfo || !finding.filePath) return null;
    const path   = finding.filePath.replace(/^\/+/, "");
    const anchor = finding.lineStart
      ? `#L${finding.lineStart}${finding.lineEnd && finding.lineEnd !== finding.lineStart ? `-L${finding.lineEnd}` : ""}`
      : "";
    return `https://github.com/${repoInfo.fullName}/blob/${repoInfo.defaultBranch}/${path}${anchor}`;
  })();

  // ── Extract code snippet (priority order) ─────────────────────────────────
  const codeSnippet = (() => {
    const candidates: (string | null | undefined)[] = [];

    // 1. Merged SAST — primary location snippet stored in locations[]
    if (isMerged) candidates.push(rawOut?.locations?.[0]?.snippet);

    // 2. codeSnippet column — backfilled for IAC/SAST/SECRET at scan time
    candidates.push(finding.codeSnippet);

    // 3. Semgrep extra.lines stored in rawOutput
    const extra = finding.rawOutput?.["extra"] as Record<string, unknown> | undefined;
    candidates.push(typeof extra?.["lines"] === "string" ? extra["lines"] : null);

    // 4. Merged SAST — primary raw output extra.lines
    const primary = finding.rawOutput?.["primary"] as Record<string, unknown> | undefined;
    const pExtra  = primary?.["extra"] as Record<string, unknown> | undefined;
    candidates.push(typeof pExtra?.["lines"] === "string" ? pExtra["lines"] : null);

    for (const c of candidates) {
      if (!c) continue;
      const trimmed = c.trim();
      if (!trimmed) continue;
      if (/^requires?\s+login$/i.test(trimmed)) continue;
      return trimmed;
    }
    return null;
  })();

  // ── AI analysis — prefer locally-fetched over DB-cached ──────────────────
  const shownAnalysis   = localAnalysis?.analysis   ?? (finding.aiAnalysis as AIAnalysis | null | undefined) ?? null;
  const shownAnalysedAt = localAnalysis?.aiAnalysedAt ?? (finding.aiAnalysedAt ? String(finding.aiAnalysedAt) : null) ?? null;
  const hasAnalysis     = shownAnalysis !== null && shownAnalysedAt !== null;

  // ── FP analysis — prefer locally-fetched over DB-cached ──────────────────
  const shownFp  = localFp?.analysis       ?? finding.aiFpAnalysis ?? null;
  const shownFpAt= localFp?.aiFpAnalysedAt ?? (finding.aiFpAnalysedAt ? String(finding.aiFpAnalysedAt) : null) ?? null;
  const hasFp    = shownFp !== null && shownFpAt !== null;


  return (
    <div className="fixed inset-0 z-50 flex justify-end">
      {/* Backdrop */}
      <div className="absolute inset-0 bg-black/60" onClick={onClose} />

      {/* Drawer panel */}
      <div className="relative z-10 flex h-full w-full max-w-xl flex-col bg-gray-900 shadow-2xl">

        {/* ── Header ───────────────────────────────────────────────────── */}
        <div className="flex items-start justify-between border-b border-gray-800 p-5">
          <div className="flex-1 pr-4">
            {/* Tracking ID row */}
            <div className="mb-2 flex items-center gap-2">
              <span className="font-mono text-xs font-semibold text-indigo-400 bg-indigo-950/50 border border-indigo-800/50 rounded px-2 py-0.5 select-all">
                #{finding.id.slice(0, 8).toUpperCase()}
              </span>
              <button
                onClick={async () => {
                  const url = `${window.location.origin}/findings?id=${finding.id}`;
                  await navigator.clipboard.writeText(url);
                  setLinkCopied(true);
                  setTimeout(() => setLinkCopied(false), 2000);
                }}
                className="flex items-center gap-1 rounded px-1.5 py-0.5 text-[11px] text-gray-500 hover:text-gray-200 hover:bg-gray-800 transition-colors"
                title="Copy link to this finding"
              >
                {linkCopied
                  ? <><Check className="h-3 w-3 text-green-400" /><span className="text-green-400">Copied!</span></>
                  : <><Link className="h-3 w-3" /><span>Copy link</span></>
                }
              </button>
            </div>
            <div className="mb-2 flex flex-wrap items-center gap-2">
              <SeverityBadge severity={finding.severity} />
              <ConfidenceBadge confidence={finding.confidence} />
              <span className="rounded bg-gray-800 px-2 py-0.5 text-xs text-gray-400">
                {finding.scanType}
              </span>
              <span className="rounded bg-gray-800 px-2 py-0.5 text-xs text-gray-400">
                {finding.scanner}
              </span>
            </div>
            <h2 className="text-base font-semibold text-white">
              {finding.title}
              {(isMerged || isScaMerged || isDastMerged) && (
                <span className="ml-2 inline-flex items-center gap-1 rounded-full bg-gray-800 px-2 py-0.5 text-xs font-medium text-gray-400">
                  {isDastMerged
                    ? <Globe  className="h-3 w-3" />
                    : <Layers className="h-3 w-3" />}
                  {isDastMerged
                    ? `${dastOccurrences.length} URL${dastOccurrences.length !== 1 ? "s" : ""}`
                    : isScaMerged
                      ? `${(rawOut?.cves ?? []).length} CVE${(rawOut?.cves ?? []).length !== 1 ? "s" : ""}`
                      : `${locations.length} location${locations.length !== 1 ? "s" : ""}`}
                </span>
              )}
            </h2>
          </div>
          <button onClick={onClose} className="text-gray-500 hover:text-gray-200">
            <X className="h-5 w-5" />
          </button>
        </div>

        {/* ── Scrollable body ───────────────────────────────────────────── */}
        <div className="flex-1 overflow-y-auto p-5 space-y-5">

          {/* Verify result banner */}
          {verifyResult && (
            <div className={`rounded-lg border p-3 ${
              verifyResult.confirmed
                ? "border-red-700/50 bg-red-900/20 text-red-300"
                : "border-green-700/50 bg-green-900/20 text-green-300"
            }`}>
              <p className="text-sm font-medium">
                {verifyResult.confirmed
                  ? `Re-verification confirmed: ${verifyResult.confidence}`
                  : "Re-verification: finding no longer detected — may have been fixed"}
              </p>
              {!!verifyResult.evidence?.detail && (
                <p className="mt-1 text-xs opacity-75">{String(verifyResult.evidence.detail)}</p>
              )}
            </div>
          )}

          {/* ── AI Autotriage — loads automatically when drawer opens ──── */}
          {analyse.isPending || (!hasAnalysis && !analyse.isError) ? (
            <AILoadingPanel />
          ) : hasAnalysis ? (
            <AIAnalysisPanel
              analysis={shownAnalysis!}
              analysedAt={shownAnalysedAt!}
              onReanalyse={() => analyse.mutate(true)}
              isPending={analyse.isPending}
            />
          ) : (
            /* Only reached on error */
            <div className="rounded-xl border border-red-800/50 bg-red-950/20 px-4 py-3 flex items-center justify-between gap-3">
              <p className="text-xs text-red-300">{(analyse.error as Error | null)?.message ?? "Analysis failed"}</p>
              <button
                onClick={() => analyse.mutate(false)}
                className="shrink-0 flex items-center gap-1.5 rounded px-2.5 py-1 text-xs font-medium text-red-300 hover:bg-red-900/40 transition-colors"
              >
                <RefreshCw className="h-3 w-3" />
                Retry
              </button>
            </div>
          )}

          {/* ── AI False Positive Check ──────────────────────────────────── */}
          {checkFp.isPending ? (
            <div className="flex flex-col items-center justify-center gap-3 rounded-xl border border-indigo-800/30 bg-indigo-950/20 py-6">
              <div className="relative">
                <Sparkles className="h-5 w-5 text-indigo-400" />
                <span className="absolute -top-1 -right-1 flex h-2.5 w-2.5">
                  <span className="animate-ping absolute inline-flex h-full w-full rounded-full bg-indigo-400 opacity-75" />
                  <span className="relative inline-flex rounded-full h-2.5 w-2.5 bg-indigo-500" />
                </span>
              </div>
              <div className="text-center">
                <p className="text-sm font-medium text-indigo-300">Checking for false positive…</p>
                <p className="mt-0.5 text-xs text-indigo-500">May take 20–60 seconds on CPU</p>
              </div>
            </div>
          ) : hasFp ? (
            <FpPanel
              analysis={shownFp!}
              analysedAt={shownFpAt!}
              onRecheck={() => checkFp.mutate(true)}
              isPending={checkFp.isPending}
              onMarkFp={() => updateStatus.mutate("IGNORED")}
              isMarkingFp={updateStatus.isPending}
            />
          ) : (
            <button
              onClick={() => checkFp.mutate(false)}
              className="flex w-full items-center justify-center gap-2.5 rounded-xl border border-dashed border-indigo-700/50 bg-indigo-950/20 py-3.5 text-sm font-medium text-indigo-400 hover:border-indigo-500 hover:bg-indigo-950/40 hover:text-indigo-300 transition-colors"
            >
              <CheckCircle2 className="h-4 w-4" />
              Check for False Positive with AI
            </button>
          )}

          {checkFp.isError && (
            <p className="rounded-lg border border-red-800 bg-red-900/20 px-3 py-2 text-xs text-red-300">
              {(checkFp.error as Error).message}
            </p>
          )}

          {/* Description */}
          <div>
            <h3 className="mb-1.5 text-xs font-semibold uppercase tracking-wider text-gray-500">
              Description
            </h3>
            <p className="text-sm text-gray-300 leading-relaxed">{finding.description}</p>
          </div>

          {/* Code Evidence — SAST / IAC / SECRET: always show when filePath is known */}
          {["SAST", "IAC", "SECRET"].includes(finding.scanType) && finding.filePath && (
            <CodeEvidencePanel
              snippet={codeSnippet}         // null → header-only with GitHub link
              filePath={finding.filePath}
              lineStart={finding.lineStart ?? null}
              lineEnd={finding.lineEnd ?? null}
              githubUrl={githubUrl}
              onAnalyse={() => { setCodeModalOverride(null); setShowCodeModal(true); }}
            />
          )}

          {/* Subissues panel — merged SCA (multiple CVEs for same package) */}
          {isScaMerged && (rawOut?.cves ?? []).length > 0 && (
            <ScaSubissuesPanel
              rawOut={rawOut as ScaMergedRawOutput}
              pkg={finding.packageName ?? "package"}
              ver={finding.packageVersion ?? rawOut?.installedVersion ?? ""}
            />
          )}

          {/* Subissues panel — merged SAST (multiple locations for same rule) */}
          {isMerged && locations.length > 0 && (
            <SubissuesPanel
              locations={locations}
              repoFullName={repoInfo?.fullName ?? null}
              defaultBranch={repoInfo?.defaultBranch ?? null}
              onViewCode={(loc, ghUrl) => {
                // Clean up the snippet the same way codeSnippet does
                const rawSnip = loc.snippet?.trim() ?? null;
                const cleanSnip = rawSnip && !/^requires?\s+login$/i.test(rawSnip) ? rawSnip : null;
                setCodeModalOverride({
                  filePath:  loc.filePath,
                  lineStart: loc.lineStart,
                  lineEnd:   loc.lineEnd,
                  snippet:   cleanSnip,
                  githubUrl: ghUrl,
                });
                setShowCodeModal(true);
              }}
            />
          )}

          {/* Subissues panel — merged DAST / Pentest (same rule on multiple URLs) */}
          {isDastMerged && dastOccurrences.length > 0 && (
            <DastSubissuesPanel
              rawOut={rawOut as DastMergedRawOutput}
              onViewCode={(occ) => {
                // Build a structured evidence block as the "snippet" for the AI modal.
                // DAST findings have no source file — the evidence IS the context.
                const lines: string[] = [];
                if (occ.url)                           lines.push(`URL: ${occ.url}`);
                if (occ.param)                         lines.push(`Vulnerable Parameter: ${occ.param}`);
                if (occ.responseStatus != null)        lines.push(`HTTP Status: ${occ.responseStatus}`);
                if (occ.confidence)                    lines.push(`Confidence: ${occ.confidence}`);
                if (occ.attack)                        lines.push(`\nAttack Payload:\n${occ.attack}`);
                if (occ.evidence)                      lines.push(`\nEvidence:\n${occ.evidence}`);
                if (occ.other)                         lines.push(`\nAdditional Info:\n${occ.other}`);
                const evidenceSnippet = lines.join("\n").trim() || null;
                setCodeModalOverride({
                  filePath:  occ.url,   // modal label — shows the attacked URL
                  lineStart: null,
                  lineEnd:   null,
                  snippet:   evidenceSnippet,
                  githubUrl: occ.url,   // external link opens the URL directly
                });
                setShowCodeModal(true);
              }}
            />
          )}

          {/* Subissues panel — merged SECRET (same detector on multiple files) */}
          {isSecretMerged && secretOccurrences.length > 0 && (
            <SecretSubissuesPanel rawOut={rawOut as SecretMergedRawOutput} repoInfo={repoInfo} />
          )}

          {/* Resources panel — merged IAC (same rule failing on multiple resources) */}
          {isIacMerged && iacResources.length > 0 && (
            <IacResourcesPanel
              rawOut={rawOut as unknown as IacMergedRawOutput}
              repoInfo={repoInfo}
              onViewCode={(res, ghUrl) => {
                // Strip "N: code" line-number prefixes before sending to AI modal
                const rawSnip = res.snippet?.trim() ?? null;
                const lines = rawSnip ? rawSnip.split("\n") : [];
                const allHavePrefix = lines.length > 0 && lines.every((l) => l.trim() === "" || /^\s*\d+:\s?/.test(l));
                const cleanSnip = allHavePrefix
                  ? lines.map((l) => l.replace(/^\s*\d+:\s?/, "")).join("\n").trim() || null
                  : rawSnip;
                setCodeModalOverride({
                  filePath:  res.filePath ?? finding.filePath ?? "",
                  lineStart: res.lineStart ?? null,
                  lineEnd:   res.lineEnd   ?? null,
                  snippet:   cleanSnip,
                  githubUrl: ghUrl,
                });
                setShowCodeModal(true);
              }}
            />
          )}

          {/* Single URL — non-merged DAST/Pentest finding with a URL */}
          {!isDastMerged && ["DAST", "PENTEST", "PENTEST_FULL"].includes(finding.scanType) && finding.filePath && (
            <div>
              <h3 className="mb-1.5 text-xs font-semibold uppercase tracking-wider text-gray-500">Affected URL</h3>
              <a
                href={finding.filePath}
                target="_blank"
                rel="noopener noreferrer"
                className="inline-flex items-center gap-1.5 break-all rounded bg-gray-800 px-3 py-1.5 font-mono text-xs text-blue-300 hover:text-blue-200 hover:underline"
              >
                <Globe className="h-3 w-3 shrink-0" />
                {finding.filePath}
              </a>
            </div>
          )}

          {/* Single Location — non-merged SAST-adjacent findings only */}
          {!isMerged && !isScaMerged && !isDastMerged
            && !["SAST", "IAC", "SECRET", "DAST", "PENTEST", "PENTEST_FULL"].includes(finding.scanType)
            && finding.filePath && (
            <div>
              <h3 className="mb-1.5 text-xs font-semibold uppercase tracking-wider text-gray-500">Location</h3>
              <code className="rounded bg-gray-800 px-3 py-1.5 text-xs text-indigo-300">
                {finding.filePath}
                {finding.lineStart ? `:${finding.lineStart}` : ""}
                {finding.lineEnd && finding.lineEnd !== finding.lineStart ? `–${finding.lineEnd}` : ""}
              </code>
            </div>
          )}

          {/* Vulnerability details */}
          {(finding.cveId || finding.cvssScore != null || finding.packageName) && (
            <div>
              <h3 className="mb-2 text-xs font-semibold uppercase tracking-wider text-gray-500">
                Vulnerability Details
              </h3>
              <dl className="grid grid-cols-2 gap-2 text-sm">
                {finding.cveId && (
                  <><dt className="text-gray-500">CVE</dt><dd className="font-mono text-gray-200">{finding.cveId}</dd></>
                )}
                {finding.cvssScore != null && (
                  <><dt className="text-gray-500">CVSS Score</dt><dd className="font-semibold text-gray-200">{finding.cvssScore.toFixed(1)}</dd></>
                )}
                {finding.packageName && (
                  <><dt className="text-gray-500">Package</dt>
                  <dd className="font-mono text-gray-200">
                    {finding.packageName}{finding.packageVersion ? `@${finding.packageVersion}` : ""}
                  </dd></>
                )}
                {finding.fixVersion && (
                  <><dt className="text-gray-500">Fix version</dt><dd className="font-mono text-green-400">{finding.fixVersion}</dd></>
                )}
              </dl>
            </div>
          )}

          {/* Remediation */}
          {finding.remediation && (
            <div>
              <h3 className="mb-1.5 text-xs font-semibold uppercase tracking-wider text-gray-500">Remediation</h3>
              <p className="text-sm text-gray-300">{finding.remediation}</p>
            </div>
          )}

          {/* Evidence — hidden for DAST merged (each occurrence has its own evidence in the panel above) */}
          {!isDastMerged && finding.evidence && Object.keys(finding.evidence).length > 0 && (
            <div>
              <button
                onClick={() => setShowEvidence((v) => !v)}
                className="flex items-center gap-1 text-xs font-medium text-gray-500 hover:text-gray-300"
              >
                {showEvidence ? <ChevronUp className="h-3.5 w-3.5" /> : <ChevronDown className="h-3.5 w-3.5" />}
                Detection evidence
              </button>
              {showEvidence && (
                <div className="mt-2 space-y-1.5 rounded bg-gray-950 p-3 text-xs text-gray-400">
                  {Object.entries(finding.evidence).map(([key, value]) => (
                    <div key={key} className="flex gap-2">
                      <span className="shrink-0 text-gray-600 min-w-[120px]">{key}:</span>
                      <span className="break-all text-gray-300">
                        {typeof value === "object" ? JSON.stringify(value) : String(value)}
                      </span>
                    </div>
                  ))}
                </div>
              )}
            </div>
          )}

          {/* Metadata */}
          <div>
            <h3 className="mb-2 text-xs font-semibold uppercase tracking-wider text-gray-500">Metadata</h3>
            <dl className="grid grid-cols-2 gap-2 text-sm">
              <dt className="text-gray-500">Tracking ID</dt>
              <dd className="font-mono text-xs text-indigo-400 select-all">#{finding.id.slice(0, 8).toUpperCase()}</dd>
              <dt className="text-gray-500">First seen</dt>
              <dd className="text-gray-300">{formatDate(finding.firstSeen)}</dd>
              <dt className="text-gray-500">Last seen</dt>
              <dd className="text-gray-300">{formatDate(finding.lastSeen)}</dd>
              <dt className="text-gray-500">Status</dt>
              <dd className="text-gray-300">{finding.status}</dd>
              <dt className="text-gray-500">Confidence</dt>
              <dd><ConfidenceBadge confidence={finding.confidence} /></dd>
              {finding.verifiedAt && (
                <><dt className="text-gray-500">Last verified</dt><dd className="text-gray-300">{formatDate(finding.verifiedAt)}</dd></>
              )}
              {finding.ruleId && (
                <><dt className="text-gray-500">Rule ID</dt><dd className="truncate font-mono text-xs text-gray-400">{finding.ruleId}</dd></>
              )}
            </dl>
          </div>

          {/* Raw output */}
          <div>
            <button
              onClick={() => setShowRaw((v) => !v)}
              className="flex items-center gap-1 text-xs font-medium text-gray-500 hover:text-gray-300"
            >
              {showRaw ? <ChevronUp className="h-3.5 w-3.5" /> : <ChevronDown className="h-3.5 w-3.5" />}
              Raw scanner output
            </button>
            {showRaw && (
              <pre className="mt-2 max-h-48 overflow-auto rounded bg-gray-950 p-3 text-xs text-gray-400">
                {JSON.stringify((finding as never as Record<string, unknown>)["rawOutput"], null, 2)}
              </pre>
            )}
          </div>
        </div>

        {/* ── Footer actions ─────────────────────────────────────────────── */}
        <div className="flex flex-col gap-3 border-t border-gray-800 p-4">
          <div className="flex items-center gap-3">
            <select
              value={finding.status}
              onChange={(e) => updateStatus.mutate(e.target.value)}
              className="flex-1 rounded bg-gray-800 px-3 py-1.5 text-sm text-gray-200 focus:outline-none focus:ring-1 focus:ring-indigo-500"
            >
              <option value="OPEN">Open</option>
              <option value="ACKNOWLEDGED">Acknowledged</option>
              <option value="FALSE_POSITIVE">False Positive (confirmed)</option>
              <option value="FIXED">Fixed</option>
              <option value="IGNORED">Ignored (AI dismissed)</option>
            </select>
            <button
              onClick={() => createTicket.mutate()}
              disabled={createTicket.isPending || !!finding.ticket}
              className="rounded bg-indigo-600 px-3 py-1.5 text-sm font-medium text-white hover:bg-indigo-500 disabled:opacity-50"
            >
              {finding.ticket ? "Ticket exists" : "Create Ticket"}
            </button>
          </div>

          {/* Re-verify (DAST / PENTEST_FULL only) */}
          {canVerify && (
            <button
              onClick={() => { setVerifyResult(null); verify.mutate(); }}
              disabled={verify.isPending}
              className="flex items-center justify-center gap-2 rounded border border-gray-700 bg-gray-800 px-3 py-1.5 text-sm font-medium text-gray-300 hover:bg-gray-700 hover:text-white disabled:opacity-50"
            >
              {verify.isPending
                ? <Loader2 className="h-4 w-4 animate-spin" />
                : <ShieldCheck className="h-4 w-4" />}
              {verify.isPending ? "Verifying…" : "Re-verify finding"}
            </button>
          )}
        </div>
      </div>

      {/* Code Analysis Modal — opens from CodeEvidencePanel (primary) or SubissuesPanel (per-location) */}
      {showCodeModal && (
        <CodeAnalysisModal
          finding={finding as Finding & Record<string, unknown>}
          snippet={codeSnippet}
          githubUrl={githubUrl}
          repoInfo={repoInfo}
          locationOverride={codeModalOverride}
          onClose={() => { setShowCodeModal(false); setCodeModalOverride(null); }}
        />
      )}
    </div>
  );
}
