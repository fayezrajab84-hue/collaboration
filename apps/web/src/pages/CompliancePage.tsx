/**
 * Compliance dashboard page (Phase 16 Slice D).
 *
 * Three layers stacked vertically:
 *   1. Framework picker tabs at the top — click to switch between
 *      OWASP Top 10 / SOC 2 / PCI DSS. Each tab shows a "X of Y
 *      controls have findings" summary.
 *   2. Control matrix table — one row per control with code, name,
 *      severity histogram of OPEN findings, status counts, and a
 *      click-to-expand drill-down.
 *   3. Inline drill-down — clicking a row expands beneath it with
 *      the actual findings paginated 20 at a time.
 *
 * The data drives this — Slice C's API returns everything needed.
 * No reshape on the client, just rendering. Heavy lifting (mappings,
 * counts, severity histograms) all happens server-side.
 *
 * Read-only for VIEWER+. The PDF / CSV evidence-export buttons that
 * Slice E will add are ADMIN+, gated via <Can role="ADMIN">.
 */
import { useMemo, useState } from "react";
import { useQuery } from "@tanstack/react-query";
import {
  ChevronDown, ChevronRight, ScrollText, ShieldCheck, BookOpenCheck, FileSpreadsheet, FileDown,
} from "lucide-react";
import { complianceApi } from "../lib/api";
import { cn } from "../lib/utils";
import SeverityBadge from "../components/SeverityBadge";
import FindingStatusBadge from "../components/FindingStatusBadge";
import Can from "../components/Can";
import { formatRelative } from "../lib/utils";
import type { ComplianceFramework, ControlBreakdown } from "@devsecops/types";

const SEVERITY_DOT: Record<keyof ControlBreakdown["severity"], string> = {
  CRITICAL: "bg-red-400",
  HIGH:     "bg-orange-400",
  MEDIUM:   "bg-amber-400",
  LOW:      "bg-sky-400",
  INFO:     "bg-gray-500",
};

export default function CompliancePage() {
  const [activeFramework, setActiveFramework] = useState<ComplianceFramework>("OWASP_TOP_10");
  const [expandedControlId, setExpandedControlId] = useState<string | null>(null);

  // ── Top-level summary across frameworks ──────────────────────────────────
  const { data: summary, isLoading: loadingSummary } = useQuery({
    queryKey: ["compliance", "frameworks"],
    queryFn:  complianceApi.frameworks,
  });

  // ── Active framework's per-control matrix ───────────────────────────────
  const { data: dashboard, isLoading: loadingDashboard } = useQuery({
    queryKey: ["compliance", "dashboard", activeFramework],
    queryFn:  () => complianceApi.dashboard(activeFramework),
  });

  // Group controls by category for visual grouping (SOC 2 has CC6, CC7,
  // CC8 sections; OWASP doesn't bother). Stable keys so re-renders are cheap.
  const grouped = useMemo(() => {
    if (!dashboard) return [] as Array<{ category: string | null; controls: ControlBreakdown[] }>;
    const map = new Map<string, ControlBreakdown[]>();
    for (const c of dashboard.controls) {
      const key = c.category ?? "";
      if (!map.has(key)) map.set(key, []);
      map.get(key)!.push(c);
    }
    return Array.from(map.entries()).map(([category, controls]) => ({
      category: category || null,
      controls,
    }));
  }, [dashboard]);

  return (
    <div className="p-6">
      {/* Page header */}
      <div className="mb-6 flex items-center gap-3">
        <BookOpenCheck className="h-5 w-5 text-indigo-400" />
        <h1 className="text-3xl font-bold text-white">Compliance</h1>
        <span className="ml-auto text-xs text-gray-500">
          Findings mapped to compliance controls. CWE-based matching with
          keyword fallback for findings that lack a CWE.
        </span>
      </div>

      {/* Framework picker tabs */}
      <div className="mb-6 flex flex-wrap gap-2">
        {(loadingSummary ? [] : summary?.frameworks ?? []).map((f) => {
          const active = f.framework === activeFramework;
          return (
            <button
              key={f.framework}
              type="button"
              onClick={() => { setActiveFramework(f.framework); setExpandedControlId(null); }}
              className={cn(
                "flex items-center gap-3 rounded-lg border px-4 py-3 text-left transition-colors",
                active
                  ? "border-indigo-700/60 bg-indigo-950/40 text-indigo-100"
                  : "border-gray-800 bg-gray-900/40 text-gray-300 hover:border-gray-700 hover:bg-gray-900/70",
              )}
            >
              <ScrollText className={cn("h-4 w-4", active ? "text-indigo-300" : "text-gray-500")} />
              <div className="flex flex-col">
                <span className={cn("text-sm font-semibold", active ? "text-white" : "text-gray-200")}>
                  {f.label}
                </span>
                <span className={cn("text-[11px]", active ? "text-indigo-300" : "text-gray-500")}>
                  {f.controlsWithFindings}/{f.controlCount} controls hit ·{" "}
                  <span className="font-semibold">{f.openFindingCount}</span> open
                </span>
              </div>
            </button>
          );
        })}
        {loadingSummary && (
          <span className="text-xs text-gray-500">Loading frameworks…</span>
        )}
      </div>

      {/* Active dashboard */}
      {loadingDashboard ? (
        <div className="rounded-lg border border-gray-800 bg-gray-900/40 p-6 text-center text-xs text-gray-500">
          Loading {activeFramework} controls…
        </div>
      ) : !dashboard ? null : (
        <div className="space-y-6">
          {/* Header summary for the framework */}
          <div className="rounded-lg border border-indigo-900/40 bg-indigo-950/20 p-4">
            <div className="flex items-start gap-2">
              <ShieldCheck className="h-4 w-4 text-indigo-400 mt-0.5" />
              <div className="flex-1">
                <h2 className="text-base font-semibold text-white">{dashboard.label}</h2>
                <p className="mt-2 text-xs text-gray-400">
                  <span className="font-semibold text-gray-200">{dashboard.totalMappings}</span> finding-to-control links across{" "}
                  <span className="font-semibold text-gray-200">{dashboard.controls.length}</span> controls. Each
                  finding can satisfy multiple controls — the same SCA result lights up CC7.1 and Req-6.3.1 at the same time.
                </p>
              </div>

              {/* Evidence export — ADMIN-gated. CSV is the spreadsheet
                  format for ad-hoc analysis; HTML is the print-to-PDF
                  format for the auditor's evidence folder. Both audit-
                  logged on the API side. */}
              <Can role="ADMIN">
                <div className="flex shrink-0 gap-2">
                  <a
                    href={`/api/compliance/${activeFramework}/export.csv`}
                    download
                    className="inline-flex items-center gap-1.5 rounded border border-indigo-800/60 bg-indigo-950/40 px-3 py-1.5 text-xs font-medium text-indigo-200 hover:bg-indigo-950/60"
                    title="Download per-control evidence as CSV"
                  >
                    <FileSpreadsheet className="h-3.5 w-3.5" />
                    CSV
                  </a>
                  <a
                    href={`/api/compliance/${activeFramework}/export.html`}
                    download
                    className="inline-flex items-center gap-1.5 rounded border border-indigo-800/60 bg-indigo-950/40 px-3 py-1.5 text-xs font-medium text-indigo-200 hover:bg-indigo-950/60"
                    title="Download printable evidence report (HTML — open in browser, Cmd-P to save as PDF)"
                  >
                    <FileDown className="h-3.5 w-3.5" />
                    HTML / PDF
                  </a>
                </div>
              </Can>
            </div>
          </div>

          {/* Control matrix */}
          {grouped.map((group, gi) => (
            <div key={group.category ?? `group-${gi}`} className="space-y-2">
              {group.category && (
                <h3 className="text-[11px] font-semibold uppercase tracking-wider text-indigo-400">
                  {group.category}
                </h3>
              )}
              <div className="overflow-hidden rounded-lg border border-gray-800">
                <table className="w-full">
                  <thead className="bg-gray-900/60 text-left text-[10px] font-semibold uppercase tracking-wider text-gray-500">
                    <tr>
                      <th className="w-8 px-3 py-2" />
                      <th className="px-3 py-2">Control</th>
                      <th className="px-3 py-2">Open severity</th>
                      <th className="px-3 py-2 text-right">Open</th>
                      <th className="px-3 py-2 text-right">Total</th>
                      <th className="px-3 py-2 text-right">Status</th>
                    </tr>
                  </thead>
                  <tbody className="divide-y divide-gray-800 text-xs text-gray-300">
                    {group.controls.map((c) => {
                      const isOpen = expandedControlId === c.id;
                      const dotColor =
                        c.severity.CRITICAL > 0 ? "bg-red-400"
                        : c.severity.HIGH    > 0 ? "bg-orange-400"
                        : c.severity.MEDIUM  > 0 ? "bg-amber-400"
                        : c.severity.LOW     > 0 ? "bg-sky-400"
                        : c.open             > 0 ? "bg-gray-500"
                        :                          "bg-emerald-500";
                      return (
                        <ControlRow
                          key={c.id}
                          control={c}
                          framework={activeFramework}
                          isOpen={isOpen}
                          onToggle={() => setExpandedControlId(isOpen ? null : c.id)}
                          dotColor={dotColor}
                        />
                      );
                    })}
                  </tbody>
                </table>
              </div>
            </div>
          ))}
        </div>
      )}
    </div>
  );
}

// ── Per-control row + drill-down ────────────────────────────────────────

function ControlRow({
  control: c,
  framework,
  isOpen,
  onToggle,
  dotColor,
}: {
  control:   ControlBreakdown;
  framework: ComplianceFramework;
  isOpen:    boolean;
  onToggle:  () => void;
  dotColor:  string;
}) {
  return (
    <>
      <tr
        className={cn("cursor-pointer hover:bg-gray-900/60", isOpen && "bg-gray-900/40")}
        onClick={onToggle}
      >
        <td className="px-3 py-2 align-top">
          {isOpen
            ? <ChevronDown  className="h-3.5 w-3.5 text-indigo-400" />
            : <ChevronRight className="h-3.5 w-3.5 text-gray-500" />}
        </td>
        <td className="px-3 py-2 align-top">
          <div className="flex items-center gap-2">
            <span className={cn("h-2 w-2 shrink-0 rounded-full", dotColor)} title={c.open > 0 ? "Has open findings" : "Clean"} />
            <span className="font-mono text-[11px] text-indigo-300">{c.code}</span>
            <span className="font-medium text-gray-200">{c.name}</span>
          </div>
          <p className="mt-1 line-clamp-2 text-[11px] text-gray-500">{c.description}</p>
        </td>
        <td className="px-3 py-2 align-top">
          <SeverityHistogram severity={c.severity} />
        </td>
        <td className="px-3 py-2 align-top text-right font-semibold text-gray-100">
          {c.open}
        </td>
        <td className="px-3 py-2 align-top text-right text-gray-400">
          {c.total}
        </td>
        <td className="px-3 py-2 align-top text-right">
          <div className="flex flex-col items-end gap-0.5 text-[10px] text-gray-500">
            {c.fixed > 0          && <span className="text-emerald-400">{c.fixed} fixed</span>}
            {c.acknowledged > 0   && <span>{c.acknowledged} ack</span>}
            {c.falsePositive > 0  && <span>{c.falsePositive} FP</span>}
            {c.ignored > 0        && <span>{c.ignored} ignored</span>}
          </div>
        </td>
      </tr>
      {isOpen && (
        <tr>
          <td colSpan={6} className="bg-gray-950/50 px-3 py-3">
            <ControlDrillDown framework={framework} code={c.code} />
          </td>
        </tr>
      )}
    </>
  );
}

function SeverityHistogram({ severity }: { severity: ControlBreakdown["severity"] }) {
  const total = severity.CRITICAL + severity.HIGH + severity.MEDIUM + severity.LOW + severity.INFO;
  if (total === 0) {
    return <span className="text-[10px] text-emerald-400">no open</span>;
  }
  return (
    <div className="flex flex-wrap items-center gap-1">
      {(Object.keys(severity) as Array<keyof ControlBreakdown["severity"]>).map((sev) => {
        const n = severity[sev];
        if (n === 0) return null;
        return (
          <span
            key={sev}
            className="inline-flex items-center gap-1 rounded border border-gray-700/60 bg-gray-800/70 px-1.5 py-0.5 text-[10px] text-gray-300"
            title={`${n} OPEN ${sev}`}
          >
            <span className={cn("h-1.5 w-1.5 rounded-full", SEVERITY_DOT[sev])} />
            <span>{n}</span>
          </span>
        );
      })}
    </div>
  );
}

function ControlDrillDown({ framework, code }: { framework: ComplianceFramework; code: string }) {
  const [page, setPage] = useState(1);
  const [status, setStatus] = useState<"OPEN" | "ALL">("OPEN");
  const limit = 10;

  const { data, isLoading } = useQuery({
    queryKey: ["compliance", "control-findings", framework, code, status, page],
    queryFn:  () => complianceApi.controlFindings(framework, code, { status, page, limit }),
  });

  if (isLoading || !data) {
    return <p className="text-xs text-gray-500">Loading findings…</p>;
  }

  const totalPages = Math.max(1, Math.ceil(data.total / limit));

  return (
    <div className="space-y-3">
      <div className="flex items-center gap-3 text-[11px] text-gray-400">
        <span>
          <span className="font-semibold text-gray-200">{data.total}</span> findings ·{" "}
          {status === "OPEN" ? "showing OPEN only" : "showing all statuses"}
        </span>
        <button
          type="button"
          onClick={(e) => { e.stopPropagation(); setStatus(status === "OPEN" ? "ALL" : "OPEN"); setPage(1); }}
          className="rounded border border-indigo-900/50 bg-indigo-950/30 px-2 py-1 text-[10px] text-indigo-300 hover:bg-indigo-950/60"
        >
          {status === "OPEN" ? "Show all" : "Open only"}
        </button>
      </div>

      {data.findings.length === 0 ? (
        <p className="text-xs text-gray-500">
          {status === "OPEN"
            ? "No open findings for this control. Toggle to see fixed / acknowledged / false-positive history."
            : "No findings on file for this control."}
        </p>
      ) : (
        <ul className="space-y-1.5">
          {data.findings.map((f) => (
            <li
              key={f.id}
              className="flex items-start gap-2 rounded border border-gray-800/80 bg-gray-900/40 px-3 py-2 text-xs"
              onClick={(e) => e.stopPropagation()}
            >
              <SeverityBadge severity={f.severity} />
              <div className="min-w-0 flex-1">
                <div className="flex items-center gap-2">
                  <span className="truncate font-medium text-gray-200">{f.title}</span>
                  <span className="rounded bg-gray-800/60 px-1.5 py-0.5 text-[9px] uppercase tracking-wide text-gray-500">
                    {f.scanType}
                  </span>
                </div>
                <div className="mt-0.5 flex flex-wrap items-center gap-2 text-[10px] text-gray-500">
                  {f.cweId && <span className="rounded bg-indigo-950/40 px-1.5 py-0.5 text-indigo-300">{f.cweId}</span>}
                  {f.cveId && <span className="rounded bg-amber-950/40 px-1.5 py-0.5 text-amber-300">{f.cveId}</span>}
                  {f.packageName && <span>{f.packageName}{f.packageVersion ? `@${f.packageVersion}` : ""}</span>}
                  {f.filePath && <span className="font-mono text-[10px]">{f.filePath}{f.lineStart ? `:${f.lineStart}` : ""}</span>}
                  <span className="ml-auto">{formatRelative(f.firstSeen)}</span>
                </div>
              </div>
              <FindingStatusBadge status={f.status} />
            </li>
          ))}
        </ul>
      )}

      {totalPages > 1 && (
        <div className="flex items-center justify-between text-[11px] text-gray-500">
          <span>Page {data.page} of {totalPages}</span>
          <div className="flex gap-2">
            <button
              type="button"
              onClick={(e) => { e.stopPropagation(); setPage(Math.max(1, page - 1)); }}
              disabled={page === 1}
              className="rounded border border-gray-800 bg-gray-900/60 px-2 py-1 text-gray-300 hover:bg-gray-900 disabled:cursor-not-allowed disabled:opacity-40"
            >
              Prev
            </button>
            <button
              type="button"
              onClick={(e) => { e.stopPropagation(); setPage(Math.min(totalPages, page + 1)); }}
              disabled={page >= totalPages}
              className="rounded border border-gray-800 bg-gray-900/60 px-2 py-1 text-gray-300 hover:bg-gray-900 disabled:cursor-not-allowed disabled:opacity-40"
            >
              Next
            </button>
          </div>
        </div>
      )}
    </div>
  );
}

