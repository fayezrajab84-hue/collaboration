import React, { useState, useEffect, useRef } from "react";
import { useQuery, useQueryClient, useMutation } from "@tanstack/react-query";
import { Activity, ChevronLeft, ChevronRight, GitBranch, Box, Globe, Clock, Square, Sparkles, ChevronDown, Trash2, RefreshCw, AlertCircle, GitCompare, Plus, Minus, X } from "lucide-react";
import SeverityBadge from "../components/SeverityBadge";
import { scansApi } from "../lib/api";
import ScanStatusBadge from "../components/ScanStatusBadge";
import { formatRelative } from "../lib/utils";
import type { ScanJob } from "@devsecops/types";

// Unified target-type tag — matches TargetTag component. Neutral chip,
// repo/container keep slate/blue tints; the domain icon uses gray-300 (light
// silver) so every Globe in the app (dashboard tabs, stats cards, recent
// scans, top targets, finding chips) reads as the same web semantic without
// competing with the indigo action accent.
const TYPE_ICONS: Record<string, React.ReactNode> = {
  REPOSITORY: <GitBranch className="h-3.5 w-3.5 text-slate-400" />,
  CONTAINER:  <Box        className="h-3.5 w-3.5 text-blue-400"  />,
  DOMAIN:     <Globe      className="h-3.5 w-3.5 text-gray-300"  />,
};

const TYPE_CHIP = "bg-gray-800/80 text-gray-300 border border-gray-700/60";

function SeverityPill({ count, color }: { count: number; color: string }) {
  if (!count) return null;
  return (
    <span className={`rounded px-1.5 py-0.5 text-xs font-semibold ${color}`}>
      {count}
    </span>
  );
}

function duration(scan: ScanJob): string {
  if (!scan.startedAt || !scan.completedAt) return "—";
  const ms = new Date(scan.completedAt).getTime() - new Date(scan.startedAt).getTime();
  const s = Math.round(ms / 1000);
  if (s < 60) return `${s}s`;
  const m = Math.floor(s / 60);
  const rem = s % 60;
  return rem > 0 ? `${m}m ${rem}s` : `${m}m`;
}

/** Live crawl stats emitted by the Playwright crawler sidecar during the
 *  pre-scan discovery phase. */
type CrawlerProgress = {
  pagesVisited: number;
  pagesQueued:  number;
  xhrObserved:  number;
  formsFound:   number;
  currentUrl:   string | null;
  elapsedSecs:  number;
};

/** Subscribe to SSE for a scan job. Returns the latest phase progress (0-99),
 *  the current phase name (snake_case from the scanner), and the latest
 *  crawler progress snapshot (null until the first event).
 *
 *  `seedPct` / `seedPhase` come from the scan object's `currentPhasePct` /
 *  `currentPhase` fields — the API caches the last emitted progress in memory
 *  so a fresh page load (or SSE reconnect after a drop) hydrates the bar
 *  immediately, instead of staring at "Scanning…" until the next phase
 *  boundary fires (Nuclei sits silent for ~25 min). */
function usePhaseProgress(
  scanId: string,
  active: boolean,
  seedPct: number | null = null,
  seedPhase: string | null = null,
): { phasePct: number | null; phase: string | null; crawler: CrawlerProgress | null } {
  const [phasePct, setPct] = useState<number | null>(seedPct);
  const [phase, setPhase] = useState<string | null>(seedPhase);
  const [crawler, setCrawler] = useState<CrawlerProgress | null>(null);
  const esRef = useRef<EventSource | null>(null);

  // Re-hydrate when the seed values change (e.g. on a refetch after the API
  // has cached a newer phase). Don't downgrade to null if we already have
  // newer state from SSE — only adopt seed values that are actually newer.
  useEffect(() => {
    if (seedPct !== null) setPct((prev) => (prev === null ? seedPct : prev));
    if (seedPhase !== null) setPhase((prev) => (prev === null ? seedPhase : prev));
  }, [seedPct, seedPhase]);

  useEffect(() => {
    if (!active) { setPct(null); setPhase(null); setCrawler(null); return; }
    if (esRef.current) return; // already connected

    const es = new EventSource(`/api/scans/${scanId}/events`);
    esRef.current = es;

    es.onmessage = (ev) => {
      try {
        const data = JSON.parse(ev.data);
        if (data.type === "PHASE_PROGRESS") {
          if (typeof data.pct === "number") setPct(data.pct);
          // The scanner emits a phase name on every progress callback (e.g.
          // "spider_started", "active_scanning"). Stash it so the UI can show
          // *what* the scanner is doing, not just how far along it is.
          if (typeof data.phase === "string" && data.phase.length > 0) {
            setPhase(data.phase);
          }
        }
        if (data.type === "CRAWLER_PROGRESS") {
          setCrawler({
            pagesVisited: data.pagesVisited ?? 0,
            pagesQueued:  data.pagesQueued  ?? 0,
            xhrObserved:  data.xhrObserved  ?? 0,
            formsFound:   data.formsFound   ?? 0,
            currentUrl:   data.currentUrl   ?? null,
            elapsedSecs:  data.elapsedSecs  ?? 0,
          });
        }
        if (data.type === "STATUS_CHANGE" &&
            (data.status === "COMPLETED" || data.status === "FAILED" || data.status === "CANCELLED")) {
          es.close();
          esRef.current = null;
        }
      } catch { /* ignore */ }
    };

    return () => {
      es.close();
      esRef.current = null;
    };
  }, [scanId, active]);

  return { phasePct, phase, crawler };
}

/** Map raw scanner phase identifiers to human-readable labels. Falls back to
 *  a snake_case → Title Case transform for any phase we haven't seen yet, so
 *  new scanner phases automatically show up readable without code changes. */
const PHASE_LABELS: Record<string, string> = {
  probing:                 "Probing target",
  auth_configured:         "Authentication configured",
  playwright_crawl_done:   "Browser crawl complete",
  katana_crawl_done:       "Katana crawl complete",
  ffuf_discovery_done:     "FFUF discovery complete",
  graphql_discovery_done:  "GraphQL discovery complete",
  spider_started:          "Spider started",
  spidering:               "Spidering",
  spider_done:             "Spider complete",
  active_scan_started:     "Active scan started",
  active_scanning:         "Active scanning",
  active_scan_done:        "Active scan complete",
  active_scan_skipped:     "Active scan skipped — harvesting alerts",
  collecting:              "Collecting findings",
  confirming_findings:     "Confirming findings",
  nuclei_api_scan:         "Nuclei API scan",
  targeted_checks:         "Targeted checks",
  scanning:                "Scanning",
  // PENTEST_FULL phase labels (orchestrator emits these via _report_progress).
  // Each phase has _started, _done, and _failed variants — _failed is emitted
  // when the phase callable raises so the bar still advances past a broken
  // scanner instead of stalling at the same %.
  crawler_started:           "Crawling URLs",
  crawler_done:              "Crawl complete",
  recon_started:             "Recon (subfinder + httpx)",
  recon_done:                "Recon complete",
  recon_failed:              "Recon failed — continuing",
  discovery_started:         "Discovery (nmap + ffuf)",
  discovery_done:            "Discovery complete",
  discovery_failed:          "Discovery failed — continuing",
  // Recon and Discovery now run in parallel as a single segment
  recon_discovery_started:   "Recon + Discovery (parallel)",
  recon_discovery_done:      "Recon + Discovery complete",
  vuln_scan_started:         "Vuln scan (Nuclei + Nikto + testssl)",
  vuln_scan_done:            "Vuln scan complete",
  vuln_scan_failed:          "Vuln scan failed — continuing",
  targeted_checks_started: "Targeted checks (CORS, SSRF, IDOR…)",
  targeted_checks_done:    "Targeted checks complete",
  exploit_started:         "Exploitation (SQLMap + XSStrike)",
  exploit_done:            "Exploitation complete",
  exploit_failed:          "Exploitation failed — continuing",
  finalizing:              "Finalizing",
  done:                    "Finalizing",
};
function humanizePhase(raw: string): string {
  if (PHASE_LABELS[raw]) return PHASE_LABELS[raw]!;
  // Generic fallback: spider_done → "Spider done"
  return raw
    .split("_")
    .filter(Boolean)
    .map((w, i) => i === 0 ? w.charAt(0).toUpperCase() + w.slice(1) : w)
    .join(" ");
}

/** Truncate a URL to its path (host elided) for compact progress display. */
function shortUrl(u: string): string {
  try {
    const url = new URL(u);
    const p = url.pathname + (url.search || "");
    return p.length > 44 ? p.slice(0, 41) + "…" : p;
  } catch {
    return u.length > 44 ? u.slice(0, 41) + "…" : u;
  }
}

/** Thin animated progress bar for PENDING / RUNNING scans */
function ScanProgressBar({ scan }: { scan: ScanJob }) {
  const isActive = scan.status === "PENDING" || scan.status === "RUNNING";
  // `currentPhasePct` / `currentPhase` come from the API's in-memory progress
  // cache; if the user reloaded the page mid-scan, these seed the SSE hook
  // so the progress bar appears immediately rather than waiting for the
  // next phase boundary (which can be 25 min away during Nuclei).
  const { phasePct, phase, crawler } = usePhaseProgress(
    scan.id,
    isActive,
    (scan as { currentPhasePct?: number | null }).currentPhasePct ?? null,
    (scan as { currentPhase?:    string | null }).currentPhase    ?? null,
  );

  if (!isActive) return null;

  const total = scan.totalScans ?? 0;
  const done = scan.completedScans ?? 0;
  // Prefer real-time phase progress; fall back to coarse per-scanner progress
  const coarsePct = total > 0 ? Math.round((done / total) * 100) : 0;
  const displayPct = phasePct !== null ? phasePct : coarsePct;
  const isIndeterminate = displayPct === 0 && scan.status === "RUNNING";

  // Promote the live phase name to the prominent top-row label so the user
  // sees what's actually happening ("Vuln scan (Nuclei + Nikto + testssl)")
  // instead of the generic "Scanning…" placeholder. Falls back gracefully
  // when no phase has been emitted yet (PENDING, or pre-first-emit RUNNING).
  let label: string;
  let labelIsPhase = false;
  if (scan.status === "PENDING") {
    label = "Queued…";
  } else if (phase) {
    label = humanizePhase(phase);
    labelIsPhase = true;
  } else if (done > 0) {
    label = `${done} / ${total} scanners`;
  } else {
    label = "Scanning…";
  }

  // Secondary line: only worth showing when there are multiple scanner types
  // (e.g., a multi-scan repo job: SAST + SCA + Secrets…). Single-scanner runs
  // like PENTEST_FULL would just say "0 / 1 scanners" — noise.
  const showScannerCount = total > 1 && labelIsPhase;

  return (
    <div className="mt-1.5 space-y-0.5">
      <div className="flex items-center justify-between gap-2 text-[10px]">
        <span
          className={`flex min-w-0 items-center gap-1.5 ${
            labelIsPhase ? "text-indigo-300" : "text-gray-500"
          }`}
        >
          {labelIsPhase && (
            <span className="inline-block h-1.5 w-1.5 shrink-0 animate-pulse rounded-full bg-indigo-400" />
          )}
          <span className="truncate" title={labelIsPhase ? phase ?? undefined : undefined}>
            {label}
          </span>
        </span>
        {displayPct > 0 && <span className="shrink-0 text-gray-500">{displayPct}%</span>}
      </div>
      <div className="h-1 w-full overflow-hidden rounded-full bg-gray-700">
        {!isIndeterminate ? (
          <div
            className="h-full rounded-full bg-indigo-500 transition-all duration-500"
            style={{ width: `${Math.max(displayPct, 2)}%` }}
          />
        ) : (
          <div className="h-full w-1/3 animate-pulse rounded-full bg-indigo-600/60" />
        )}
      </div>
      {showScannerCount && (
        <div className="pt-0.5 text-[10px] text-gray-500">
          {done} / {total} scanners
        </div>
      )}
      {crawler && (
        <div className="flex items-center justify-between gap-2 pt-0.5 text-[10px] text-gray-500">
          <span className="font-mono">
            crawler: <span className="text-gray-400">{crawler.pagesVisited}</span> pages
            {crawler.xhrObserved > 0 && (
              <> · <span className="text-gray-400">{crawler.xhrObserved}</span> XHR</>
            )}
            {crawler.formsFound > 0 && (
              <> · <span className="text-gray-400">{crawler.formsFound}</span> forms</>
            )}
            {crawler.pagesQueued > 0 && (
              <> · <span className="text-gray-400">{crawler.pagesQueued}</span> queued</>
            )}
          </span>
          {crawler.currentUrl && (
            <span
              className="truncate font-mono text-gray-600"
              title={crawler.currentUrl}
            >
              {shortUrl(crawler.currentUrl)}
            </span>
          )}
        </div>
      )}
    </div>
  );
}

/**
 * Inline error diagnostics panel shown below a failed scan row.
 *
 * The raw `error` string from the scanner is usually a Python exception class
 * name + message. Turn that into an actionable hint users can follow without
 * opening a shell — e.g. "ZAP unreachable" → "check `docker compose ps zap`".
 */
function ErrorDiagnosticsRow({ scan }: { scan: ScanJob }) {
  const err = scan.error ?? "";
  const hint = diagnoseError(err);
  return (
    <tr>
      <td colSpan={7} className="px-4 pb-3 pt-0">
        <div className="flex items-start gap-2.5 rounded-lg border border-red-900/40 bg-red-950/20 px-4 py-3">
          <AlertCircle className="mt-0.5 h-3.5 w-3.5 flex-shrink-0 text-red-400" />
          <div className="min-w-0 flex-1 space-y-2">
            <div>
              <div className="text-[10px] uppercase tracking-wider text-red-400/70">Scanner error</div>
              <pre className="mt-1 whitespace-pre-wrap break-words font-mono text-xs text-red-200">{err}</pre>
            </div>
            {hint && (
              <div>
                <div className="text-[10px] uppercase tracking-wider text-red-400/70">What to try</div>
                <p className="mt-1 text-xs text-gray-300">{hint}</p>
              </div>
            )}
          </div>
        </div>
      </td>
    </tr>
  );
}

/** Map common scanner error patterns to actionable next-step hints. */
function diagnoseError(err: string): string | null {
  const e = err.toLowerCase();
  if (e.includes("zap") && (e.includes("connection") || e.includes("unreachable") || e.includes("refused"))) {
    return "ZAP container is unreachable. Check `docker compose ps zap` and restart with `docker compose up -d zap`.";
  }
  if (e.includes("timed out") || e.includes("readtimeout") || e.includes("timeout")) {
    return "A downstream tool timed out. If this is DAST, the target may be slow or ZAP's alert harvest is overloaded — re-run, or record fewer URLs before scanning.";
  }
  if (e.includes("crawler")) {
    return "Playwright crawler sidecar is down. Check `docker compose ps crawler` and restart with `docker compose up -d crawler`.";
  }
  if (e.includes("login") || e.includes("auth") || e.includes("logged_in_pattern")) {
    return "Authentication failed. Verify the username/password and `logged_in_pattern` in the Domain Auth Config — the pattern must match text on the authenticated landing page.";
  }
  if (e.includes("nuclei") || e.includes("nikto") || e.includes("sqlmap")) {
    return "A pentest tool failed to start. The scanner image may be missing the binary — check `docker compose logs scanner` and rebuild with `docker compose build scanner`.";
  }
  if (e.includes("rate") || e.includes("429")) {
    return "Target is rate-limiting the scanner. Reduce scan depth, exclude noisy paths, or slow down the run.";
  }
  if (e.includes("stalled")) {
    return "BullMQ marked this job stalled — the worker didn't renew its lock in time. This usually means the scan ran longer than the worker's `lockDuration` (2 h for PENTEST_FULL, 1 h for DAST, 35 min for everything else) or the scanner container restarted mid-run. Check `docker compose ps scanner` and re-trigger the scan; if it happens repeatedly on pentest, reduce the URL set or drop AGGRESSIVE → STANDARD depth.";
  }
  return null;
}

/** Inline AI summary panel shown below a completed scan row */
function AISummaryRow({ scan }: { scan: ScanJob }) {
  // Poll the individual scan every 5 s until aiSummary arrives
  const { data: fresh } = useQuery({
    queryKey: ["scan", scan.id, "summary"],
    queryFn:  () => scansApi.get(scan.id),
    enabled:  !scan.aiSummary,   // only poll when no summary yet
    refetchInterval: 5_000,
    staleTime: 0,
  });

  const generateMutation = useMutation({
    mutationFn: () => scansApi.generateSummary(scan.id),
  });

  const summary = scan.aiSummary ?? fresh?.aiSummary ?? null;
  const isGenerating = !summary && (generateMutation.isIdle ? !scan.aiSummarisedAt : !generateMutation.isError);

  const newCount = fresh?.newThisScan;
  const confirmedCount = fresh?.confirmedCount;
  const hasSplit = typeof newCount === "number" && typeof confirmedCount === "number";
  const splitBadge = hasSplit ? (
    <div className="mb-2 flex items-center gap-3 text-[11px] text-gray-400">
      <span>
        <span className="font-semibold text-emerald-400">{newCount}</span> new this run
      </span>
      <span className="text-gray-600">·</span>
      <span>
        <span className="font-semibold text-sky-400">{confirmedCount}</span> re-confirmed from prior scans
      </span>
      {newCount === 0 && confirmedCount === 0 && (
        <span className="text-gray-500">(clean)</span>
      )}
    </div>
  ) : null;

  if (summary) {
    return (
      <tr>
        <td colSpan={7} className="px-4 pb-3 pt-0">
          {splitBadge}
          <div className="flex items-start gap-2.5 rounded-lg border border-indigo-900/40 bg-indigo-950/20 px-4 py-3">
            <Sparkles className="mt-0.5 h-3.5 w-3.5 flex-shrink-0 text-indigo-400" />
            <p className="text-xs leading-relaxed text-gray-300">{summary}</p>
          </div>
        </td>
      </tr>
    );
  }

  // Summary not yet generated — either still generating or never triggered
  const wasNeverGenerated = !scan.aiSummarisedAt && !fresh?.aiSummarisedAt;

  return (
    <tr>
      <td colSpan={7} className="px-4 pb-3 pt-0">
        {splitBadge}
        <div className="flex items-center gap-3 rounded-lg border border-dashed border-indigo-900/50 bg-indigo-950/20 px-4 py-2.5">
          {isGenerating && !wasNeverGenerated ? (
            <>
              <Sparkles className="h-3.5 w-3.5 animate-pulse text-indigo-500 flex-shrink-0" />
              <span className="text-xs text-indigo-400">AI summary generating… checking every 5 s</span>
            </>
          ) : (
            <>
              <Sparkles className="h-3.5 w-3.5 text-indigo-500 flex-shrink-0" />
              <span className="text-xs text-indigo-500">
                {generateMutation.isError
                  ? "Failed to start — "
                  : "Summary not generated yet — "}
              </span>
              <button
                onClick={() => generateMutation.mutate()}
                disabled={generateMutation.isPending}
                className="flex items-center gap-1 text-xs text-indigo-400 hover:text-indigo-200 disabled:opacity-50"
              >
                <RefreshCw className={`h-3 w-3 ${generateMutation.isPending ? "animate-spin" : ""}`} />
                {generateMutation.isPending ? "Queuing…" : "Generate now"}
              </button>
            </>
          )}
        </div>
      </td>
    </tr>
  );
}

/** Modal comparing two completed scans — added / removed / unchanged */
function ScanDiffModal({ scanId, onClose }: { scanId: string; onClose: () => void }) {
  const { data, isLoading, error } = useQuery({
    queryKey: ["scan-diff", scanId],
    queryFn:  () => scansApi.diff(scanId),
    staleTime: 60_000,
  });

  const fmtWhen = (iso?: string | null) => iso ? formatRelative(iso) : "—";

  return (
    <div
      className="fixed inset-0 z-50 flex items-center justify-center bg-black/60 p-4"
      onClick={onClose}
    >
      <div
        className="flex max-h-[85vh] w-full max-w-4xl flex-col overflow-hidden rounded-xl border border-gray-800 bg-gray-950 shadow-2xl"
        onClick={(e) => e.stopPropagation()}
      >
        {/* Header */}
        <div className="flex items-center justify-between border-b border-gray-800 px-5 py-3">
          <div className="flex items-center gap-2">
            <GitCompare className="h-4 w-4 text-indigo-400" />
            <h2 className="text-sm font-semibold text-white">Scan comparison</h2>
          </div>
          <button onClick={onClose} className="rounded p-1 text-gray-500 hover:bg-gray-800 hover:text-gray-200">
            <X className="h-4 w-4" />
          </button>
        </div>

        {/* Body */}
        <div className="flex-1 overflow-y-auto px-5 py-4">
          {isLoading ? (
            <div className="flex h-40 items-center justify-center text-gray-500">Loading diff…</div>
          ) : error ? (
            <div className="flex h-40 items-center justify-center text-red-400 text-sm">
              Failed to load diff — {(error as Error).message}
            </div>
          ) : !data ? null : !data.scanA || data.reason ? (
            <div className="flex h-40 flex-col items-center justify-center gap-2 px-6 text-center text-sm text-gray-500">
              <GitCompare className="h-6 w-6" />
              <p>
                {data.reason
                  ?? "No earlier completed scan for this target — nothing to compare against yet."}
              </p>
              {data.effectiveScanTypes !== undefined && data.effectiveScanTypes.length === 0 && (
                <p className="text-[11px] text-gray-600">
                  Re-run the scan with overlapping scan types to enable comparison.
                </p>
              )}
            </div>
          ) : (
            <>
              {/* Scan meta */}
              <div className="mb-4 grid grid-cols-2 gap-3 text-xs">
                <div className="rounded border border-gray-800 bg-gray-900/60 px-3 py-2">
                  <div className="text-[10px] uppercase tracking-wider text-gray-500">Previous (A)</div>
                  <div className="font-mono text-gray-300">{data.scanA.id.slice(-12)}</div>
                  <div className="mt-0.5 text-gray-500">{fmtWhen(data.scanA.completedAt)}</div>
                  {typeof data.scanA.targetUrlCount === "number" && (
                    <div className="mt-1 text-[10px] text-gray-500">
                      {data.scanA.targetUrlCount} URL(s) examined
                    </div>
                  )}
                </div>
                <div className="rounded border border-indigo-900/50 bg-indigo-950/30 px-3 py-2">
                  <div className="text-[10px] uppercase tracking-wider text-indigo-400">This scan (B)</div>
                  <div className="font-mono text-gray-200">{data.scanB.id.slice(-12)}</div>
                  <div className="mt-0.5 text-gray-500">{fmtWhen(data.scanB.completedAt)}</div>
                  {typeof data.scanB.targetUrlCount === "number" && (
                    <div className="mt-1 text-[10px] text-gray-500">
                      {data.scanB.targetUrlCount} URL(s) examined
                    </div>
                  )}
                </div>
              </div>

              {/* Summary pills */}
              <div className="mb-4 flex flex-wrap items-center gap-2 text-xs">
                <span className="inline-flex items-center gap-1 rounded bg-emerald-950/60 px-2 py-1 text-emerald-300">
                  <Plus className="h-3 w-3" /> {data.added.length} added
                </span>
                <span className="inline-flex items-center gap-1 rounded bg-rose-950/60 px-2 py-1 text-rose-300">
                  <Minus className="h-3 w-3" /> {data.removed.length} fixed
                </span>
                {data.scopeAware &&
                  (data.outOfScopeRemoved.length > 0 || data.outOfScopeAdded.length > 0) && (
                  <span
                    className="inline-flex items-center gap-1 rounded bg-amber-950/60 px-2 py-1 text-amber-300"
                    title="Findings whose URL was not re-visited in the other scan — we cannot claim they were fixed or newly introduced"
                  >
                    {data.outOfScopeRemoved.length + data.outOfScopeAdded.length} out of scope
                  </span>
                )}
                <span className="inline-flex items-center gap-1 rounded bg-gray-800/70 px-2 py-1 text-gray-400">
                  {data.unchangedCount} unchanged
                </span>
              </div>

              {/* Added (in-scope) */}
              <DiffSection
                title="Added in this scan"
                Icon={Plus}
                tone="emerald"
                items={data.added}
              />
              {/* Removed (in-scope = genuinely fixed) */}
              <DiffSection
                title={data.scopeAware ? "Fixed (URL re-scanned, vuln gone)" : "No longer present"}
                Icon={Minus}
                tone="rose"
                items={data.removed}
              />
              {/* Out of scope this run — only shown when scope info is available */}
              {data.scopeAware && data.outOfScopeRemoved.length > 0 && (
                <DiffSection
                  title="Not re-checked (URL never visited in this scan)"
                  Icon={Minus}
                  tone="amber"
                  items={data.outOfScopeRemoved}
                />
              )}
              {data.scopeAware && data.outOfScopeAdded.length > 0 && (
                <DiffSection
                  title="Newly discovered URL surface"
                  Icon={Plus}
                  tone="amber"
                  items={data.outOfScopeAdded}
                />
              )}
            </>
          )}
        </div>
      </div>
    </div>
  );
}

function DiffSection({
  title, Icon, tone, items,
}: {
  title: string;
  Icon: React.ComponentType<{ className?: string }>;
  tone: "emerald" | "rose" | "amber";
  items: Array<{ id: string; title: string; severity: string; scanType: string; filePath?: string | null; lineStart?: number | null }>;
}) {
  if (items.length === 0) return null;
  const toneText =
    tone === "emerald" ? "text-emerald-400"
    : tone === "rose"  ? "text-rose-400"
    :                    "text-amber-400";
  return (
    <div className="mb-5">
      <div className={`mb-2 flex items-center gap-1.5 text-xs font-semibold ${toneText}`}>
        <Icon className="h-3.5 w-3.5" />
        {title} <span className="text-gray-500">({items.length})</span>
      </div>
      <ul className="divide-y divide-gray-800 rounded border border-gray-800 bg-gray-900/50">
        {items.slice(0, 100).map((f) => (
          <li key={f.id} className="flex items-center gap-3 px-3 py-2 text-xs">
            <SeverityBadge severity={f.severity as never} />
            <span className="flex-1 truncate text-gray-300" title={f.title}>{f.title}</span>
            <span className="text-gray-500">{f.scanType}</span>
            {f.filePath && (
              <span className="truncate max-w-[200px] font-mono text-gray-500" title={f.filePath}>
                {f.filePath}{f.lineStart ? `:${f.lineStart}` : ""}
              </span>
            )}
          </li>
        ))}
        {items.length > 100 && (
          <li className="px-3 py-1.5 text-[11px] text-gray-500">
            …and {items.length - 100} more (showing first 100)
          </li>
        )}
      </ul>
    </div>
  );
}

export default function ScansPage() {
  const [page, setPage] = useState(1);
  const [expandedSummary, setExpandedSummary] = useState<string | null>(null);
  const [expandedError,   setExpandedError]   = useState<string | null>(null);
  const [diffScanId, setDiffScanId] = useState<string | null>(null);
  const LIMIT = 20;
  const queryClient = useQueryClient();

  const { data, isLoading } = useQuery({
    queryKey: ["scans", page],
    queryFn: () => scansApi.list(page, LIMIT),
    // Auto-refresh while any scan is active
    refetchInterval: (query) => {
      const d = query.state.data;
      if (!d) return false;
      const hasActive = d.data.some(
        (s) => s.status === "PENDING" || s.status === "RUNNING"
      );
      return hasActive ? 3000 : false;
    },
  });

  const cancelMutation = useMutation({
    mutationFn: (id: string) => scansApi.cancel(id),
    onSuccess: () => queryClient.invalidateQueries({ queryKey: ["scans"] }),
  });

  const deleteMutation = useMutation({
    mutationFn: (id: string) => scansApi.delete(id),
    onSuccess: () => queryClient.invalidateQueries({ queryKey: ["scans"] }),
  });

  const clearFailedMutation = useMutation({
    mutationFn: () => scansApi.clearFailed(),
    onSuccess: () => queryClient.invalidateQueries({ queryKey: ["scans"] }),
  });

  const failedCount = data?.data.filter((s) => s.status === "FAILED").length ?? 0;

  const totalPages = data ? Math.ceil(data.total / LIMIT) : 1;

  return (
    <div className="p-6">
      <div className="mb-6 flex items-center justify-between">
        <div>
          <h1 className="text-3xl font-bold text-white">Scans</h1>
          <p className="mt-0.5 text-xs text-gray-500">
            {data ? `${data.total} scan${data.total !== 1 ? "s" : ""} — active and completed` : ""}
          </p>
        </div>
        {failedCount > 0 && (
          <button
            onClick={() => clearFailedMutation.mutate()}
            disabled={clearFailedMutation.isPending}
            className="flex items-center gap-1.5 rounded-lg border border-red-900/50 bg-red-950/30 px-3 py-1.5 text-xs text-red-400 hover:border-red-700 hover:text-red-300 disabled:opacity-50 transition-colors"
          >
            <Trash2 className="h-3.5 w-3.5" />
            {clearFailedMutation.isPending ? "Clearing…" : `Clear ${failedCount} failed`}
          </button>
        )}
      </div>

      {isLoading ? (
        <div className="flex h-48 items-center justify-center text-gray-500">Loading…</div>
      ) : !data?.data.length ? (
        <div className="flex h-48 flex-col items-center justify-center gap-3 text-gray-500">
          <Activity className="h-8 w-8" />
          <p>No scans yet — trigger a scan from Repositories, Containers, or Domains.</p>
        </div>
      ) : (
        <>
          <div className="overflow-x-auto rounded-lg border border-gray-800">
            <table className="w-full text-sm">
              <thead className="border-b border-gray-800 bg-gray-900">
                <tr className="text-left text-xs text-gray-500">
                  <th className="px-4 py-3 font-medium">Target</th>
                  <th className="px-4 py-3 font-medium">Trigger</th>
                  <th className="px-4 py-3 font-medium">Scan Types</th>
                  <th className="px-4 py-3 font-medium">Status / Progress</th>
                  <th className="px-4 py-3 font-medium">Findings</th>
                  <th className="px-4 py-3 font-medium">Duration</th>
                  <th className="px-4 py-3 font-medium">Started</th>
                  <th className="px-4 py-3 font-medium"></th>
                </tr>
              </thead>
              <tbody className="divide-y divide-gray-800 bg-gray-900/50">
                {data.data.map((scan) => {
                  const isActive = scan.status === "PENDING" || scan.status === "RUNNING";
                  const isCancelling = cancelMutation.isPending && cancelMutation.variables === scan.id;

                  return (
                    <React.Fragment key={scan.id}>
                    <tr className="hover:bg-gray-800/40">
                      {/* Target */}
                      <td className="px-4 py-3">
                        <div className="flex flex-col gap-1">
                          <span className={`inline-flex items-center gap-1.5 rounded px-2 py-0.5 text-xs font-medium w-fit ${TYPE_CHIP}`}>
                            {TYPE_ICONS[scan.targetType]}
                            {scan.targetType}
                          </span>
                          <span
                            className="max-w-[200px] truncate text-xs text-gray-300"
                            title={scan.repository?.fullName ?? scan.container?.imageRef ?? scan.domain?.domain}
                          >
                            {scan.repository?.fullName ?? scan.container?.imageRef ?? scan.domain?.domain}
                          </span>
                        </div>
                      </td>

                      {/* Trigger */}
                      <td className="px-4 py-3">
                        <TriggerChip
                          triggerType={(scan as unknown as { triggerType?: string }).triggerType}
                          prNumber={(scan as unknown as { prNumber?: number }).prNumber}
                          commitSha={(scan as unknown as { commitSha?: string }).commitSha}
                          repoFullName={scan.repository?.fullName}
                        />
                      </td>

                      {/* Scan types */}
                      <td className="px-4 py-3">
                        <div className="flex flex-wrap gap-1">
                          {scan.scanTypes.map((t) => (
                            <span key={t} className="rounded bg-gray-800 px-1.5 py-0.5 text-xs text-gray-400">
                              {t}
                            </span>
                          ))}
                        </div>
                      </td>

                      {/* Status + progress bar */}
                      <td className="px-4 py-3 min-w-[160px]">
                        <div className="flex flex-col gap-1">
                          <div className="flex items-center gap-2">
                            <ScanStatusBadge status={scan.status} />
                            {scan.status === "FAILED" && scan.error && (
                              <button
                                onClick={() => setExpandedError(
                                  expandedError === scan.id ? null : scan.id
                                )}
                                className="flex items-center gap-1 text-xs text-red-400 hover:text-red-300 max-w-[180px]"
                                title="Click to see diagnostic details"
                              >
                                <span className="truncate">{scan.error}</span>
                                <ChevronDown className={`h-3 w-3 flex-none transition-transform ${expandedError === scan.id ? "rotate-180" : ""}`} />
                              </button>
                            )}
                          </div>
                          <ScanProgressBar scan={scan} />
                        </div>
                      </td>

                      {/* Finding counts */}
                      <td className="px-4 py-3">
                        {scan.status === "COMPLETED" ? (
                          <div className="flex items-center gap-1">
                            <SeverityPill count={scan.criticalCount ?? 0} color="bg-red-950/70    text-red-300"    />
                            <SeverityPill count={scan.highCount ?? 0}     color="bg-orange-950/70 text-orange-300" />
                            <SeverityPill count={scan.mediumCount ?? 0}   color="bg-amber-950/70  text-amber-300"  />
                            <SeverityPill count={scan.lowCount ?? 0}      color="bg-sky-950/70    text-sky-300"    />
                            {!scan.criticalCount && !scan.highCount && !scan.mediumCount && !scan.lowCount && (
                              <span className="text-xs text-gray-600">No findings</span>
                            )}
                          </div>
                        ) : (
                          <span className="text-xs text-gray-600">—</span>
                        )}
                      </td>

                      {/* Duration */}
                      <td className="px-4 py-3">
                        <span className="inline-flex items-center gap-1 text-xs text-gray-400">
                          <Clock className="h-3 w-3 text-gray-600" />
                          {duration(scan)}
                        </span>
                      </td>

                      {/* Started */}
                      <td className="px-4 py-3 text-xs text-gray-500">
                        {scan.createdAt ? formatRelative(scan.createdAt) : "—"}
                      </td>

                      {/* Actions */}
                      <td className="px-4 py-3">
                        <div className="flex items-center gap-2">
                          {isActive && (
                            <button
                              onClick={() => cancelMutation.mutate(scan.id)}
                              disabled={isCancelling}
                              title="Stop scan"
                              className="inline-flex items-center gap-1 rounded border border-gray-700 px-2 py-1 text-xs text-gray-400 hover:border-red-700 hover:text-red-400 disabled:opacity-40 transition-colors"
                            >
                              <Square className="h-3 w-3" />
                              {isCancelling ? "Stopping…" : "Stop"}
                            </button>
                          )}
                          {scan.status === "COMPLETED" && (
                            <button
                              onClick={() => setExpandedSummary(
                                expandedSummary === scan.id ? null : scan.id
                              )}
                              title="AI Summary"
                              className="inline-flex items-center gap-1 rounded border border-gray-700/60 bg-gray-800/70 px-2 py-1 text-xs text-gray-300 hover:border-gray-600 hover:bg-gray-800 transition-colors"
                            >
                              <Sparkles className="h-3 w-3 text-indigo-400/80" />
                              AI
                              <ChevronDown className={`h-3 w-3 text-gray-500 transition-transform ${expandedSummary === scan.id ? "rotate-180" : ""}`} />
                            </button>
                          )}
                          {scan.status === "COMPLETED" && (
                            <button
                              onClick={() => setDiffScanId(scan.id)}
                              title="Compare to previous scan"
                              className="inline-flex items-center gap-1 rounded border border-gray-700/60 bg-gray-800/70 px-2 py-1 text-xs text-gray-300 hover:border-gray-600 hover:bg-gray-800 transition-colors"
                            >
                              <GitCompare className="h-3 w-3 text-indigo-400/80" />
                              Diff
                            </button>
                          )}
                          {(scan.status === "FAILED" || scan.status === "CANCELLED") && (
                            <button
                              onClick={() => deleteMutation.mutate(scan.id)}
                              disabled={deleteMutation.isPending && deleteMutation.variables === scan.id}
                              title="Remove"
                              className="inline-flex items-center gap-1 rounded border border-gray-700 px-2 py-1 text-xs text-gray-500 hover:border-red-700 hover:text-red-400 disabled:opacity-40 transition-colors"
                            >
                              <Trash2 className="h-3 w-3" />
                            </button>
                          )}
                        </div>
                      </td>
                    </tr>
                    {expandedSummary === scan.id && (
                      <AISummaryRow scan={scan} />
                    )}
                    {expandedError === scan.id && scan.error && (
                      <ErrorDiagnosticsRow scan={scan} />
                    )}
                    </React.Fragment>
                  );
                })}
              </tbody>
            </table>
          </div>

          {/* Pagination */}
          {totalPages > 1 && (
            <div className="mt-4 flex items-center justify-between text-xs text-gray-500">
              <span>
                Page {page} of {totalPages} ({data.total} scans)
              </span>
              <div className="flex items-center gap-2">
                <button
                  onClick={() => setPage((p) => Math.max(1, p - 1))}
                  disabled={page === 1}
                  className="flex items-center gap-1 rounded border border-gray-700 px-2 py-1 hover:border-gray-500 disabled:opacity-40"
                >
                  <ChevronLeft className="h-3 w-3" /> Prev
                </button>
                <button
                  onClick={() => setPage((p) => Math.min(totalPages, p + 1))}
                  disabled={page === totalPages}
                  className="flex items-center gap-1 rounded border border-gray-700 px-2 py-1 hover:border-gray-500 disabled:opacity-40"
                >
                  Next <ChevronRight className="h-3 w-3" />
                </button>
              </div>
            </div>
          )}
        </>
      )}

      {/* Scan diff modal */}
      {diffScanId && (
        <ScanDiffModal scanId={diffScanId} onClose={() => setDiffScanId(null)} />
      )}
    </div>
  );
}

// ── Trigger chip — shows how the scan was initiated (manual / push / PR) ────
function TriggerChip({
  triggerType,
  prNumber,
  commitSha,
  repoFullName,
}: {
  triggerType?:  string;
  prNumber?:     number;
  commitSha?:    string;
  repoFullName?: string;
}) {
  const t = triggerType ?? "MANUAL";
  const commitShort = commitSha?.slice(0, 7);

  if (t === "PULL_REQUEST" && prNumber && repoFullName) {
    return (
      <a
        href={`https://github.com/${repoFullName}/pull/${prNumber}`}
        target="_blank"
        rel="noopener noreferrer"
        className="inline-flex items-center gap-1 rounded bg-indigo-900/40 px-2 py-0.5 text-xs font-medium text-indigo-200 hover:bg-indigo-900/70"
        title={commitShort ? `PR head: ${commitShort}` : undefined}
      >
        PR #{prNumber}
      </a>
    );
  }

  if (t === "PUSH" && commitShort) {
    return (
      <span className="inline-flex items-center gap-1 rounded bg-teal-900/40 px-2 py-0.5 text-xs font-medium text-teal-200">
        push · {commitShort}
      </span>
    );
  }

  if (t === "SCHEDULED") {
    return (
      <span className="inline-flex items-center gap-1 rounded bg-amber-900/40 px-2 py-0.5 text-xs font-medium text-amber-200">
        scheduled
      </span>
    );
  }

  return (
    <span className="inline-flex items-center gap-1 rounded bg-gray-800 px-2 py-0.5 text-xs font-medium text-gray-400">
      manual
    </span>
  );
}
