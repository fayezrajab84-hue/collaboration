import React, { useState, useEffect, useRef } from "react";
import { useQuery, useQueryClient, useMutation } from "@tanstack/react-query";
import { Activity, ChevronLeft, ChevronRight, GitBranch, Box, Globe, Clock, Square, Sparkles, ChevronDown, Trash2, RefreshCw } from "lucide-react";
import { scansApi } from "../lib/api";
import ScanStatusBadge from "../components/ScanStatusBadge";
import { formatRelative } from "../lib/utils";
import type { ScanJob } from "@devsecops/types";

const TYPE_ICONS: Record<string, React.ReactNode> = {
  REPOSITORY: <GitBranch className="h-3.5 w-3.5" />,
  CONTAINER:  <Box className="h-3.5 w-3.5" />,
  DOMAIN:     <Globe className="h-3.5 w-3.5" />,
};

const TYPE_COLORS: Record<string, string> = {
  REPOSITORY: "bg-indigo-900/50 text-indigo-300",
  CONTAINER:  "bg-cyan-900/50 text-cyan-300",
  DOMAIN:     "bg-emerald-900/50 text-emerald-300",
};

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

/** Subscribe to SSE for a scan job and return the latest phase progress (0-99).
 *  Returns null when not connected / no PHASE_PROGRESS received yet. */
function usePhaseProgress(scanId: string, active: boolean): number | null {
  const [pct, setPct] = useState<number | null>(null);
  const esRef = useRef<EventSource | null>(null);

  useEffect(() => {
    if (!active) { setPct(null); return; }
    if (esRef.current) return; // already connected

    const es = new EventSource(`/api/scans/${scanId}/events`);
    esRef.current = es;

    es.onmessage = (ev) => {
      try {
        const data = JSON.parse(ev.data);
        if (data.type === "PHASE_PROGRESS" && typeof data.pct === "number") {
          setPct(data.pct);
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

  return pct;
}

/** Thin animated progress bar for PENDING / RUNNING scans */
function ScanProgressBar({ scan }: { scan: ScanJob }) {
  const isActive = scan.status === "PENDING" || scan.status === "RUNNING";
  const phasePct = usePhaseProgress(scan.id, isActive);

  if (!isActive) return null;

  const total = scan.totalScans ?? 0;
  const done = scan.completedScans ?? 0;
  // Prefer real-time phase progress; fall back to coarse per-scanner progress
  const coarsePct = total > 0 ? Math.round((done / total) * 100) : 0;
  const displayPct = phasePct !== null ? phasePct : coarsePct;
  const isIndeterminate = displayPct === 0 && scan.status === "RUNNING";

  let label: string;
  if (scan.status === "PENDING") {
    label = "Queued…";
  } else if (phasePct !== null) {
    // We have real phase progress — show it
    label = done > 0 ? `${done} / ${total} scanners` : "Scanning…";
  } else if (done > 0) {
    label = `${done} / ${total} scanners`;
  } else {
    label = "Scanning…";
  }

  return (
    <div className="mt-1.5 space-y-0.5">
      <div className="flex items-center justify-between text-[10px] text-gray-500">
        <span>{label}</span>
        {displayPct > 0 && <span>{displayPct}%</span>}
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
    </div>
  );
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

  if (summary) {
    return (
      <tr>
        <td colSpan={7} className="px-4 pb-3 pt-0">
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

export default function ScansPage() {
  const [page, setPage] = useState(1);
  const [expandedSummary, setExpandedSummary] = useState<string | null>(null);
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
          <h1 className="text-3xl font-bold text-white">Scan History</h1>
          <p className="mt-0.5 text-xs text-gray-500">
            {data ? `${data.total} scan${data.total !== 1 ? "s" : ""} total` : ""}
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
                    <tr className="hover:bg-gray-800/30">
                      {/* Target */}
                      <td className="px-4 py-3">
                        <div className="flex flex-col gap-1">
                          <span className={`inline-flex items-center gap-1.5 rounded px-2 py-0.5 text-xs font-medium w-fit ${TYPE_COLORS[scan.targetType] ?? "bg-gray-800 text-gray-400"}`}>
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
                              <p className="text-xs text-red-400 max-w-[150px] truncate" title={scan.error}>
                                {scan.error}
                              </p>
                            )}
                          </div>
                          <ScanProgressBar scan={scan} />
                        </div>
                      </td>

                      {/* Finding counts */}
                      <td className="px-4 py-3">
                        {scan.status === "COMPLETED" ? (
                          <div className="flex items-center gap-1">
                            <SeverityPill count={scan.criticalCount ?? 0} color="bg-red-950 text-red-400" />
                            <SeverityPill count={scan.highCount ?? 0} color="bg-orange-950 text-orange-400" />
                            <SeverityPill count={scan.mediumCount ?? 0} color="bg-yellow-950 text-yellow-400" />
                            <SeverityPill count={scan.lowCount ?? 0} color="bg-green-950 text-green-400" />
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
                              className="inline-flex items-center gap-1 rounded border border-indigo-900/50 bg-indigo-950/30 px-2 py-1 text-xs text-indigo-400 hover:border-indigo-700 hover:text-indigo-300 transition-colors"
                            >
                              <Sparkles className="h-3 w-3" />
                              AI
                              <ChevronDown className={`h-3 w-3 transition-transform ${expandedSummary === scan.id ? "rotate-180" : ""}`} />
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
    </div>
  );
}
