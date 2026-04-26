/**
 * Audit Log tab — read-only view of every recorded mutation event for the
 * current org. ADMIN+ only (the API enforces this; the tab also hides
 * itself for lower roles via SettingsPage's <Can> guard).
 *
 * Filters: action prefix, resource type, user, date range.
 * Pagination: simple offset + limit, server returns total count.
 * Export: hits the CSV endpoint with the same filters as a file download.
 */
import { Fragment, useState } from "react";
import { useQuery } from "@tanstack/react-query";
import {
  ChevronDown, ChevronLeft, ChevronRight, ChevronUp, Download,
  Search, ScrollText, X,
} from "lucide-react";
import { auditApi, type AuditFilters } from "../../lib/api";
import { formatDate } from "../../lib/utils";

const PAGE_SIZE = 50;

export default function AuditLogTab() {
  const [filters, setFilters] = useState<AuditFilters>({});
  const [page, setPage] = useState(0);
  // Click a metadata cell to expand a pretty-printed JSON payload row
  // beneath. Multiple rows can be open simultaneously — auditors often
  // compare two events side-by-side. Set is keyed by AuditEvent.id.
  const [expandedIds, setExpandedIds] = useState<Set<string>>(new Set());

  function toggleExpand(id: string) {
    setExpandedIds((prev) => {
      const next = new Set(prev);
      if (next.has(id)) next.delete(id);
      else next.add(id);
      return next;
    });
  }

  const queryFilters: AuditFilters = {
    ...filters,
    limit:  PAGE_SIZE,
    offset: page * PAGE_SIZE,
  };

  const { data, isLoading, isError, error, refetch } = useQuery({
    queryKey: ["audit", queryFilters],
    queryFn:  () => auditApi.list(queryFilters),
  });

  function applyFilter(patch: Partial<AuditFilters>) {
    setFilters((f) => ({ ...f, ...patch }));
    setPage(0);
  }

  function clearFilters() {
    setFilters({});
    setPage(0);
  }

  const hasFilters = Object.values(filters).some((v) => v !== undefined && v !== "");

  const rows  = data?.rows ?? [];
  const total = data?.total ?? 0;
  const from  = total === 0 ? 0 : page * PAGE_SIZE + 1;
  const to    = Math.min((page + 1) * PAGE_SIZE, total);

  return (
    <div>
      {/* ── Header ─────────────────────────────────────────────────────────── */}
      <div className="mb-4 flex items-center gap-2">
        <ScrollText className="h-4 w-4 text-indigo-400" />
        <h2 className="text-base font-semibold text-white">Audit Log</h2>
        <span className="ml-auto text-xs text-gray-500">
          Every mutation event is recorded — write paths log to <code className="text-indigo-300">AuditEvent</code>.
        </span>
      </div>

      {/* ── Filters ────────────────────────────────────────────────────────── */}
      <div className="mb-4 grid grid-cols-1 gap-3 rounded-lg border border-gray-800 bg-gray-900/40 p-3 sm:grid-cols-5">
        <FilterInput
          label="Action prefix"
          placeholder="finding."
          value={filters.actionPrefix ?? ""}
          onChange={(v) => applyFilter({ actionPrefix: v || undefined })}
        />
        <FilterInput
          label="Resource type"
          placeholder="Finding"
          value={filters.resourceType ?? ""}
          onChange={(v) => applyFilter({ resourceType: v || undefined })}
        />
        <FilterInput
          label="User ID"
          placeholder="cm…"
          value={filters.userId ?? ""}
          onChange={(v) => applyFilter({ userId: v || undefined })}
        />
        <FilterInput
          type="datetime-local"
          label="From"
          value={filters.fromDate?.slice(0, 16) ?? ""}
          onChange={(v) => applyFilter({ fromDate: v ? new Date(v).toISOString() : undefined })}
        />
        <FilterInput
          type="datetime-local"
          label="To"
          value={filters.toDate?.slice(0, 16) ?? ""}
          onChange={(v) => applyFilter({ toDate: v ? new Date(v).toISOString() : undefined })}
        />
      </div>

      {/* ── Action bar ─────────────────────────────────────────────────────── */}
      <div className="mb-3 flex items-center gap-2">
        <span className="text-xs text-gray-500">
          {isLoading
            ? "Loading…"
            : total === 0
              ? "No matching events"
              : `Showing ${from}–${to} of ${total}`}
        </span>
        {hasFilters && (
          <button
            onClick={clearFilters}
            className="inline-flex items-center gap-1 rounded px-2 py-1 text-xs text-gray-400 hover:bg-gray-800 hover:text-gray-200"
          >
            <X className="h-3 w-3" />
            Clear filters
          </button>
        )}
        <button
          onClick={() => refetch()}
          className="inline-flex items-center gap-1 rounded px-2 py-1 text-xs text-gray-400 hover:bg-gray-800 hover:text-gray-200"
        >
          <Search className="h-3 w-3" />
          Refresh
        </button>
        <a
          href={auditApi.exportCsvUrl(filters)}
          download
          className="ml-auto inline-flex items-center gap-1.5 rounded-md bg-indigo-600 px-3 py-1.5 text-xs font-semibold text-white hover:bg-indigo-500"
        >
          <Download className="h-3 w-3" />
          Export CSV
        </a>
      </div>

      {/* ── Error state ────────────────────────────────────────────────────── */}
      {isError && (
        <div className="mb-3 rounded-md border border-red-900/50 bg-red-950/30 px-3 py-2 text-xs text-red-300">
          Failed to load audit log: {(error as Error)?.message ?? "unknown error"}
        </div>
      )}

      {/* ── Table ──────────────────────────────────────────────────────────── */}
      <div className="overflow-hidden rounded-lg border border-gray-800">
        <table className="w-full text-left text-xs">
          <thead>
            <tr className="border-b border-gray-800 bg-gray-900/60 text-gray-400">
              <th className="px-3 py-2 font-semibold">Timestamp</th>
              <th className="px-3 py-2 font-semibold">Actor</th>
              <th className="px-3 py-2 font-semibold">Action</th>
              <th className="px-3 py-2 font-semibold">Resource</th>
              <th className="px-3 py-2 font-semibold">Metadata</th>
            </tr>
          </thead>
          <tbody className="divide-y divide-gray-800/60">
            {rows.length === 0 && !isLoading && (
              <tr>
                <td colSpan={5} className="px-3 py-8 text-center text-gray-600">
                  {hasFilters ? "No events match the current filters." : "No audit events yet."}
                </td>
              </tr>
            )}
            {rows.map((row) => {
              const fieldCount = Object.keys(row.metadata ?? {}).length;
              const isExpanded = expandedIds.has(row.id);
              return (
                <Fragment key={row.id}>
                  <tr className="hover:bg-gray-800/30">
                    <td className="px-3 py-2 font-mono text-[11px] text-gray-400 whitespace-nowrap">
                      {formatDate(row.createdAt)}
                    </td>
                    <td className="px-3 py-2 text-gray-300 whitespace-nowrap">
                      {row.user ? (
                        <span className="inline-flex items-center gap-1.5">
                          {row.user.avatarUrl && (
                            <img src={row.user.avatarUrl} alt="" className="h-4 w-4 rounded-full ring-1 ring-gray-700" />
                          )}
                          {row.user.username}
                        </span>
                      ) : (
                        <span className="text-gray-500 italic">{row.userId}</span>
                      )}
                    </td>
                    <td className="px-3 py-2 font-mono text-[11px] text-indigo-300 whitespace-nowrap">
                      {row.action}
                    </td>
                    <td className="px-3 py-2 text-gray-400 whitespace-nowrap">
                      <span className="text-gray-500">{row.resourceType}</span>
                      {row.resourceId && (
                        <span className="ml-1 font-mono text-[10px] text-gray-600">{row.resourceId}</span>
                      )}
                    </td>
                    <td className="px-3 py-2">
                      {fieldCount > 0 ? (
                        <button
                          onClick={() => toggleExpand(row.id)}
                          className="inline-flex items-center gap-1 rounded px-1.5 py-0.5 text-[11px] text-gray-400 hover:bg-gray-800 hover:text-indigo-300"
                          aria-expanded={isExpanded}
                          title={isExpanded ? "Collapse metadata" : "Expand metadata"}
                        >
                          {isExpanded
                            ? <ChevronUp   className="h-3 w-3" />
                            : <ChevronDown className="h-3 w-3" />}
                          {fieldCount} field{fieldCount === 1 ? "" : "s"}
                        </button>
                      ) : (
                        <span className="text-gray-700">—</span>
                      )}
                    </td>
                  </tr>
                  {isExpanded && (
                    <tr className="bg-indigo-950/20 border-l-2 border-l-indigo-700/50">
                      {/* colSpan covers all 5 columns; pre wraps long values */}
                      <td colSpan={5} className="px-3 pb-3 pt-1">
                        <pre className="overflow-x-auto rounded-md bg-gray-950 px-3 py-2 font-mono text-[10px] leading-relaxed text-indigo-200">
{JSON.stringify(row.metadata, null, 2)}
                        </pre>
                      </td>
                    </tr>
                  )}
                </Fragment>
              );
            })}
          </tbody>
        </table>
      </div>

      {/* ── Pagination ─────────────────────────────────────────────────────── */}
      {total > PAGE_SIZE && (
        <div className="mt-3 flex items-center justify-end gap-2 text-xs">
          <button
            disabled={page === 0}
            onClick={() => setPage((p) => Math.max(0, p - 1))}
            className="inline-flex items-center gap-1 rounded px-2 py-1 text-gray-400 hover:bg-gray-800 hover:text-gray-200 disabled:cursor-not-allowed disabled:opacity-40"
          >
            <ChevronLeft className="h-3 w-3" />
            Prev
          </button>
          <span className="text-gray-500">
            Page {page + 1} of {Math.ceil(total / PAGE_SIZE)}
          </span>
          <button
            disabled={(page + 1) * PAGE_SIZE >= total}
            onClick={() => setPage((p) => p + 1)}
            className="inline-flex items-center gap-1 rounded px-2 py-1 text-gray-400 hover:bg-gray-800 hover:text-gray-200 disabled:cursor-not-allowed disabled:opacity-40"
          >
            Next
            <ChevronRight className="h-3 w-3" />
          </button>
        </div>
      )}
    </div>
  );
}

function FilterInput({
  label,
  type = "text",
  value,
  placeholder,
  onChange,
}: {
  label:        string;
  type?:        "text" | "datetime-local";
  value:        string;
  placeholder?: string;
  onChange:     (v: string) => void;
}) {
  return (
    <label className="block">
      <span className="mb-1 block text-[10px] font-semibold uppercase tracking-wider text-gray-500">{label}</span>
      <input
        type={type}
        value={value}
        placeholder={placeholder}
        onChange={(e) => onChange(e.target.value)}
        className="w-full rounded border border-gray-800 bg-gray-950 px-2 py-1 text-xs text-gray-200 placeholder:text-gray-600 focus:border-indigo-700 focus:outline-none"
      />
    </label>
  );
}
