import { useState } from "react";
import { useQuery } from "@tanstack/react-query";
import { ShieldAlert, Search } from "lucide-react";
import { findingsApi } from "../lib/api";
import type { Finding } from "@devsecops/types";
import SeverityBadge from "../components/SeverityBadge";
import FindingDetailDrawer from "../components/FindingDetailDrawer";
import { formatRelative } from "../lib/utils";

const SEVERITIES = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"];
const SCAN_TYPES = ["SAST", "SCA", "SECRET", "IAC", "CONTAINER", "DAST", "PENTEST"];
const STATUSES = ["OPEN", "ACKNOWLEDGED", "FALSE_POSITIVE", "FIXED"];

export default function FindingsPage() {
  const [severity, setSeverity] = useState("");
  const [scanType, setScanType] = useState("");
  const [status, setStatus] = useState("OPEN");
  const [search, setSearch] = useState("");
  const [page, setPage] = useState(1);
  const [selected, setSelected] = useState<Finding | null>(null);

  const { data, isLoading } = useQuery({
    queryKey: ["findings", { severity, scanType, status, search, page }],
    queryFn: () =>
      findingsApi.list({
        severity: severity || undefined,
        scanType: (scanType || undefined) as never,
        status: (status || undefined) as never,
        search: search || undefined,
        page,
        limit: 25,
      }),
  });

  return (
    <div className="flex h-full flex-col p-6">
      <h1 className="mb-5 text-xl font-bold text-white">Findings</h1>

      {/* Filter bar */}
      <div className="mb-4 flex flex-wrap items-center gap-3">
        <div className="relative">
          <Search className="absolute left-2.5 top-1/2 h-3.5 w-3.5 -translate-y-1/2 text-gray-500" />
          <input
            className="rounded bg-gray-800 pl-8 pr-3 py-1.5 text-sm text-gray-200 placeholder-gray-500 focus:outline-none focus:ring-1 focus:ring-indigo-500 w-48"
            placeholder="Search findings…"
            value={search}
            onChange={(e) => { setSearch(e.target.value); setPage(1); }}
          />
        </div>

        <select value={severity} onChange={(e) => { setSeverity(e.target.value); setPage(1); }}
          className="rounded bg-gray-800 px-3 py-1.5 text-sm text-gray-300 focus:outline-none focus:ring-1 focus:ring-indigo-500">
          <option value="">All severities</option>
          {SEVERITIES.map((s) => <option key={s}>{s}</option>)}
        </select>

        <select value={scanType} onChange={(e) => { setScanType(e.target.value); setPage(1); }}
          className="rounded bg-gray-800 px-3 py-1.5 text-sm text-gray-300 focus:outline-none focus:ring-1 focus:ring-indigo-500">
          <option value="">All types</option>
          {SCAN_TYPES.map((t) => <option key={t}>{t}</option>)}
        </select>

        <select value={status} onChange={(e) => { setStatus(e.target.value); setPage(1); }}
          className="rounded bg-gray-800 px-3 py-1.5 text-sm text-gray-300 focus:outline-none focus:ring-1 focus:ring-indigo-500">
          <option value="">All statuses</option>
          {STATUSES.map((s) => <option key={s}>{s}</option>)}
        </select>

        {data && (
          <span className="ml-auto text-xs text-gray-500">{data.total} findings</span>
        )}
      </div>

      {/* Table */}
      <div className="flex-1 overflow-auto rounded-lg border border-gray-800">
        <table className="w-full text-sm">
          <thead className="sticky top-0 border-b border-gray-800 bg-gray-900">
            <tr className="text-left text-xs text-gray-500">
              <th className="px-4 py-3 font-medium">Severity</th>
              <th className="px-4 py-3 font-medium">Title</th>
              <th className="px-4 py-3 font-medium">Type</th>
              <th className="px-4 py-3 font-medium">Location</th>
              <th className="px-4 py-3 font-medium">Status</th>
              <th className="px-4 py-3 font-medium">First Seen</th>
            </tr>
          </thead>
          <tbody className="divide-y divide-gray-800 bg-gray-900/50">
            {isLoading ? (
              <tr><td colSpan={6} className="py-12 text-center text-gray-500">Loading…</td></tr>
            ) : data?.data.length === 0 ? (
              <tr>
                <td colSpan={6} className="py-12 text-center">
                  <ShieldAlert className="mx-auto mb-2 h-8 w-8 text-gray-700" />
                  <p className="text-gray-500">No findings match your filters.</p>
                </td>
              </tr>
            ) : (
              data?.data.map((f) => (
                <tr key={f.id} className="cursor-pointer hover:bg-gray-800/40" onClick={() => setSelected(f)}>
                  <td className="px-4 py-3"><SeverityBadge severity={f.severity} /></td>
                  <td className="px-4 py-3 max-w-sm">
                    <p className="truncate font-medium text-gray-200">{f.title}</p>
                    {f.cveId && <p className="text-xs text-gray-500">{f.cveId}</p>}
                  </td>
                  <td className="px-4 py-3 text-xs text-gray-400">{f.scanType}</td>
                  <td className="px-4 py-3 max-w-[180px]">
                    {f.filePath ? (
                      <span className="truncate font-mono text-xs text-gray-400">
                        {f.filePath}{f.lineStart ? `:${f.lineStart}` : ""}
                      </span>
                    ) : <span className="text-gray-600">—</span>}
                  </td>
                  <td className="px-4 py-3">
                    <span className={`text-xs ${f.status === "FIXED" ? "text-green-400" : f.status === "FALSE_POSITIVE" ? "text-gray-500" : "text-gray-300"}`}>
                      {f.status}
                    </span>
                  </td>
                  <td className="px-4 py-3 text-xs text-gray-500">{formatRelative(f.firstSeen)}</td>
                </tr>
              ))
            )}
          </tbody>
        </table>
      </div>

      {/* Pagination */}
      {data && data.totalPages > 1 && (
        <div className="mt-4 flex items-center justify-end gap-2">
          <button onClick={() => setPage((p) => Math.max(1, p - 1))} disabled={page === 1}
            className="rounded bg-gray-800 px-3 py-1.5 text-xs text-gray-300 hover:bg-gray-700 disabled:opacity-40">
            Previous
          </button>
          <span className="text-xs text-gray-500">Page {page} of {data.totalPages}</span>
          <button onClick={() => setPage((p) => Math.min(data.totalPages, p + 1))} disabled={page === data.totalPages}
            className="rounded bg-gray-800 px-3 py-1.5 text-xs text-gray-300 hover:bg-gray-700 disabled:opacity-40">
            Next
          </button>
        </div>
      )}

      <FindingDetailDrawer finding={selected} onClose={() => setSelected(null)} />
    </div>
  );
}
