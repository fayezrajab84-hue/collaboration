import { useState } from "react";
import { useQuery, useMutation } from "@tanstack/react-query";
import { useSearchParams } from "react-router-dom";
import { ShieldAlert, Search, GitBranch, Box, Globe, Layers, Sparkles, ChevronDown, ChevronRight, KeyRound, Bot, Wrench, X } from "lucide-react";
import { findingsApi, reposApi, containersApi, domainsApi } from "../lib/api";
import type { Finding, FindingGroup } from "@devsecops/types";
import SeverityBadge from "../components/SeverityBadge";
import ConfidenceBadge from "../components/ConfidenceBadge";
import FindingStatusBadge from "../components/FindingStatusBadge";
import FindingDetailDrawer from "../components/FindingDetailDrawer";
import { formatRelative } from "../lib/utils";
import { SEVERITY_BADGE } from "../lib/colors";

function TargetTag({ finding }: { finding: Finding }) {
  if (finding.repository) {
    return (
      <span className="inline-flex items-center gap-1 rounded bg-indigo-900/50 px-2 py-0.5 text-xs text-indigo-300 max-w-[160px] truncate">
        <GitBranch className="h-3 w-3 shrink-0" />
        <span className="truncate">{finding.repository.fullName}</span>
      </span>
    );
  }
  if (finding.container) {
    return (
      <span className="inline-flex items-center gap-1 rounded bg-cyan-900/50 px-2 py-0.5 text-xs text-cyan-300 max-w-[160px] truncate">
        <Box className="h-3 w-3 shrink-0" />
        <span className="truncate">{finding.container.imageRef}</span>
      </span>
    );
  }
  if (finding.domain) {
    return (
      <span className="inline-flex items-center gap-1 rounded bg-emerald-900/50 px-2 py-0.5 text-xs text-emerald-300 max-w-[160px] truncate">
        <Globe className="h-3 w-3 shrink-0" />
        <span className="truncate">{finding.domain.domain}</span>
      </span>
    );
  }
  return <span className="text-gray-600">—</span>;
}

const SEVERITIES = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"];
const SCAN_TYPES = ["SAST", "SCA", "SECRET", "IAC", "CONTAINER", "DAST", "PENTEST", "PENTEST_FULL"];
const STATUSES = ["OPEN", "ACKNOWLEDGED", "FALSE_POSITIVE", "FIXED", "IGNORED"];
const CONFIDENCES = ["CONFIRMED", "LIKELY", "POSSIBLE"];

// Encode target filter as "repo:<id>", "container:<id>", or "domain:<id>"
function parseTarget(val: string) {
  if (!val) return {};
  const [type, id] = val.split(":");
  if (type === "repo") return { repoId: id };
  if (type === "container") return { containerId: id };
  if (type === "domain") return { domainId: id };
  return {};
}

// SEV_COLOR alias — uses canonical SEVERITY_BADGE from colors.ts
const SEV_COLOR = SEVERITY_BADGE;

// ── Finding Groups View (Phase 6) ─────────────────────────────────────────────

function FindingGroupCard({ group }: { group: FindingGroup }) {
  const [expanded, setExpanded] = useState(false);
  const [localInsight, setLocalInsight] = useState<string | null>(group.aiInsight ?? null);

  const insightMutation = useMutation({
    mutationFn: () => findingsApi.groupInsight(group.key),
    onSuccess: (data) => setLocalInsight(data.insight),
  });

  const insight = localInsight;
  const isGenerating = insightMutation.isPending;

  return (
    <div className="rounded-xl border border-gray-800 bg-gray-900 overflow-hidden">
      {/* Header row */}
      <button
        className="flex w-full items-center gap-3 px-5 py-4 text-left hover:bg-gray-800/40 transition-colors"
        onClick={() => setExpanded((e) => !e)}
      >
        <div className="flex-1 min-w-0">
          <div className="flex items-center gap-2 flex-wrap">
            <span className="text-sm font-semibold text-white truncate max-w-[400px]">{group.label}</span>
            <span className="rounded bg-gray-800 px-1.5 py-0.5 text-[10px] text-gray-400">{group.scanType}</span>
            <span className="rounded bg-indigo-950 border border-indigo-800 px-2 py-0.5 text-xs font-bold text-indigo-300">
              {group.count} findings
            </span>
          </div>
          <div className="mt-1.5 flex items-center gap-1.5 flex-wrap">
            {group.criticalCount > 0 && (
              <span className={`rounded px-1.5 py-0.5 text-xs font-semibold ${SEV_COLOR.CRITICAL}`}>{group.criticalCount} critical</span>
            )}
            {group.highCount > 0 && (
              <span className={`rounded px-1.5 py-0.5 text-xs font-semibold ${SEV_COLOR.HIGH}`}>{group.highCount} high</span>
            )}
            {group.mediumCount > 0 && (
              <span className={`rounded px-1.5 py-0.5 text-xs font-semibold ${SEV_COLOR.MEDIUM}`}>{group.mediumCount} medium</span>
            )}
            {group.lowCount > 0 && (
              <span className={`rounded px-1.5 py-0.5 text-xs font-semibold ${SEV_COLOR.LOW}`}>{group.lowCount} low</span>
            )}
            <span className="text-xs text-gray-500">
              across {group.affectedTargets.length} target{group.affectedTargets.length !== 1 ? "s" : ""}:
              {" "}{group.affectedTargets.slice(0, 3).join(", ")}
              {group.affectedTargets.length > 3 ? ` +${group.affectedTargets.length - 3} more` : ""}
            </span>
          </div>
        </div>
        {expanded ? (
          <ChevronDown className="h-4 w-4 text-gray-500 flex-shrink-0" />
        ) : (
          <ChevronRight className="h-4 w-4 text-gray-500 flex-shrink-0" />
        )}
      </button>

      {/* Expanded detail */}
      {expanded && (
        <div className="border-t border-gray-800 px-5 pb-4 pt-3 space-y-3">
          {/* Sample findings */}
          <div className="space-y-1.5">
            <p className="text-xs font-medium text-gray-500 uppercase tracking-wider">Sample findings</p>
            {group.sampleFindings.map((f) => (
              <div key={f.id} className="flex items-center gap-2 text-xs text-gray-300">
                <span className={`rounded px-1.5 py-0.5 text-[10px] font-bold flex-shrink-0 ${SEV_COLOR[f.severity] ?? "bg-gray-800 text-gray-400"}`}>
                  {f.severity}
                </span>
                <span className="truncate">{f.title}</span>
                <span className="text-gray-600 flex-shrink-0">— {f.targetName}</span>
              </div>
            ))}
          </div>

          {/* AI Insight */}
          {insight ? (
            <div className="rounded-lg border border-indigo-900/40 bg-indigo-950/20 px-4 py-3">
              <div className="flex items-center gap-1.5 mb-1.5">
                <Sparkles className="h-3.5 w-3.5 text-indigo-400" />
                <span className="text-xs font-semibold text-indigo-300">AI Root Cause Analysis</span>
              </div>
              <p className="text-xs leading-relaxed text-gray-300">{insight}</p>
            </div>
          ) : (
            <button
              onClick={(e) => { e.stopPropagation(); insightMutation.mutate(); }}
              disabled={isGenerating}
              className="flex items-center gap-2 rounded-lg border border-dashed border-indigo-800/50 bg-indigo-950/10 px-4 py-2.5 text-xs text-indigo-400 hover:border-indigo-700 hover:text-indigo-300 disabled:opacity-60 transition-colors w-full justify-center"
            >
              <Sparkles className={`h-3.5 w-3.5 ${isGenerating ? "animate-pulse" : ""}`} />
              {isGenerating ? "Analysing root cause…" : "Explain root cause with AI"}
            </button>
          )}
        </div>
      )}
    </div>
  );
}

function FindingGroupsView() {
  const { data: groups, isLoading } = useQuery({
    queryKey: ["finding-groups"],
    queryFn:  findingsApi.groups,
    staleTime: 60_000,
  });

  if (isLoading) {
    return (
      <div className="flex h-48 items-center justify-center text-gray-500">
        <Sparkles className="mr-2 h-4 w-4 animate-pulse" /> Analysing patterns…
      </div>
    );
  }

  if (!groups?.length) {
    return (
      <div className="flex h-48 flex-col items-center justify-center gap-3 text-gray-500">
        <Layers className="h-8 w-8" />
        <p>No repeated patterns found yet — run more scans to see grouped insights.</p>
      </div>
    );
  }

  return (
    <div className="space-y-3">
      <p className="text-xs text-gray-500">
        {groups.length} pattern{groups.length !== 1 ? "s" : ""} detected across open findings.
        Groups with a shared root cause are surfaced here for faster remediation.
      </p>
      {groups.map((g) => (
        <FindingGroupCard key={g.key} group={g} />
      ))}
    </div>
  );
}

// ── Main page ─────────────────────────────────────────────────────────────────

export default function FindingsPage() {
  // All filter state lives in the URL so links from other pages work and
  // browser back/forward preserves the filter context.
  const [searchParams, setSearchParams] = useSearchParams();

  const tab        = (searchParams.get("tab") as "list" | "groups") ?? "list";
  const severity   = searchParams.get("severity")   ?? "";
  const scanType   = searchParams.get("scanType")   ?? "";
  const status     = searchParams.get("status")     ?? "";
  const confidence = searchParams.get("confidence") ?? "";
  const search     = searchParams.get("search")     ?? "";
  const target     = searchParams.get("target")     ?? "";
  const page       = parseInt(searchParams.get("page") ?? "1", 10);

  const setFilter = (key: string, value: string) => {
    setSearchParams((prev) => {
      if (value) prev.set(key, value); else prev.delete(key);
      if (key !== "page") prev.delete("page");   // reset to page 1 on filter change
      return prev;
    });
  };

  const setTab = (t: "list" | "groups") => setFilter("tab", t === "list" ? "" : t);
  const setPage = (p: number) => setFilter("page", p > 1 ? String(p) : "");

  // URL-driven finding selection — ?id=<findingId> makes the link shareable
  const selectedId = searchParams.get("id");

  const { data: selectedFinding = null } = useQuery({
    queryKey: ["finding", selectedId],
    queryFn:  () => findingsApi.get(selectedId!),
    enabled:  !!selectedId,
    staleTime: 0,
  });

  const openFinding = (f: Finding) => {
    setSearchParams((prev) => { prev.set("id", f.id); return prev; });
  };

  const closeFinding = () => {
    setSearchParams((prev) => { prev.delete("id"); return prev; });
  };

  const { data: repos } = useQuery({ queryKey: ["repos"], queryFn: reposApi.list });
  const { data: containers } = useQuery({ queryKey: ["containers"], queryFn: containersApi.list });
  const { data: domains } = useQuery({ queryKey: ["domains"], queryFn: domainsApi.list });

  const targetFilter = parseTarget(target);

  // Check whether any filters are active (to distinguish "no results" from "nothing scanned yet")
  const hasActiveFilters = !!(severity || scanType || status || confidence || search || target);

  const { data, isLoading } = useQuery({
    queryKey: ["findings", { severity, scanType, status, confidence, search, target, page }],
    queryFn: () =>
      findingsApi.list({
        severity: severity || undefined,
        scanType: (scanType || undefined) as never,
        status: (status || undefined) as never,
        confidence: (confidence || undefined) as never,
        search: search || undefined,
        ...targetFilter,
        page,
        limit: 25,
      }),
  });

  return (
    <div className="flex h-full flex-col p-6">
      <div className="mb-5 flex items-center justify-between">
        <h1 className="text-3xl font-bold text-white">Findings</h1>
        {/* Tab switcher */}
        <div className="flex rounded-lg border border-gray-800 bg-gray-900 p-1 gap-1">
          <button
            onClick={() => setTab("list")}
            className={`flex items-center gap-1.5 rounded-md px-3 py-1.5 text-xs font-medium transition-colors ${
              tab === "list"
                ? "bg-indigo-600 text-white"
                : "text-gray-400 hover:text-white"
            }`}
          >
            <ShieldAlert className="h-3.5 w-3.5" />
            All Findings
          </button>
          <button
            onClick={() => setTab("groups")}
            className={`flex items-center gap-1.5 rounded-md px-3 py-1.5 text-xs font-medium transition-colors ${
              tab === "groups"
                ? "bg-indigo-600 text-white"
                : "text-gray-400 hover:text-white"
            }`}
          >
            <Layers className="h-3.5 w-3.5" />
            Smart Groups
            <span className="rounded-full bg-indigo-500/20 px-1.5 py-0.5 text-[10px] text-indigo-300">AI</span>
          </button>
        </div>
      </div>

      {/* Groups view */}
      {tab === "groups" && <FindingGroupsView />}

      {/* List view */}
      {tab === "list" && <>
      <div className="mb-4 flex flex-wrap items-center gap-3">
        <div className="relative">
          <Search className="absolute left-2.5 top-1/2 h-3.5 w-3.5 -translate-y-1/2 text-gray-500" />
          <input
            className="rounded bg-gray-800 pl-8 pr-3 py-1.5 text-sm text-gray-200 placeholder-gray-500 focus:outline-none focus:ring-1 focus:ring-indigo-500 w-48"
            placeholder="Search findings…"
            value={search}
            onChange={(e) => setFilter("search", e.target.value)}
          />
        </div>

        {/* Target filter */}
        <select
          value={target}
          onChange={(e) => setFilter("target", e.target.value)}
          className="rounded bg-gray-800 px-3 py-1.5 text-sm text-gray-300 focus:outline-none focus:ring-1 focus:ring-indigo-500"
        >
          <option value="">All targets</option>
          {repos && repos.length > 0 && (
            <optgroup label="Repositories">
              {repos.map((r) => (
                <option key={r.id} value={`repo:${r.id}`}>{r.fullName}</option>
              ))}
            </optgroup>
          )}
          {containers && containers.length > 0 && (
            <optgroup label="Containers">
              {containers.map((c) => (
                <option key={c.id} value={`container:${c.id}`}>{c.imageRef}</option>
              ))}
            </optgroup>
          )}
          {domains && domains.length > 0 && (
            <optgroup label="Domains">
              {domains.map((d) => (
                <option key={d.id} value={`domain:${d.id}`}>{d.domain}</option>
              ))}
            </optgroup>
          )}
        </select>

        <select value={severity} onChange={(e) => setFilter("severity", e.target.value)}
          className="rounded bg-gray-800 px-3 py-1.5 text-sm text-gray-300 focus:outline-none focus:ring-1 focus:ring-indigo-500">
          <option value="">All severities</option>
          {SEVERITIES.map((s) => <option key={s}>{s}</option>)}
        </select>

        <select value={scanType} onChange={(e) => setFilter("scanType", e.target.value)}
          className="rounded bg-gray-800 px-3 py-1.5 text-sm text-gray-300 focus:outline-none focus:ring-1 focus:ring-indigo-500">
          <option value="">All types</option>
          {SCAN_TYPES.map((t) => <option key={t}>{t}</option>)}
        </select>

        <select value={status} onChange={(e) => setFilter("status", e.target.value)}
          className="rounded bg-gray-800 px-3 py-1.5 text-sm text-gray-300 focus:outline-none focus:ring-1 focus:ring-indigo-500">
          <option value="">All statuses</option>
          {STATUSES.map((s) => <option key={s}>{s}</option>)}
        </select>

        <select value={confidence} onChange={(e) => setFilter("confidence", e.target.value)}
          className="rounded bg-gray-800 px-3 py-1.5 text-sm text-gray-300 focus:outline-none focus:ring-1 focus:ring-indigo-500">
          <option value="">All confidence</option>
          {CONFIDENCES.map((c) => <option key={c}>{c}</option>)}
        </select>

        {/* Clear all filters */}
        {hasActiveFilters && (
          <button
            onClick={() => setSearchParams((prev) => {
              const id = prev.get("id");
              const next = new URLSearchParams();
              if (id) next.set("id", id);
              return next;
            })}
            className="flex items-center gap-1 rounded bg-gray-800 px-2.5 py-1.5 text-xs text-gray-400 hover:text-gray-200 hover:bg-gray-700"
          >
            <X className="h-3 w-3" /> Clear filters
          </button>
        )}

        {data && (
          <span className="ml-auto text-xs text-gray-500">{data.total.toLocaleString()} finding{data.total !== 1 ? "s" : ""}</span>
        )}
      </div>

      {/* Table */}
      <div className="flex-1 overflow-auto rounded-lg border border-gray-800">
        <table className="w-full text-sm">
          <thead className="sticky top-0 border-b border-gray-800 bg-gray-900">
            <tr className="text-left text-xs text-gray-500">
              <th className="px-4 py-3 font-medium">Severity</th>
              <th className="px-4 py-3 font-medium">Title</th>
              <th className="px-4 py-3 font-medium">Target</th>
              <th className="px-4 py-3 font-medium">Type</th>
              <th className="px-4 py-3 font-medium">Confidence</th>
              <th className="px-4 py-3 font-medium">AI</th>
              <th className="px-4 py-3 font-medium">Status</th>
              <th className="px-4 py-3 font-medium">First Seen</th>
            </tr>
          </thead>
          <tbody className="divide-y divide-gray-800 bg-gray-900/50">
            {isLoading ? (
              <tr><td colSpan={7} className="py-12 text-center text-gray-500">Loading…</td></tr>
            ) : data?.data.length === 0 ? (
              <tr>
                <td colSpan={8} className="py-12 text-center">
                  <ShieldAlert className="mx-auto mb-2 h-8 w-8 text-gray-700" />
                  {hasActiveFilters ? (
                    <>
                      <p className="text-gray-500">No findings match your filters.</p>
                      <button
                        onClick={() => setSearchParams((prev) => {
                          const id = prev.get("id");
                          const next = new URLSearchParams();
                          if (id) next.set("id", id);
                          return next;
                        })}
                        className="mt-2 text-xs text-indigo-400 hover:text-indigo-300 underline underline-offset-2"
                      >
                        Clear filters
                      </button>
                    </>
                  ) : (
                    <p className="text-gray-500">No findings yet — run a scan to get started.</p>
                  )}
                </td>
              </tr>
            ) : (
              data?.data.map((f) => (
                <tr key={f.id} className={`cursor-pointer hover:bg-gray-800/40 ${selectedId === f.id ? "bg-indigo-950/20" : ""}`} onClick={() => openFinding(f)}>
                  <td className="px-4 py-3"><SeverityBadge severity={f.severity} /></td>
                  <td className="px-4 py-3 max-w-sm">
                    <div className="flex items-center gap-2 min-w-0">
                      <p className="truncate font-medium text-gray-200">{f.title}</p>
                      {(() => {
                        const raw = f.rawOutput as Record<string, unknown> | null;
                        if (!raw || raw["merged"] !== true) return null;
                        const occs = raw["occurrences"] as unknown[] | undefined;
                        const cves = raw["cves"] as unknown[] | undefined;
                        const locs = raw["locations"] as unknown[] | undefined;
                        const ress = raw["resources"] as unknown[] | undefined;
                        if (ress?.length) return (
                          <span className="shrink-0 inline-flex items-center gap-1 rounded-full bg-violet-900/40 px-1.5 py-0.5 text-[10px] text-violet-400">
                            <Layers className="h-2.5 w-2.5" />{ress.length} resource{ress.length !== 1 ? "s" : ""}
                          </span>
                        );
                        if (occs?.length) {
                          if (f.scanType === "SECRET") return (
                            <span className="shrink-0 inline-flex items-center gap-1 rounded-full bg-amber-900/40 px-1.5 py-0.5 text-[10px] text-amber-400">
                              <KeyRound className="h-2.5 w-2.5" />{occs.length} file{occs.length !== 1 ? "s" : ""}
                            </span>
                          );
                          return (
                            <span className="shrink-0 inline-flex items-center gap-1 rounded-full bg-emerald-900/40 px-1.5 py-0.5 text-[10px] text-emerald-400">
                              <Globe className="h-2.5 w-2.5" />{occs.length} URL{occs.length !== 1 ? "s" : ""}
                            </span>
                          );
                        }
                        if (cves?.length) return (
                          <span className="shrink-0 inline-flex items-center gap-1 rounded-full bg-gray-800 px-1.5 py-0.5 text-[10px] text-gray-400">
                            <Layers className="h-2.5 w-2.5" />{cves.length} CVE{cves.length !== 1 ? "s" : ""}
                          </span>
                        );
                        if (locs?.length) return (
                          <span className="shrink-0 inline-flex items-center gap-1 rounded-full bg-gray-800 px-1.5 py-0.5 text-[10px] text-gray-400">
                            <Layers className="h-2.5 w-2.5" />{locs.length} loc{locs.length !== 1 ? "s" : ""}
                          </span>
                        );
                        return null;
                      })()}
                    </div>
                    {f.cveId && <p className="text-xs text-gray-500">{f.cveId}</p>}
                  </td>
                  <td className="px-4 py-3"><TargetTag finding={f} /></td>
                  <td className="px-4 py-3 text-xs text-gray-400">{f.scanType}</td>
                  <td className="px-4 py-3">
                    <ConfidenceBadge confidence={f.confidence} />
                  </td>
                  {/* AI triage status: both done / analysis only / fix only / pending */}
                  <td className="px-4 py-3">
                    {(() => {
                      const hasAnalysis = !!(f as Record<string, unknown>)["aiAnalysedAt"];
                      const hasFix      = !!(f as Record<string, unknown>)["aiFixSuggestedAt"];
                      if (hasAnalysis && hasFix) return (
                        <span title="AI analysis + fix suggestion ready" className="inline-flex items-center gap-1 rounded-full bg-emerald-900/40 px-1.5 py-0.5 text-[10px] font-semibold text-emerald-400 border border-emerald-800/50">
                          <Sparkles className="h-2.5 w-2.5" /> Triaged
                        </span>
                      );
                      if (hasAnalysis) return (
                        <span title="AI analysis ready" className="inline-flex items-center gap-1 rounded-full bg-blue-900/40 px-1.5 py-0.5 text-[10px] font-semibold text-blue-400 border border-blue-800/50">
                          <Bot className="h-2.5 w-2.5" /> Analysed
                        </span>
                      );
                      if (hasFix) return (
                        <span title="Fix suggestion ready" className="inline-flex items-center gap-1 rounded-full bg-violet-900/40 px-1.5 py-0.5 text-[10px] font-semibold text-violet-400 border border-violet-800/50">
                          <Wrench className="h-2.5 w-2.5" /> Fix ready
                        </span>
                      );
                      return <span className="text-[10px] text-gray-700">—</span>;
                    })()}
                  </td>
                  <td className="px-4 py-3">
                    <FindingStatusBadge status={f.status} />
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
          <button onClick={() => setPage(Math.max(1, page - 1))} disabled={page === 1}
            className="rounded bg-gray-800 px-3 py-1.5 text-xs text-gray-300 hover:bg-gray-700 disabled:opacity-40">
            Previous
          </button>
          <span className="text-xs text-gray-500">Page {page} of {data.totalPages}</span>
          <button onClick={() => setPage(Math.min(data.totalPages, page + 1))} disabled={page === data.totalPages}
            className="rounded bg-gray-800 px-3 py-1.5 text-xs text-gray-300 hover:bg-gray-700 disabled:opacity-40">
            Next
          </button>
        </div>
      )}

      </>}

      <FindingDetailDrawer key={selectedFinding?.id} finding={selectedFinding} onClose={closeFinding} />
    </div>
  );
}
