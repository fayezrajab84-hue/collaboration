import { useState, useEffect } from "react";
import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import { useSearchParams } from "react-router-dom";
import { ShieldAlert, Search, Globe, Layers, Sparkles, ChevronDown, ChevronRight, ChevronsUpDown, ArrowUp, ArrowDown, KeyRound, Bot, Wrench, X, EyeOff, Eye, Download, CheckSquare, CheckCircle2, ShieldOff, RotateCcw, Ticket as TicketIcon, Code2, ExternalLink } from "lucide-react";
import { findingsApi, reposApi, containersApi, domainsApi, suppressionsApi } from "../lib/api";
import type { Finding, FindingGroup } from "@devsecops/types";
import Can from "../components/Can";
import SeverityBadge from "../components/SeverityBadge";
import ConfidenceBadge from "../components/ConfidenceBadge";
import ProofOfExploitBadge from "../components/ProofOfExploitBadge";
import FindingStatusBadge from "../components/FindingStatusBadge";
import FindingDetailDrawer from "../components/FindingDetailDrawer";
import TargetTag from "../components/TargetTag";
import MultiSelect from "../components/MultiSelect";
import { formatRelative } from "../lib/utils";
import { hasProofOfExploit } from "../lib/findings";
import { SEVERITY_BADGE } from "../lib/colors";
import { useDebouncedValue } from "../hooks/useDebouncedValue";

type SortField = "severity" | "firstSeen" | "lastSeen" | "title" | "scanType" | "status" | "confidence";
type SortOrder = "asc" | "desc";
const PAGE_SIZES = [25, 50, 100] as const;

const SEVERITIES = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"];
// ── Code vs Web split ────────────────────────────────────────────────────────
// Code findings have a file path + line number (the artefact is source).
// Web findings have a URL + HTTP exchange (the artefact is a request/response).
// CONTAINER lives in Code despite using image refs — its findings reference
// packages/CVEs, not URLs, so the user-facing shape matches SCA.
const CODE_SCAN_TYPE_OPTIONS: Array<{ value: string; label: string }> = [
  { value: "SAST",      label: "SAST" },
  { value: "SCA",       label: "SCA" },
  { value: "SECRET",    label: "Secrets" },
  { value: "IAC",       label: "IaC" },
  { value: "CONTAINER", label: "Container" },
];
const WEB_SCAN_TYPE_OPTIONS: Array<{ value: string; label: string }> = [
  { value: "DAST",         label: "DAST" },
  { value: "PENTEST_FULL", label: "Pentest" },
];
const CODE_SCAN_TYPES = CODE_SCAN_TYPE_OPTIONS.map((o) => o.value);
const WEB_SCAN_TYPES  = WEB_SCAN_TYPE_OPTIONS.map((o) => o.value);
const STATUSES = ["OPEN", "ACKNOWLEDGED", "FALSE_POSITIVE", "FIXED", "IGNORED"];
const CONFIDENCES = ["CONFIRMED", "LIKELY", "POSSIBLE"];
// AI triage filter values — matched server-side against aiAnalysedAt/aiFixSuggestedAt
const AI_FILTERS: Array<{ value: string; label: string }> = [
  { value: "triaged",   label: "AI: Triaged (analysis + fix)" },
  { value: "analysed",  label: "AI: Analysed" },
  { value: "fix_ready", label: "AI: Fix ready" },
  { value: "untriaged", label: "AI: Untriaged" },
];

// Encode each target filter value as "repo:<id>" / "container:<id>" / "domain:<id>".
// Multi-select: the URL holds comma-separated values; split into per-type arrays
// so the server can apply OR across target types.
function parseTargets(val: string) {
  if (!val) return {};
  const repoIds: string[] = [];
  const containerIds: string[] = [];
  const domainIds: string[] = [];
  for (const raw of val.split(",")) {
    const token = raw.trim();
    if (!token) continue;
    const [type, id] = token.split(":");
    if (!id) continue;
    if (type === "repo")      repoIds.push(id);
    else if (type === "container") containerIds.push(id);
    else if (type === "domain")    domainIds.push(id);
  }
  const out: Record<string, string> = {};
  if (repoIds.length)      out["repoId"]      = repoIds.join(",");
  if (containerIds.length) out["containerId"] = containerIds.join(",");
  if (domainIds.length)    out["domainId"]    = domainIds.join(",");
  return out;
}

// SEV_COLOR alias — uses canonical SEVERITY_BADGE from colors.ts
const SEV_COLOR = SEVERITY_BADGE;

// ── Sortable column header ────────────────────────────────────────────────────
function SortTh({
  field, label, sort, sortOrder, toggle,
}: {
  field: SortField;
  label: string;
  sort: SortField | null;
  sortOrder: SortOrder | null;
  toggle: (f: SortField) => void;
}) {
  const active = sort === field;
  return (
    <th className="px-4 py-3 font-medium">
      <button
        onClick={() => toggle(field)}
        className={`group inline-flex items-center gap-1 rounded px-0.5 py-0.5 text-xs font-medium transition-colors ${
          active ? "text-indigo-300" : "text-gray-500 hover:text-gray-300"
        }`}
      >
        <span>{label}</span>
        {active
          ? (sortOrder === "asc"
              ? <ArrowUp className="h-3 w-3" />
              : <ArrowDown className="h-3 w-3" />)
          : <ChevronsUpDown className="h-3 w-3 opacity-40 group-hover:opacity-80" />
        }
      </button>
    </th>
  );
}

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
            {/* Neutral chips with a single coloured dot — less noisy than 4 full-colour pills */}
            {([
              ["CRITICAL", group.criticalCount, "critical", "bg-red-400"],
              ["HIGH",     group.highCount,     "high",     "bg-orange-400"],
              ["MEDIUM",   group.mediumCount,   "medium",   "bg-amber-400"],
              ["LOW",      group.lowCount,      "low",      "bg-sky-400"],
            ] as const).filter(([, c]) => c > 0).map(([sev, c, label, dot]) => (
              <span key={sev} className="inline-flex items-center gap-1.5 rounded px-1.5 py-0.5 text-xs font-medium text-gray-300 bg-gray-800/70">
                <span className={`h-1.5 w-1.5 rounded-full ${dot}`} />
                <span className="tabular-nums">{c}</span>
                <span className="text-gray-500">{label}</span>
              </span>
            ))}
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

  // Tab state — replaces the old "list | groups" toggle. The list view is now
  // split into Code (file-based scanners) and Web (URL-based scanners) so the
  // URL column only appears where it makes sense and dropdown options aren't
  // mixed across two very different finding shapes. Default to "code" since
  // most users add a repo first and code findings dominate volume.
  const tab        = (searchParams.get("tab") as "code" | "web" | "groups") ?? "code";
  // Multi-select filters stored as comma-separated values in the URL so links
  // remain shareable; the server splits and parses them via `multi()`.
  const parseMulti = (v: string) => v.split(",").map((s) => s.trim()).filter(Boolean);
  const severity   = parseMulti(searchParams.get("severity")   ?? "");
  const scanType   = parseMulti(searchParams.get("scanType")   ?? "");
  const status     = parseMulti(searchParams.get("status")     ?? "");
  const confidence = parseMulti(searchParams.get("confidence") ?? "");
  const aiFilter   = parseMulti(searchParams.get("ai") ?? "");
  const aiFilterKey = aiFilter.join(",");
  // Stable primitives for dep arrays — arrays produced above are new every render.
  // (Note: no scanTypeKey — the API call uses `effectiveScanTypeKey` which folds
  // the tab's allowed set in, and that's what the cache key tracks.)
  const severityKey   = severity.join(",");
  const statusKey     = status.join(",");
  const confidenceKey = confidence.join(",");

  // Effective scanType filter sent to the API: intersection of the tab's
  // allowed set with whatever the user picked in the dropdown. If the user
  // picked nothing, fall back to the full tab set so Code/Web tabs don't
  // accidentally show each other's findings.
  const tabScanTypes = tab === "web" ? WEB_SCAN_TYPES : CODE_SCAN_TYPES;
  const effectiveScanTypes = scanType.length
    ? scanType.filter((t) => tabScanTypes.includes(t))
    : tabScanTypes;
  const effectiveScanTypeKey = effectiveScanTypes.join(",");
  const urlSearch  = searchParams.get("search")     ?? "";
  const target     = searchParams.get("target")     ?? "";
  const includeSuppressed = searchParams.get("includeSuppressed") === "true";
  const page       = parseInt(searchParams.get("page") ?? "1", 10);
  const pageSize   = (() => {
    const parsed = parseInt(searchParams.get("pageSize") ?? "25", 10);
    return (PAGE_SIZES as readonly number[]).includes(parsed) ? parsed : 25;
  })();
  const sort       = (searchParams.get("sort") as SortField | null) ?? null;
  const sortOrder  = (searchParams.get("sortOrder") as SortOrder | null) ?? null;

  // Local-state search that updates the input instantly but debounces the URL
  // write — previously every keystroke forced a Prisma query + history push.
  const [searchDraft, setSearchDraft] = useState(urlSearch);
  const debouncedSearch = useDebouncedValue(searchDraft, 300);
  useEffect(() => { setSearchDraft(urlSearch); }, [urlSearch]);
  useEffect(() => {
    if (debouncedSearch === urlSearch) return;
    setSearchParams((prev) => {
      if (debouncedSearch) prev.set("search", debouncedSearch); else prev.delete("search");
      prev.delete("page");
      return prev;
    });
  }, [debouncedSearch]); // eslint-disable-line react-hooks/exhaustive-deps
  const search = urlSearch; // used for the Prisma filter via URL

  const setFilter = (key: string, value: string) => {
    setSearchParams((prev) => {
      if (value) prev.set(key, value); else prev.delete(key);
      if (key !== "page") prev.delete("page");   // reset to page 1 on filter change
      return prev;
    });
  };

  // Multi-select filter setter — joins with commas so all selections live in one URL key
  const setMultiFilter = (key: string, values: string[]) => {
    setFilter(key, values.join(","));
  };

  // Switching tabs also clears the scanType chip filter — selections from one
  // tab (e.g. "SAST" picked while in Code) wouldn't intersect with the other
  // tab's allowed set anyway, so leaving them stale would just be confusing.
  const setTab = (t: "code" | "web" | "groups") => {
    setSearchParams((prev) => {
      if (t === "code") prev.delete("tab"); else prev.set("tab", t);
      prev.delete("scanType");
      prev.delete("page");
      return prev;
    });
  };
  const setPage = (p: number) => setFilter("page", p > 1 ? String(p) : "");
  const setPageSize = (size: number) => setFilter("pageSize", size === 25 ? "" : String(size));

  // Sort: clicking the same column toggles asc→desc→clear; new column → desc
  const toggleSort = (field: SortField) => {
    setSearchParams((prev) => {
      const cur = prev.get("sort");
      const curOrder = prev.get("sortOrder");
      if (cur !== field) {
        prev.set("sort", field);
        prev.set("sortOrder", "desc");
      } else if (curOrder === "desc") {
        prev.set("sortOrder", "asc");
      } else {
        prev.delete("sort");
        prev.delete("sortOrder");
      }
      prev.delete("page");
      return prev;
    });
  };

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

  // Active suppressions — used to mark suppressed findings when "Show suppressed" is on
  const { data: activeSuppressions } = useQuery({
    queryKey: ["suppressions", "active"],
    queryFn:  () => suppressionsApi.list(true),
    staleTime: 30_000,
  });
  const suppressedFingerprints = new Set((activeSuppressions ?? []).map((s) => s.fingerprint));

  const targetFilter = parseTargets(target);

  // ── Bulk selection ──────────────────────────────────────────────────────
  // Page-local selection state (cleared on filter/page change to avoid stale IDs).
  const [selected, setSelected] = useState<Set<string>>(new Set());
  useEffect(() => { setSelected(new Set()); }, [severityKey, effectiveScanTypeKey, statusKey, confidenceKey, aiFilterKey, search, target, page, pageSize, includeSuppressed]);
  const queryClient = useQueryClient();

  const bulkMutation = useMutation({
    mutationFn: ({ ids, status: s }: { ids: string[]; status: "OPEN"|"ACKNOWLEDGED"|"FALSE_POSITIVE"|"FIXED"|"IGNORED" }) =>
      findingsApi.bulkUpdate(ids, s),
    onSuccess: () => {
      setSelected(new Set());
      queryClient.invalidateQueries({ queryKey: ["findings"] });
    },
  });
  const applyBulk = (s: "OPEN"|"ACKNOWLEDGED"|"FALSE_POSITIVE"|"FIXED"|"IGNORED") => {
    if (selected.size === 0) return;
    bulkMutation.mutate({ ids: Array.from(selected), status: s });
  };

  // Bulk-create tickets from current selection. Skips findings that already
  // have a ticket; shows a toast-like inline banner on completion.
  const [bulkTicketMsg, setBulkTicketMsg] = useState<string | null>(null);
  const bulkTicketMutation = useMutation({
    mutationFn: (ids: string[]) => findingsApi.bulkCreateTickets(ids),
    onSuccess: (res) => {
      setSelected(new Set());
      setBulkTicketMsg(
        `Created ${res.created} ticket${res.created !== 1 ? "s" : ""}${
          res.skipped > 0 ? ` — skipped ${res.skipped} (already ticketed or not found)` : ""
        }`,
      );
      queryClient.invalidateQueries({ queryKey: ["findings"] });
      queryClient.invalidateQueries({ queryKey: ["tickets"] });
      setTimeout(() => setBulkTicketMsg(null), 5000);
    },
  });
  const createTicketsForSelected = () => {
    if (selected.size === 0) return;
    bulkTicketMutation.mutate(Array.from(selected));
  };
  const toggleRow = (id: string) => {
    setSelected((prev) => {
      const next = new Set(prev);
      if (next.has(id)) next.delete(id); else next.add(id);
      return next;
    });
  };

  // Check whether any filters are active (to distinguish "no results" from "nothing scanned yet")
  const hasActiveFilters = !!(
    severity.length || scanType.length || status.length || confidence.length ||
    aiFilter.length || search || target
  );

  const { data, isLoading } = useQuery({
    // Use effectiveScanTypeKey (tab ∩ user) so the cache invalidates correctly
    // when switching Code↔Web — same user-selected types but different tab
    // produces a different effective set, hence a different query.
    queryKey: ["findings", { severityKey, effectiveScanTypeKey, statusKey, confidenceKey, aiFilterKey, search, target, page, pageSize, sort, sortOrder, includeSuppressed }],
    queryFn: () =>
      findingsApi.list({
        // Multi-select: send comma-joined values — server splits via `multi()`.
        severity: severityKey || undefined,
        scanType: (effectiveScanTypeKey || undefined) as never,
        status: (statusKey || undefined) as never,
        confidence: (confidenceKey || undefined) as never,
        search: search || undefined,
        ...targetFilter,
        page,
        limit: pageSize,
        ...(aiFilterKey ? { ai: aiFilterKey as never } : {}),
        ...(sort ? { sort: sort as never, sortOrder: (sortOrder ?? "desc") as never } : {}),
        ...(includeSuppressed ? { includeSuppressed: "true" as never } : {}),
      } as never),
  });

  return (
    <div className="flex h-full flex-col p-6">
      <div className="mb-5 flex items-center justify-between">
        <h1 className="text-3xl font-bold text-white">Findings</h1>
        {/* Tab switcher — Code (file-based) vs Web (URL-based) split, plus the
            existing Smart Groups view. Switching Code↔Web wipes the scanType
            chip filter so we don't carry over an option that's invalid in the
            other tab. */}
        <div className="flex rounded-lg border border-gray-800 bg-gray-900 p-1 gap-1">
          <button
            onClick={() => setTab("code")}
            className={`flex items-center gap-1.5 rounded-md px-3 py-1.5 text-xs font-medium transition-colors ${
              tab === "code"
                ? "bg-indigo-700 text-white"
                : "text-gray-400 hover:text-white"
            }`}
            title="SAST, SCA, Secrets, IaC, Container — file/path based"
          >
            <Code2 className="h-3.5 w-3.5" />
            Code
          </button>
          <button
            onClick={() => setTab("web")}
            className={`flex items-center gap-1.5 rounded-md px-3 py-1.5 text-xs font-medium transition-colors ${
              tab === "web"
                ? "bg-indigo-700 text-white"
                : "text-gray-400 hover:text-white"
            }`}
            title="DAST, Pentest — URL based"
          >
            <Globe className="h-3.5 w-3.5 text-gray-300" />
            Web
          </button>
          <button
            onClick={() => setTab("groups")}
            className={`flex items-center gap-1.5 rounded-md px-3 py-1.5 text-xs font-medium transition-colors ${
              tab === "groups"
                ? "bg-indigo-700 text-white"
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

      {/* List view (shared by Code and Web tabs — they only differ in scope
          and the URL column rendered below) */}
      {tab !== "groups" && <>
      <div className="mb-4 flex flex-wrap items-center gap-3">
        <div className="relative">
          <Search className="absolute left-2.5 top-1/2 h-3.5 w-3.5 -translate-y-1/2 text-gray-500" />
          <input
            className="rounded bg-gray-800 pl-8 pr-3 py-1.5 text-sm text-gray-200 placeholder-gray-500 focus:outline-none focus:ring-1 focus:ring-indigo-500 w-48"
            placeholder="Search findings…"
            value={searchDraft}
            onChange={(e) => setSearchDraft(e.target.value)}
          />
        </div>

        {/* Target filter — multi-select across repos, containers and domains.
            Labels prefixed so mixed-type selection is legible in the chip. */}
        <MultiSelect
          label="Targets"
          options={[
            ...(repos       ?? []).map((r) => ({ value: `repo:${r.id}`,      label: `Repo · ${r.fullName}` })),
            ...(containers  ?? []).map((c) => ({ value: `container:${c.id}`, label: `Container · ${c.imageRef}` })),
            ...(domains     ?? []).map((d) => ({ value: `domain:${d.id}`,    label: `Domain · ${d.domain}` })),
          ]}
          value={parseMulti(target)}
          onChange={(v) => setMultiFilter("target", v)}
        />

        <MultiSelect
          label="Severities"
          options={SEVERITIES.map((s) => ({ value: s, label: s }))}
          value={severity}
          onChange={(v) => setMultiFilter("severity", v)}
        />

        <MultiSelect
          label="Types"
          // Tab-scoped — Code tab shows file-based scanners, Web tab shows
          // URL-based scanners. Mixing them was confusing and made the dropdown
          // longer than necessary.
          options={tab === "web" ? WEB_SCAN_TYPE_OPTIONS : CODE_SCAN_TYPE_OPTIONS}
          value={scanType}
          onChange={(v) => setMultiFilter("scanType", v)}
        />

        <MultiSelect
          label="Statuses"
          options={STATUSES.map((s) => ({ value: s, label: s }))}
          value={status}
          onChange={(v) => setMultiFilter("status", v)}
        />

        <MultiSelect
          label="Confidence"
          options={CONFIDENCES.map((c) => ({ value: c, label: c }))}
          value={confidence}
          onChange={(v) => setMultiFilter("confidence", v)}
        />

        <MultiSelect
          label="AI triage"
          options={AI_FILTERS}
          value={aiFilter}
          onChange={(v) => setMultiFilter("ai", v)}
          title="Filter by AI triage state"
        />

        {/* Show suppressed toggle */}
        <label
          className={`flex items-center gap-1.5 rounded px-2.5 py-1.5 text-xs cursor-pointer transition-colors ${
            includeSuppressed
              ? "bg-amber-900/30 border border-amber-800/60 text-amber-300 hover:bg-amber-900/40"
              : "bg-gray-800 text-gray-300 hover:bg-gray-700"
          }`}
          title={
            suppressedFingerprints.size > 0
              ? `${suppressedFingerprints.size} active suppression${suppressedFingerprints.size !== 1 ? "s" : ""} — toggle to reveal accepted-risk findings`
              : "No active suppressions"
          }
        >
          <input
            type="checkbox"
            checked={includeSuppressed}
            onChange={(e) => setFilter("includeSuppressed", e.target.checked ? "true" : "")}
            className="h-3 w-3 accent-amber-500"
          />
          <EyeOff className="h-3 w-3" />
          Show suppressed
          {suppressedFingerprints.size > 0 && (
            <span className={`rounded-full px-1.5 py-0.5 text-[10px] font-bold ${
              includeSuppressed ? "bg-amber-800 text-amber-100" : "bg-gray-700 text-gray-400"
            }`}>
              {suppressedFingerprints.size}
            </span>
          )}
        </label>

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

        {/* Export CSV — respects all current filters, including the active
            tab's scope (so a Code-tab export never includes web findings). */}
        <a
          href={findingsApi.exportCsvUrl({
            severity: severityKey || undefined,
            scanType: (effectiveScanTypeKey || undefined) as never,
            status:   (statusKey   || undefined) as never,
            confidence: (confidenceKey || undefined) as never,
            search:   search   || undefined,
            ...targetFilter,
            ...(aiFilterKey ? { ai: aiFilterKey as never } : {}),
            ...(includeSuppressed ? { includeSuppressed: "true" as never } : {}),
          } as never)}
          className="flex items-center gap-1.5 rounded bg-gray-800 px-2.5 py-1.5 text-xs text-gray-300 hover:bg-gray-700 hover:text-white"
          title="Export current filter as CSV (max 10 000 rows)"
        >
          <Download className="h-3 w-3" /> Export CSV
        </a>

        {data && (
          <span className="ml-auto text-xs text-gray-500">{data.total.toLocaleString()} finding{data.total !== 1 ? "s" : ""}</span>
        )}
      </div>

      {/* Bulk action toolbar — appears only when rows are selected.
          Wrapped in <Can role="SECURITY"> because the underlying APIs
          (POST /api/findings/bulk + POST /api/findings/bulk-tickets)
          require SECURITY+. Without this gate VIEWER/DEVELOPER could
          select rows and see the toolbar buttons that 403 on click. */}
      <Can role="SECURITY">
      {selected.size > 0 && (
        <div className="mb-3 flex flex-wrap items-center gap-2 rounded-lg border border-indigo-800/60 bg-indigo-950/40 px-3 py-2">
          <CheckSquare className="h-4 w-4 text-indigo-400" />
          <span className="text-xs font-medium text-indigo-200">
            {selected.size} selected
          </span>
          <span className="text-xs text-gray-500">— mark as:</span>
          {/* Neutral-chip style — icons only (no colour), so the toolbar stays
              calm and doesn't compete with severity badges in the table below. */}
          {([
            ["ACKNOWLEDGED",   "Acknowledged",   Eye],
            ["FALSE_POSITIVE", "False Positive", ShieldOff],
            ["IGNORED",        "Ignored",        EyeOff],
            ["FIXED",          "Fixed",          CheckCircle2],
            ["OPEN",           "Re-open",        RotateCcw],
          ] as const).map(([value, label, Icon]) => (
            <button
              key={value}
              onClick={() => applyBulk(value)}
              disabled={bulkMutation.isPending}
              className="inline-flex items-center gap-1.5 rounded border border-gray-700/60 bg-gray-800/70 px-2.5 py-1 text-xs text-gray-200 hover:border-gray-600 hover:bg-gray-800 disabled:opacity-50"
            >
              <Icon className="h-3 w-3 text-gray-400" />
              {label}
            </button>
          ))}
          <span className="text-xs text-gray-600">|</span>
          <button
            onClick={createTicketsForSelected}
            disabled={bulkTicketMutation.isPending}
            className="inline-flex items-center gap-1.5 rounded border border-indigo-800/70 bg-indigo-900/40 px-2.5 py-1 text-xs text-indigo-200 hover:border-indigo-700 hover:bg-indigo-900/60 disabled:opacity-50"
            title="Create one internal ticket per selected finding (findings already ticketed are skipped)"
          >
            <TicketIcon className="h-3 w-3 text-gray-400" />
            {bulkTicketMutation.isPending ? "Creating…" : "Create Tickets"}
          </button>
          <button
            onClick={() => setSelected(new Set())}
            className="ml-auto flex items-center gap-1 rounded px-2 py-1 text-xs text-gray-400 hover:text-gray-200"
          >
            <X className="h-3 w-3" /> Clear
          </button>
        </div>
      )}
      </Can>

      {/* Bulk-ticket success banner */}
      {bulkTicketMsg && (
        <div className="mb-3 flex items-center gap-2 rounded-lg border border-emerald-800/60 bg-emerald-950/40 px-3 py-2 text-xs text-emerald-200">
          <TicketIcon className="h-3.5 w-3.5" />
          {bulkTicketMsg}
        </div>
      )}

      {/* Table */}
      <div className="flex-1 overflow-auto rounded-lg border border-gray-800">
        <table className="w-full text-sm">
          <thead className="sticky top-0 border-b border-gray-800 bg-gray-900">
            <tr className="text-left text-xs text-gray-500">
              <th className="w-10 px-3 py-3">
                <input
                  type="checkbox"
                  className="h-3.5 w-3.5 accent-indigo-500"
                  aria-label="Select all on page"
                  title="Select / deselect all rows on this page"
                  checked={!!(data?.data.length && data.data.every((f) => selected.has(f.id)))}
                  ref={(el) => {
                    if (el && data?.data.length) {
                      const some = data.data.some((f) => selected.has(f.id));
                      const all  = data.data.every((f) => selected.has(f.id));
                      el.indeterminate = some && !all;
                    }
                  }}
                  onChange={(e) => {
                    if (!data?.data) return;
                    setSelected((prev) => {
                      const next = new Set(prev);
                      if (e.target.checked) data.data.forEach((f) => next.add(f.id));
                      else data.data.forEach((f) => next.delete(f.id));
                      return next;
                    });
                  }}
                />
              </th>
              <SortTh field="severity"   label="Severity"   sort={sort} sortOrder={sortOrder} toggle={toggleSort} />
              <SortTh field="title"      label="Title"      sort={sort} sortOrder={sortOrder} toggle={toggleSort} />
              {/* URL column — only on Web tab. For DAST/PENTEST_FULL the URL
                  IS the location (no source file), so showing it as a top-level
                  column makes navigation/triage drastically faster than digging
                  into the drawer. */}
              {tab === "web" && <th className="px-4 py-3 font-medium">URL</th>}
              <th className="px-4 py-3 font-medium">Target</th>
              <SortTh field="scanType"   label="Type"       sort={sort} sortOrder={sortOrder} toggle={toggleSort} />
              <SortTh field="confidence" label="Confidence" sort={sort} sortOrder={sortOrder} toggle={toggleSort} />
              <th className="px-4 py-3 font-medium">AI</th>
              <SortTh field="status"     label="Status"     sort={sort} sortOrder={sortOrder} toggle={toggleSort} />
              <SortTh field="firstSeen"  label="First Seen" sort={sort} sortOrder={sortOrder} toggle={toggleSort} />
            </tr>
          </thead>
          <tbody className="divide-y divide-gray-800 bg-gray-900/50">
            {isLoading ? (
              <tr><td colSpan={tab === "web" ? 10 : 9} className="py-12 text-center text-gray-500">Loading…</td></tr>
            ) : data?.data.length === 0 ? (
              <tr>
                <td colSpan={tab === "web" ? 10 : 9} className="py-12 text-center">
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
              data?.data.map((f) => {
                const isSuppressed = suppressedFingerprints.has(f.fingerprint);
                return (
                <tr key={f.id} className={`cursor-pointer hover:bg-gray-800/40 ${selectedId === f.id ? "bg-indigo-950/20" : ""} ${selected.has(f.id) ? "bg-indigo-950/30" : ""} ${isSuppressed ? "opacity-60" : ""}`} onClick={() => openFinding(f)}>
                  <td className="w-10 px-3 py-3" onClick={(e) => e.stopPropagation()}>
                    <input
                      type="checkbox"
                      className="h-3.5 w-3.5 accent-indigo-500"
                      checked={selected.has(f.id)}
                      onChange={() => toggleRow(f.id)}
                      aria-label={`Select ${f.title}`}
                    />
                  </td>
                  <td className="px-4 py-3"><SeverityBadge severity={f.severity} /></td>
                  <td className="px-4 py-3 max-w-sm">
                    <div className="flex items-center gap-2 min-w-0">
                      <p className={`truncate font-medium ${isSuppressed ? "text-gray-400 line-through decoration-amber-600/50" : "text-gray-200"}`}>{f.title}</p>
                      {isSuppressed && (
                        <span className="shrink-0 inline-flex items-center gap-1 rounded-full border border-amber-800/60 bg-amber-900/30 px-1.5 py-0.5 text-[10px] font-semibold text-amber-300" title="Suppressed — accepted risk">
                          <EyeOff className="h-2.5 w-2.5" /> Suppressed
                        </span>
                      )}
                      {(() => {
                        // Unified "merged occurrences" chip — neutral gray body, colour
                        // lives only in the icon so multiple rows don't create visual noise.
                        const raw = f.rawOutput as Record<string, unknown> | null;
                        if (!raw || raw["merged"] !== true) return null;
                        const occs = raw["occurrences"] as unknown[] | undefined;
                        const cves = raw["cves"] as unknown[] | undefined;
                        const locs = raw["locations"] as unknown[] | undefined;
                        const ress = raw["resources"] as unknown[] | undefined;
                        const chip = "shrink-0 inline-flex items-center gap-1 rounded-full bg-gray-800/80 px-1.5 py-0.5 text-[10px] text-gray-400 border border-gray-700/50";
                        if (ress?.length) return (
                          <span className={chip}>
                            <Layers className="h-2.5 w-2.5 text-indigo-400/80" />{ress.length} resource{ress.length !== 1 ? "s" : ""}
                          </span>
                        );
                        if (occs?.length) {
                          if (f.scanType === "SECRET") return (
                            <span className={chip}>
                              <KeyRound className="h-2.5 w-2.5 text-amber-400/80" />{occs.length} file{occs.length !== 1 ? "s" : ""}
                            </span>
                          );
                          return (
                            <span className={chip}>
                              <Globe className="h-2.5 w-2.5 text-sky-400/80" />{occs.length} URL{occs.length !== 1 ? "s" : ""}
                            </span>
                          );
                        }
                        if (cves?.length) return (
                          <span className={chip}>
                            <Layers className="h-2.5 w-2.5" />{cves.length} CVE{cves.length !== 1 ? "s" : ""}
                          </span>
                        );
                        if (locs?.length) return (
                          <span className={chip}>
                            <Layers className="h-2.5 w-2.5" />{locs.length} loc{locs.length !== 1 ? "s" : ""}
                          </span>
                        );
                        return null;
                      })()}
                    </div>
                    {f.cveId && <p className="text-xs text-gray-500">{f.cveId}</p>}
                  </td>
                  {/* URL cell — Web tab only. filePath holds the attacked URL
                      for DAST/PENTEST_FULL findings (set by the scanner
                      service). Click opens it in a new tab without bubbling
                      up to the row's drawer-open handler. */}
                  {tab === "web" && (
                    <td className="px-4 py-3 max-w-[280px]">
                      {f.filePath ? (
                        <a
                          href={f.filePath}
                          target="_blank"
                          rel="noopener noreferrer"
                          onClick={(e) => e.stopPropagation()}
                          className="inline-flex items-center gap-1 truncate text-xs text-sky-400 hover:text-sky-300 hover:underline max-w-full"
                          title={f.filePath}
                        >
                          <span className="truncate">{f.filePath}</span>
                          <ExternalLink className="h-3 w-3 shrink-0 opacity-60" />
                        </a>
                      ) : (
                        <span className="text-xs text-gray-600">—</span>
                      )}
                    </td>
                  )}
                  <td className="px-4 py-3"><TargetTag finding={f} /></td>
                  <td className="px-4 py-3 text-xs text-gray-400">{f.scanType}</td>
                  <td className="px-4 py-3">
                    <span className="inline-flex items-center">
                      <ConfidenceBadge confidence={f.confidence} />
                      {hasProofOfExploit(f) && <ProofOfExploitBadge size="sm" />}
                    </span>
                  </td>
                  {/* AI triage status — unified neutral chip; colour only in the icon */}
                  <td className="px-4 py-3">
                    {(() => {
                      const hasAnalysis = !!(f as Record<string, unknown>)["aiAnalysedAt"];
                      const hasFix      = !!(f as Record<string, unknown>)["aiFixSuggestedAt"];
                      const chip = "inline-flex items-center gap-1 rounded-full bg-gray-800/80 px-1.5 py-0.5 text-[10px] font-semibold text-gray-300 border border-gray-700/60";
                      if (hasAnalysis && hasFix) return (
                        <span title="AI analysis + fix suggestion ready" className={chip}>
                          <Sparkles className="h-2.5 w-2.5 text-indigo-400" /> Triaged
                        </span>
                      );
                      if (hasAnalysis) return (
                        <span title="AI analysis ready" className={chip}>
                          <Bot className="h-2.5 w-2.5 text-indigo-400" /> Analysed
                        </span>
                      );
                      if (hasFix) return (
                        <span title="Fix suggestion ready" className={chip}>
                          <Wrench className="h-2.5 w-2.5 text-indigo-400" /> Fix ready
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
                );
              })
            )}
          </tbody>
        </table>
      </div>

      {/* Pagination + page size */}
      {data && (
        <div className="mt-4 flex items-center justify-between gap-2">
          <div className="flex items-center gap-2 text-xs text-gray-500">
            <span>Rows per page</span>
            <select
              value={pageSize}
              onChange={(e) => setPageSize(parseInt(e.target.value, 10))}
              className="rounded bg-gray-800 px-2 py-1 text-xs text-gray-300 focus:outline-none focus:ring-1 focus:ring-indigo-500"
            >
              {PAGE_SIZES.map((n) => <option key={n} value={n}>{n}</option>)}
            </select>
          </div>
          {data.totalPages > 1 ? (
            <div className="flex items-center gap-2">
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
          ) : (
            <span className="text-xs text-gray-600">Single page</span>
          )}
        </div>
      )}

      </>}

      <FindingDetailDrawer key={selectedFinding?.id} finding={selectedFinding} onClose={closeFinding} />
    </div>
  );
}
