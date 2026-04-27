/**
 * /attack-paths — Phase 27 Slice C + Phase 27.5.x UX upgrades.
 *
 * Lists scored attack paths (chains of correlated findings) with the highest-
 * scoring chain on top. Each path renders as a collapsible vertical card
 * showing the entry node → exit node walk, with edge labels explaining the
 * bridge type. Nodes are clickable — they open the existing FindingDetailDrawer
 * so operators can drill into source-line / HTTP-exchange / PENTEST evidence
 * without leaving the chain view.
 *
 * Phase 27.5.x UX additions on top of Phase 27 Slice C:
 *   - Application MultiSelect filter (mirrors FindingsPage pattern). Hidden
 *     when the org has zero applications. The cards then show only chains
 *     whose findings live on assets in the selected app(s).
 *   - Cards collapsed-by-default — show the headline + 1-line preview;
 *     expand to see the full node walk. Critical when an org has many
 *     chains across many apps.
 *   - Click any node → opens FindingDetailDrawer for that finding (same
 *     drawer used everywhere else; full SAST source-line view, DAST HTTP
 *     exchange, PENTEST evidence, AI analysis, etc.)
 *
 * Force-directed graph is still deferred (Phase 27.x candidate). This list+
 * detail combo handles dozens-of-chains comfortably.
 */
import { createContext, useContext, useMemo, useState } from "react";
import { Link, useParams, useSearchParams } from "react-router-dom";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { Network, ArrowDown, GitBranch, Shield, CheckCircle2, AlertTriangle, ChevronDown, ChevronRight, Sparkles, RefreshCw } from "lucide-react";
import { attackPathsApi, applicationsApi, findingsApi } from "../lib/api";
import SeverityBadge from "../components/SeverityBadge";
import MultiSelect from "../components/MultiSelect";
import FindingDetailDrawer from "../components/FindingDetailDrawer";
import { useToast } from "../hooks/useToast";
import type { AttackPathSummary, AttackPathNode, AttackPathSummaryAI, Finding } from "@devsecops/types";

// ── Top-level routing wrapper ─────────────────────────────────────────────

export default function AttackPathsPage() {
  const params = useParams<{ groupId?: string }>();
  if (params.groupId) return <AttackPathDetail groupId={params.groupId} />;
  return <AttackPathsList />;
}

// ── Detail page (single chain) ─────────────────────────────────────────────

function AttackPathDetail({ groupId }: { groupId: string }) {
  const { data, isLoading, error } = useQuery({
    queryKey: ["attackPath", groupId],
    queryFn:  () => attackPathsApi.get(groupId),
  });

  if (isLoading) return <div className="p-6 text-gray-500">Loading…</div>;
  if (error || !data) {
    return (
      <div className="p-6 text-gray-500">
        <p className="text-base text-gray-300">Attack path not found.</p>
        <p className="mt-2 text-sm text-gray-500">It may have been resolved or its findings marked false-positive.</p>
        <Link to="/attack-paths" className="mt-3 inline-block text-sm text-indigo-400 hover:text-indigo-300">
          ← Back to all paths
        </Link>
      </div>
    );
  }
  return (
    <FindingDrawerHost>
      <div className="p-6">
        <Link to="/attack-paths" className="mb-3 inline-block text-sm text-gray-500 hover:text-gray-300">
          ← All attack paths
        </Link>
        {/* Phase 27.5.x — AI summary panel only on the dedicated detail
            page (not in the list-view cards) so it doesn't burn AI calls
            for chains the operator never opens. */}
        <AiSummaryPanel groupId={groupId} initialSummary={data.summary ?? null} />
        {/* Detail view: prefer the AI tldr as the chain title when present;
            fall back to the heuristic title from the API. */}
        <PathCard path={data} forceExpanded aiTitle={data.summary?.tldr ?? null} />
      </div>
    </FindingDrawerHost>
  );
}

// ── AI summary panel (Phase 27.5.x) ───────────────────────────────────────
//
// Operator-triggered: shows a "Generate AI summary" button when no summary
// exists, the cached tldr+narrative when one does, and a "Regenerate"
// button (always) plus a "Stale — content changed" hint when the cached
// hash no longer matches the chain. Never auto-fires.

function AiSummaryPanel({
  groupId,
  initialSummary,
}: {
  groupId:        string;
  initialSummary: AttackPathSummaryAI | null;
}) {
  const qc = useQueryClient();
  const { toast } = useToast();
  const [summary, setSummary] = useState<AttackPathSummaryAI | null>(initialSummary);
  const [errorMsg, setErrorMsg] = useState<string | null>(null);

  const gen = useMutation({
    mutationFn: (force: boolean) => attackPathsApi.summarise(groupId, force),
    onSuccess: (next) => {
      setSummary(next);
      setErrorMsg(null);
      qc.invalidateQueries({ queryKey: ["attackPath", groupId] });
      toast.success(next.cached ? "Loaded cached summary" : "Summary generated");
    },
    onError: (err: Error & { response?: { data?: { error?: string; code?: string } } }) => {
      const code = err.response?.data?.code;
      const detail = err.response?.data?.error ?? err.message ?? "Failed to generate";
      setErrorMsg(
        code === "PROVIDER_UNCONFIGURED"
          ? "No AI provider configured for this org. Set one up in Settings → AI Providers."
          : detail,
      );
    },
  });

  // Empty state — never generated
  if (!summary) {
    return (
      <div className="mb-4 rounded-xl border border-indigo-800/40 bg-indigo-950/30 p-4">
        <div className="flex items-start gap-3">
          <Sparkles className="mt-0.5 h-4 w-4 text-indigo-400" />
          <div className="flex-1">
            <h3 className="text-sm font-semibold text-white">AI summary</h3>
            <p className="mt-0.5 text-xs text-gray-400">
              Get a 1-paragraph plain-language explanation of what this chain represents and the
              realistic exploit path. Manual trigger — costs one AI call against your configured
              provider; cached afterwards until the chain content changes.
            </p>
            <button
              type="button"
              onClick={() => gen.mutate(false)}
              disabled={gen.isPending}
              className="mt-3 inline-flex items-center gap-1.5 rounded-lg bg-indigo-700 px-3 py-1.5 text-xs font-medium text-white hover:bg-indigo-600 disabled:opacity-50"
            >
              <Sparkles className="h-3 w-3" /> {gen.isPending ? "Generating…" : "Generate summary"}
            </button>
            {errorMsg && <p className="mt-2 text-xs text-red-400">{errorMsg}</p>}
          </div>
        </div>
      </div>
    );
  }

  // Populated state
  return (
    <div className="mb-4 rounded-xl border border-indigo-800/40 bg-indigo-950/30 p-4">
      <div className="flex items-start gap-3">
        <Sparkles className="mt-0.5 h-4 w-4 text-indigo-400" />
        <div className="flex-1 min-w-0">
          <div className="flex flex-wrap items-center gap-2">
            <h3 className="text-sm font-semibold text-white">AI summary</h3>
            {summary.stale && (
              <span className="inline-flex items-center gap-1 rounded-full border border-amber-800 bg-amber-950/30 px-2 py-0.5 text-[10px] text-amber-300">
                Stale — chain content changed
              </span>
            )}
            <span className="text-[10px] text-gray-500">
              {summary.providerType.toLowerCase()} · {summary.model}
            </span>
            <button
              type="button"
              onClick={() => gen.mutate(true)}
              disabled={gen.isPending}
              className="ml-auto inline-flex items-center gap-1 rounded px-2 py-0.5 text-[11px] text-gray-400 hover:bg-gray-800 hover:text-gray-200 disabled:opacity-50"
              title="Regenerate from scratch (forces a fresh AI call)"
            >
              <RefreshCw className={`h-3 w-3 ${gen.isPending ? "animate-spin" : ""}`} />
              {gen.isPending ? "Regenerating…" : "Regenerate"}
            </button>
          </div>
          <p className="mt-2 text-sm font-medium text-indigo-100">{summary.tldr}</p>
          <p className="mt-2 whitespace-pre-line text-xs leading-relaxed text-gray-300">{summary.narrative}</p>
          {errorMsg && <p className="mt-2 text-xs text-red-400">{errorMsg}</p>}
        </div>
      </div>
    </div>
  );
}

// ── List page (top N paths) ───────────────────────────────────────────────

function AttackPathsList() {
  const [searchParams, setSearchParams] = useSearchParams();

  // Phase 27.5.x — Application filter persists in the URL so a deep-linked
  // /attack-paths?applicationId=X view stays consistent across reloads.
  const parseMulti = (v: string | null) => (v ?? "").split(",").map((s) => s.trim()).filter(Boolean);
  const appIds = parseMulti(searchParams.get("applicationId"));
  const setAppFilter = (next: string[]) => {
    const sp = new URLSearchParams(searchParams);
    if (next.length === 0) sp.delete("applicationId");
    else sp.set("applicationId", next.join(","));
    setSearchParams(sp, { replace: true });
  };

  const { data, isLoading } = useQuery({
    queryKey: ["attackPaths"],
    queryFn:  () => attackPathsApi.list(50),
  });
  const { data: applications } = useQuery({
    queryKey: ["applications"],
    queryFn:  applicationsApi.list,
  });

  // Filter chains by selected applications using the `applicationIds` field
  // the backend now stamps on each chain summary (Phase 27.5.x). A chain
  // matches when ANY of its application IDs is in the selected set.
  const filtered = useMemo(() => {
    if (!data?.paths) return [];
    if (appIds.length === 0) return data.paths;
    const selected = new Set(appIds);
    return data.paths.filter((p) => p.applicationIds.some((id) => selected.has(id)));
  }, [data, appIds]);

  if (isLoading) return <div className="p-6 text-gray-500">Loading attack paths…</div>;
  const paths = filtered;

  return (
    <FindingDrawerHost>
      <div className="p-6">
        <div className="mb-4 flex items-center gap-3">
          <Network className="h-6 w-6 text-indigo-400" />
          <h1 className="text-3xl font-bold text-white">Attack Paths</h1>
        </div>
        <p className="mb-4 text-sm text-gray-500">
          Findings the correlation engine has linked into chains. Highest-risk paths first.
          Click any path to expand the walk; click any finding to see its full evidence.
        </p>

        {/* Filter row — only render the app filter when there's at least one
            application in the org (avoid an empty-options dropdown). */}
        {(applications?.length ?? 0) > 0 && (
          <div className="mb-5 flex items-center gap-3">
            <MultiSelect
              label="Applications"
              options={(applications ?? []).map((a) => ({ value: a.id, label: a.name }))}
              value={appIds}
              onChange={setAppFilter}
            />
            {appIds.length > 0 && (
              <span className="text-xs text-gray-500">
                Showing {paths.length} chain{paths.length === 1 ? "" : "s"} for {appIds.length} app{appIds.length === 1 ? "" : "s"}
              </span>
            )}
          </div>
        )}

        {paths.length === 0 ? <EmptyState filtered={appIds.length > 0} /> : (
          <div className="space-y-3">
            {paths.map((p) => <PathCard key={p.groupId} path={p} />)}
          </div>
        )}
      </div>
    </FindingDrawerHost>
  );
}

// ── Drawer host — provides openFinding() context to every node click ──────
//
// Lifts the FindingDetailDrawer state to the page level so multiple PathCards
// share one drawer instance. Uses URL ?finding=<id> for shareability — same
// pattern as FindingsPage.

const DrawerCtx = createContext<{ openFinding: (id: string) => void }>({ openFinding: () => {} });

function FindingDrawerHost({ children }: { children: React.ReactNode }) {
  const [searchParams, setSearchParams] = useSearchParams();
  const selectedId = searchParams.get("finding");

  const { data: finding = null } = useQuery({
    queryKey: ["finding", selectedId],
    queryFn:  () => findingsApi.get(selectedId!),
    enabled:  !!selectedId,
    staleTime: 0,
  });

  const openFinding = (id: string) => {
    const sp = new URLSearchParams(searchParams);
    sp.set("finding", id);
    setSearchParams(sp, { replace: false });
  };
  const closeFinding = () => {
    const sp = new URLSearchParams(searchParams);
    sp.delete("finding");
    setSearchParams(sp, { replace: false });
  };

  return (
    <DrawerCtx.Provider value={{ openFinding }}>
      {children}
      <FindingDetailDrawer key={finding?.id ?? "empty"} finding={finding as Finding | null} onClose={closeFinding} />
    </DrawerCtx.Provider>
  );
}

// ── Card showing one chain — collapsible (Phase 27.5.x) ───────────────────

function PathCard({
  path,
  forceExpanded,
  aiTitle,
}: {
  path:           AttackPathSummary;
  forceExpanded?: boolean;
  /** AI tldr — overrides the heuristic title when present. Detail page only. */
  aiTitle?:       string | null;
}) {
  // Local expand state (default collapsed for the list view; force-open on
  // the dedicated detail page).
  const [open, setOpen] = useState(Boolean(forceExpanded));
  const Icon = path.hasConfirmed ? AlertTriangle : Network;
  const iconClass = path.hasConfirmed ? "text-red-400" : "text-indigo-400";
  const isToggleable = !forceExpanded;

  // Title: prefer AI tldr (when available — detail view only), fall back
  // to the backend's heuristic title (highest-severity, source-side preferred).
  // Never fall back to "Correlated chain" — every chain has a real title now.
  const headline = (aiTitle && aiTitle.length > 0) ? aiTitle : path.title;

  // Subtitle: confirmed-exploit qualifier OR the From→To hop story OR a
  // generic "spans N targets" fallback. The headline above carries the
  // "what", subtitle carries the "where" and "how proven".
  const fromName = path.nodes[0]?.targetName;
  const toName   = path.nodes[path.nodes.length - 1]?.targetName;
  const subtitleParts: string[] = [];
  if (path.hasConfirmed) subtitleParts.push("Confirmed exploit");
  if (fromName && toName && fromName !== toName) subtitleParts.push(`${fromName} → ${toName}`);
  else if (fromName) subtitleParts.push(fromName);
  const subtitle = subtitleParts.join(" · ");

  return (
    <div className={
      "rounded-xl border bg-gray-900/40 transition-colors " +
      (forceExpanded ? "border-gray-700" : "border-gray-800 hover:border-indigo-700")
    }>
      <button
        type="button"
        onClick={() => isToggleable && setOpen((v) => !v)}
        disabled={!isToggleable}
        className={
          "flex w-full items-start gap-3 p-5 text-left " +
          (isToggleable ? "cursor-pointer" : "cursor-default")
        }
      >
        {isToggleable && (
          <span className="mt-0.5 text-gray-500">
            {open ? <ChevronDown className="h-4 w-4" /> : <ChevronRight className="h-4 w-4" />}
          </span>
        )}
        <Icon className={`mt-0.5 h-5 w-5 ${iconClass}`} />
        <div className="flex-1 min-w-0">
          <div className="flex flex-wrap items-center gap-2">
            <h2 className="text-base font-semibold text-white">{headline}</h2>
            <SeverityBadge severity={path.maxSeverity} />
            <span className="text-xs text-gray-500">·</span>
            <span className="text-xs text-gray-500">{path.length} hops</span>
            <span className="text-xs text-gray-500">·</span>
            <span className="text-xs text-gray-500">score {path.score.toFixed(1)}</span>
          </div>
          {subtitle && <p className="mt-1 text-xs text-gray-500 truncate">{subtitle}</p>}
        </div>
        {isToggleable && (
          <Link
            to={`/attack-paths/${encodeURIComponent(path.groupId)}`}
            onClick={(e) => e.stopPropagation()}
            className="text-xs text-indigo-400 hover:text-indigo-300 self-start whitespace-nowrap"
          >
            Open full →
          </Link>
        )}
      </button>

      {open && (
        <ol className="ml-9 mr-5 mb-5 space-y-2 border-l-2 border-gray-800 pl-4">
          {path.nodes.map((node, i) => (
            <PathStep key={node.findingId} node={node} stepIndex={i} />
          ))}
        </ol>
      )}
    </div>
  );
}

function PathStep({ node, stepIndex }: { node: AttackPathNode; stepIndex: number }) {
  const { openFinding } = useContext(DrawerCtx);

  // Scan-type-aware "vulnerability locator" line. Different scan types have
  // different "where exactly is the bug" answer:
  //   SAST/IAC/SECRET → file:line + ruleId
  //   SCA/CONTAINER   → packageName@version + CVE + fix
  //   DAST/PENTEST    → URL + payload (when present)
  const locator = buildLocator(node);

  return (
    <li className="relative">
      <div className="absolute -left-[22px] top-1.5 flex h-4 w-4 items-center justify-center rounded-full border border-gray-700 bg-gray-900 text-[10px] text-gray-400">
        {stepIndex + 1}
      </div>
      <button
        type="button"
        onClick={() => openFinding(node.findingId)}
        className="flex w-full items-start gap-3 rounded p-2 text-left transition-colors hover:bg-gray-800/60 focus:outline-none focus-visible:ring-1 focus-visible:ring-indigo-400"
        title="Open finding details"
      >
        <TargetIcon targetType={node.targetType} />
        <div className="min-w-0 flex-1">
          <div className="flex flex-wrap items-center gap-2">
            <SeverityBadge severity={node.severity} />
            <span className="rounded bg-gray-800 px-1.5 py-0.5 text-[10px] font-medium text-gray-400">
              {node.scanType}
            </span>
            <span className="truncate text-sm text-gray-200">{node.title}</span>
            {node.confidence === "CONFIRMED" && (
              <span className="inline-flex items-center gap-1 text-[10px] text-emerald-400">
                <Shield className="h-3 w-3" /> proof
              </span>
            )}
          </div>
          {/* Locator line — what + where, scan-type aware */}
          {locator && (
            <p className="mt-1 text-xs text-gray-400">{locator}</p>
          )}
          {/* Target line — the asset this finding lives on */}
          {node.targetName && (
            <p className="mt-0.5 text-[11px] text-gray-600">
              {labelForTargetType(node.targetType)} · <span className="font-mono">{node.targetName}</span>
            </p>
          )}
        </div>
      </button>
    </li>
  );
}

function labelForTargetType(t: string): string {
  if (t === "REPOSITORY") return "repo";
  if (t === "CONTAINER")  return "image";
  return "domain";
}

/** Build the scan-type-aware "where exactly" string for a chain node. */
function buildLocator(node: AttackPathNode): React.ReactNode {
  // Code-side (SAST/IAC/SECRET): file path + line number + rule id
  if (node.scanType === "SAST" || node.scanType === "IAC" || node.scanType === "SECRET") {
    const parts: React.ReactNode[] = [];
    if (node.filePath) {
      parts.push(
        <span key="file" className="font-mono text-gray-300">
          {node.filePath}{node.lineStart != null ? `:${node.lineStart}` : ""}
        </span>,
      );
    }
    if (node.ruleId) parts.push(<RuleChip key="rule">{node.ruleId}</RuleChip>);
    if (node.cweId)  parts.push(<RuleChip key="cwe">CWE-{stripCwePrefix(node.cweId)}</RuleChip>);
    return parts.length ? <>{interleave(parts, " · ")}</> : null;
  }

  // Package-side (SCA / CONTAINER): package@version, CVE, fix version
  if (node.scanType === "SCA" || node.scanType === "CONTAINER") {
    const parts: React.ReactNode[] = [];
    if (node.packageName) {
      const pkg = node.packageVersion
        ? `${node.packageName}@${node.packageVersion}`
        : node.packageName;
      parts.push(<span key="pkg" className="font-mono text-gray-300">{pkg}</span>);
    }
    if (node.cveId) {
      parts.push(
        <span key="cve" className="rounded bg-red-950/30 px-1.5 py-0.5 font-mono text-[10px] text-red-300">
          {node.cveId}{node.cvssScore != null ? ` · CVSS ${node.cvssScore.toFixed(1)}` : ""}
        </span>,
      );
    }
    if (node.fixVersion) {
      parts.push(
        <span key="fix" className="rounded bg-emerald-950/30 px-1.5 py-0.5 text-[10px] text-emerald-300">
          fix → {node.fixVersion}
        </span>,
      );
    }
    return parts.length ? <span className="inline-flex flex-wrap items-center gap-1">{parts}</span> : null;
  }

  // Web-side (DAST / PENTEST / PENTEST_FULL): URL + payload (if any)
  if (node.scanType === "DAST" || node.scanType === "PENTEST" || node.scanType === "PENTEST_FULL") {
    const ev = (node.evidence ?? {}) as Record<string, unknown>;
    const url = (ev["url"] ?? ev["request_url"] ?? ev["target_url"] ?? ev["endpoint"]) as string | undefined;
    const payload = ev["payload"] as string | undefined;
    const parts: React.ReactNode[] = [];
    if (url) {
      parts.push(
        <span key="url" className="font-mono text-gray-300 break-all">
          {truncate(url, 90)}
        </span>,
      );
    }
    if (payload) {
      parts.push(
        <span key="pl" className="font-mono text-[10px] text-amber-400">
          payload: {truncate(payload, 60)}
        </span>,
      );
    }
    if (node.ruleId) parts.push(<RuleChip key="rule">{node.ruleId}</RuleChip>);
    return parts.length ? <span className="inline-flex flex-wrap items-center gap-1">{parts}</span> : null;
  }

  // Runtime / other — just show file path or evidence url if present
  if (node.filePath) return <span className="font-mono text-gray-300">{node.filePath}</span>;
  return null;
}

function RuleChip({ children }: { children: React.ReactNode }) {
  return (
    <span className="rounded bg-gray-800/60 px-1.5 py-0.5 font-mono text-[10px] text-gray-400">
      {children}
    </span>
  );
}

function stripCwePrefix(raw: string): string {
  return raw.replace(/^CWE-?/i, "");
}

function truncate(s: string, n: number): string {
  return s.length > n ? `${s.slice(0, n)}…` : s;
}

function interleave<T>(arr: T[], sep: T): T[] {
  const out: T[] = [];
  arr.forEach((item, i) => { if (i > 0) out.push(sep); out.push(item); });
  return out;
}

function TargetIcon({ targetType }: { targetType: string }) {
  const cls = "mt-0.5 h-3.5 w-3.5 text-gray-500 shrink-0";
  if (targetType === "REPOSITORY") return <GitBranch className={cls} />;
  if (targetType === "CONTAINER")  return <Network className={cls} />;
  return <ArrowDown className={cls} />;
}

// ── Empty state ───────────────────────────────────────────────────────────

function EmptyState({ filtered }: { filtered?: boolean }) {
  if (filtered) {
    return (
      <div className="rounded-xl border border-gray-800 bg-gray-900/40 p-8 text-center">
        <p className="text-sm text-gray-500">No chains match the selected application(s). Clear the filter to see all chains, or choose a different app.</p>
      </div>
    );
  }
  return (
    <div className="rounded-xl border border-gray-800 bg-gray-900/40 p-8 text-center">
      <CheckCircle2 className="mx-auto mb-3 h-8 w-8 text-emerald-500" />
      <h3 className="text-base font-semibold text-white">No attack paths discovered yet</h3>
      <p className="mx-auto mt-2 max-w-md text-sm text-gray-500">
        The correlation engine hasn't grouped any findings into chains. Two ways to make chains visible:
      </p>
      <ul className="mx-auto mt-4 max-w-md space-y-2 text-left text-sm text-gray-400">
        <li className="flex items-start gap-2">
          <span className="text-indigo-400">1.</span>
          <span>
            Run scans across multiple targets (repo + container + domain) so cross-tier matches
            (same CVE, same secret hash, same URL→file mapping) have something to link.
          </span>
        </li>
        <li className="flex items-start gap-2">
          <span className="text-indigo-400">2.</span>
          <span>
            Assign your assets to an Application on the <Link to="/applications" className="text-indigo-400 hover:text-indigo-300">Applications page</Link> —
            the engine only correlates within an app boundary, so unassigned assets don't form chains.
          </span>
        </li>
      </ul>
    </div>
  );
}

