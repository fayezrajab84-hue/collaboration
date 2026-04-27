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
import { useQuery } from "@tanstack/react-query";
import { Network, ArrowDown, GitBranch, Shield, CheckCircle2, AlertTriangle, ChevronDown, ChevronRight } from "lucide-react";
import { attackPathsApi, applicationsApi, findingsApi } from "../lib/api";
import SeverityBadge from "../components/SeverityBadge";
import MultiSelect from "../components/MultiSelect";
import FindingDetailDrawer from "../components/FindingDetailDrawer";
import type { AttackPathSummary, AttackPathNode, Finding } from "@devsecops/types";

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
        <PathCard path={data} forceExpanded />
      </div>
    </FindingDrawerHost>
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

function PathCard({ path, forceExpanded }: { path: AttackPathSummary; forceExpanded?: boolean }) {
  // Local expand state (default collapsed for the list view; force-open on
  // the dedicated detail page).
  const [open, setOpen] = useState(Boolean(forceExpanded));
  const verifiedOrLabel = path.hasConfirmed ? "Confirmed exploitation in chain" : "Correlated chain";
  const Icon = path.hasConfirmed ? AlertTriangle : Network;
  const iconClass = path.hasConfirmed ? "text-red-400" : "text-indigo-400";
  const isToggleable = !forceExpanded;

  const fromName = path.nodes[0]?.targetName;
  const toName   = path.nodes[path.nodes.length - 1]?.targetName;
  const headerSubtitle = (fromName && toName && fromName !== toName)
    ? `From ${fromName} → ${toName}`
    : (fromName ?? "Multi-tier chain across your stack");

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
            <h2 className="text-base font-semibold text-white">{verifiedOrLabel}</h2>
            <SeverityBadge severity={path.maxSeverity} />
            <span className="text-xs text-gray-500">·</span>
            <span className="text-xs text-gray-500">{path.length} hops</span>
            <span className="text-xs text-gray-500">·</span>
            <span className="text-xs text-gray-500">score {path.score.toFixed(1)}</span>
          </div>
          <p className="mt-1 text-xs text-gray-500 truncate">{headerSubtitle}</p>
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
  return (
    <li className="relative">
      <div className="absolute -left-[22px] top-1.5 flex h-4 w-4 items-center justify-center rounded-full border border-gray-700 bg-gray-900 text-[10px] text-gray-400">
        {stepIndex + 1}
      </div>
      <button
        type="button"
        onClick={() => openFinding(node.findingId)}
        className="flex w-full items-start gap-3 rounded p-1.5 text-left transition-colors hover:bg-gray-800/60 focus:outline-none focus-visible:ring-1 focus-visible:ring-indigo-400"
        title="Open finding details"
      >
        <TargetIcon targetType={node.targetType} />
        <div className="min-w-0 flex-1">
          <div className="flex items-center gap-2">
            <SeverityBadge severity={node.severity} />
            <span className="truncate text-sm text-gray-200">{node.title}</span>
          </div>
          <p className="mt-0.5 text-xs text-gray-500">
            <span className="font-mono">{node.scanType}</span>
            {node.targetName && <> · {node.targetName}</>}
            {node.filePath && <> · <span className="font-mono">{node.filePath}</span></>}
            {node.confidence === "CONFIRMED" && (
              <span className="ml-2 inline-flex items-center gap-1 text-emerald-400">
                <Shield className="h-3 w-3" /> proof
              </span>
            )}
          </p>
        </div>
      </button>
    </li>
  );
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

