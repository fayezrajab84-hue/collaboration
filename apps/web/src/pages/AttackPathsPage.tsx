/**
 * /attack-paths — Phase 27 Slice C.
 *
 * Lists scored attack paths (chains of correlated findings) with the highest-
 * scoring chain on top. Each path renders as a vertical card showing the
 * entry node → exit node walk, with edge labels explaining the bridge type.
 *
 * UX choices (per breachlens-ux-patterns.md):
 *   - Truth-in-advertising empty state: explains WHY no chains exist yet
 *     (either nothing is correlated, or operator hasn't declared asset
 *     relations on Repos/Containers/Domains)
 *   - Empty state should reward: zero chains for a healthy org renders
 *     a green check, not a gray dash
 *   - Badge meaning: severity colour, hop count, confirmed/possible state
 *     each carry one axis of information; never overlap
 *
 * v1 ships a vertical-list/timeline view rather than a force-directed graph
 * — the chain story comes through clearly without needing a graph library.
 * Force-directed graph is a Phase 27.x enhancement when the chain count
 * grows beyond what a list can render comfortably.
 */
import { useQuery } from "@tanstack/react-query";
import { Link, useParams } from "react-router-dom";
import { Network, ArrowDown, GitBranch, Shield, CheckCircle2, AlertTriangle } from "lucide-react";
import { attackPathsApi } from "../lib/api";
import SeverityBadge from "../components/SeverityBadge";
import type { AttackPathSummary, AttackPathNode } from "@devsecops/types";

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
    <div className="p-6">
      <Link to="/attack-paths" className="mb-3 inline-block text-sm text-gray-500 hover:text-gray-300">
        ← All attack paths
      </Link>
      <PathCard path={data} expanded />
    </div>
  );
}

// ── List page (top N paths) ───────────────────────────────────────────────

function AttackPathsList() {
  const { data, isLoading } = useQuery({
    queryKey: ["attackPaths"],
    queryFn:  () => attackPathsApi.list(50),
  });

  if (isLoading) {
    return <div className="p-6 text-gray-500">Loading attack paths…</div>;
  }

  const paths = data?.paths ?? [];

  return (
    <div className="p-6">
      <div className="mb-4 flex items-center gap-3">
        <Network className="h-6 w-6 text-indigo-400" />
        <h1 className="text-3xl font-bold text-white">Attack Paths</h1>
      </div>
      <p className="mb-6 text-sm text-gray-500">
        Findings the correlation engine has linked into chains. Highest-risk paths first.
        Click any path to see the full walk.
      </p>

      {paths.length === 0 ? <EmptyState /> : (
        <div className="space-y-4">
          {paths.map((p) => (
            <PathCard key={p.groupId} path={p} />
          ))}
        </div>
      )}
    </div>
  );
}

// ── Card showing one chain ────────────────────────────────────────────────

function PathCard({ path, expanded }: { path: AttackPathSummary; expanded?: boolean }) {
  const verifiedOrLabel = path.hasConfirmed ? "Confirmed exploitation in chain" : "Correlated chain";
  const Icon = path.hasConfirmed ? AlertTriangle : Network;
  const iconClass = path.hasConfirmed ? "text-red-400" : "text-indigo-400";

  return (
    <Link
      to={`/attack-paths/${encodeURIComponent(path.groupId)}`}
      className={
        "block rounded-xl border bg-gray-900/40 p-5 transition-colors " +
        (expanded
          ? "border-gray-700 cursor-default pointer-events-none"
          : "border-gray-800 hover:border-indigo-700")
      }
    >
      <div className="mb-3 flex items-start gap-3">
        <Icon className={`mt-0.5 h-5 w-5 ${iconClass}`} />
        <div className="flex-1">
          <div className="flex items-center gap-2">
            <h2 className="text-base font-semibold text-white">{verifiedOrLabel}</h2>
            <SeverityBadge severity={path.maxSeverity} />
            <span className="text-xs text-gray-500">·</span>
            <span className="text-xs text-gray-500">{path.length} hops</span>
            <span className="text-xs text-gray-500">·</span>
            <span className="text-xs text-gray-500">score {path.score.toFixed(1)}</span>
          </div>
          <p className="mt-1 text-xs text-gray-500">
            {path.nodes[0]?.targetName && path.nodes[path.nodes.length - 1]?.targetName
              ? `From ${path.nodes[0]?.targetName} → ${path.nodes[path.nodes.length - 1]?.targetName}`
              : "Multi-tier chain across your stack"}
          </p>
        </div>
      </div>
      <ol className="ml-4 space-y-2 border-l-2 border-gray-800 pl-4">
        {path.nodes.map((node, i) => (
          <PathStep key={node.findingId} node={node} stepIndex={i} />
        ))}
      </ol>
    </Link>
  );
}

function PathStep({ node, stepIndex }: { node: AttackPathNode; stepIndex: number }) {
  return (
    <li className="relative">
      <div className="absolute -left-[22px] top-1.5 flex h-4 w-4 items-center justify-center rounded-full border border-gray-700 bg-gray-900 text-[10px] text-gray-400">
        {stepIndex + 1}
      </div>
      <div className="flex items-start gap-3">
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
      </div>
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

function EmptyState() {
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
            Declare asset relations on the Repositories / Containers / Domains pages
            (the "Asset relations" panel inside Edit). Without operator-declared linkage,
            the engine can only chain on shared CVEs and secret hashes.
          </span>
        </li>
      </ul>
    </div>
  );
}

// ── Top-level routing wrapper ─────────────────────────────────────────────

export default function AttackPathsPage() {
  const params = useParams<{ groupId?: string }>();
  if (params.groupId) return <AttackPathDetail groupId={params.groupId} />;
  return <AttackPathsList />;
}
