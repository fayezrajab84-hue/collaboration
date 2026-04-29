/**
 * AttackPathFlow — kill-chain block diagram for an attack path.
 *
 * Compresses a chain's potentially-many findings into 4 logical phases:
 *
 *   Source  →  Image  →  Surface  →  Runtime
 *  (SAST/    (SCA/     (DAST/      (Wazuh
 *   IAC/      CONTAINER) PENTEST)    alerts)
 *   SECRET)
 *
 * Each phase block aggregates the chain's findings at that tier into:
 *   • count                — total nodes
 *   • highest severity     — drives the block's accent color
 *   • confirmed PoE badge  — when the phase contains a CONFIRMED finding
 *   • one-line headline    — top finding's title / rule / CVE
 *
 * Arrows between blocks show the bridge that connects evidence across
 * tiers — colored by confidence (red=CONFIRMED, indigo=LIKELY, gray=
 * POSSIBLE) and labeled with the dominant bridge type (route, runtime,
 * container_exposure, etc.) plus an edge count.
 *
 * Phases with zero findings render as muted dashed blocks — keeps the
 * 4-phase rhythm consistent across chains and visually shows what's
 * MISSING (e.g. a chain with no Runtime evidence is "potential" not
 * "proven"). Phases with CONFIRMED findings get a 🔥 PoE accent so the
 * operator's eye lands on proven-exploit blocks first.
 *
 * Design intent: the operator sees the full kill-chain story in ONE
 * horizontal scan. The collapsible per-scan-type list below the flow
 * (existing UI) is for drilling into individual findings.
 */
import { Fragment } from "react";
import { Link } from "react-router-dom";
import {
  Code2, Box, Globe, Activity, ArrowRight, Flame, AlertCircle,
} from "lucide-react";
import type { AttackPathNode, AttackPathEdge } from "@devsecops/types";

// ── Phase taxonomy ───────────────────────────────────────────────────────

type Phase = "source" | "image" | "surface" | "runtime";

const PHASE_DEF: Record<Phase, {
  label:     string;
  Icon:      typeof Code2;
  scanTypes: string[];
  caption:   string;
}> = {
  source:  {
    label:     "Source",
    Icon:      Code2,
    scanTypes: ["SAST", "IAC", "SECRET"],
    caption:   "Code · IaC · Secrets",
  },
  image: {
    label:     "Image",
    Icon:      Box,
    scanTypes: ["SCA", "CONTAINER"],
    caption:   "Dependencies · CVEs",
  },
  surface: {
    label:     "Surface",
    Icon:      Globe,
    scanTypes: ["DAST", "PENTEST_FULL"],
    caption:   "Reachable endpoints",
  },
  runtime: {
    label:     "Runtime",
    Icon:      Activity,
    scanTypes: ["RUNTIME"],
    caption:   "Live attack telemetry",
  },
};

const PHASES: Phase[] = ["source", "image", "surface", "runtime"];

function nodeToPhase(scanType: string): Phase | null {
  for (const phase of PHASES) {
    if (PHASE_DEF[phase].scanTypes.includes(scanType)) return phase;
  }
  return null;
}

// ── Aggregation ──────────────────────────────────────────────────────────

interface PhaseAgg {
  count:        number;
  maxSeverity:  string;
  hasConfirmed: boolean;
  topNode:      AttackPathNode | null;
  scanTypes:    Set<string>;
}

const SEV_RANK: Record<string, number> = {
  CRITICAL: 4, HIGH: 3, MEDIUM: 2, LOW: 1, INFO: 0,
};

function aggregateByPhase(nodes: AttackPathNode[]): Record<Phase, PhaseAgg> {
  const out: Record<Phase, PhaseAgg> = {
    source:  emptyAgg(),
    image:   emptyAgg(),
    surface: emptyAgg(),
    runtime: emptyAgg(),
  };

  for (const node of nodes) {
    const phase = nodeToPhase(node.scanType);
    if (!phase) continue;
    const agg = out[phase];
    agg.count++;
    agg.scanTypes.add(node.scanType);
    if ((SEV_RANK[node.severity] ?? 0) > (SEV_RANK[agg.maxSeverity] ?? 0)) {
      agg.maxSeverity = node.severity;
    }
    if (node.confidence === "CONFIRMED") agg.hasConfirmed = true;
    // Top node = highest-severity, then prefer confirmed
    if (
      !agg.topNode ||
      (SEV_RANK[node.severity] ?? 0) > (SEV_RANK[agg.topNode.severity] ?? 0) ||
      (node.confidence === "CONFIRMED" && agg.topNode.confidence !== "CONFIRMED")
    ) {
      agg.topNode = node;
    }
  }
  return out;
}

function emptyAgg(): PhaseAgg {
  return {
    count: 0, maxSeverity: "INFO", hasConfirmed: false,
    topNode: null, scanTypes: new Set(),
  };
}

// ── Bridge aggregation per arrow ─────────────────────────────────────────

interface BridgeAgg {
  count:           number;
  dominantType:    string | null;  // "runtime" | "route" | "container_exposure" | "cve" | "secret" | "port"
  bestConfidence:  "CONFIRMED" | "LIKELY" | "POSSIBLE" | null;
}

function bridgesBetween(
  fromPhase: Phase,
  toPhase:   Phase,
  nodes:     AttackPathNode[],
  edges:     AttackPathEdge[],
): BridgeAgg {
  const phaseByNodeId = new Map<string, Phase | null>();
  for (const n of nodes) phaseByNodeId.set(n.findingId, nodeToPhase(n.scanType));

  const typeCount = new Map<string, number>();
  let count = 0;
  let bestConfidence: BridgeAgg["bestConfidence"] = null;
  const CONF_RANK = { POSSIBLE: 1, LIKELY: 2, CONFIRMED: 3 } as const;

  for (const e of edges) {
    const a = phaseByNodeId.get(e.fromFindingId);
    const b = phaseByNodeId.get(e.toFindingId);
    // Bridges are symmetric in our engine — count an edge if it spans
    // these two phases regardless of direction.
    if ((a === fromPhase && b === toPhase) || (a === toPhase && b === fromPhase)) {
      count++;
      typeCount.set(e.bridgeType, (typeCount.get(e.bridgeType) ?? 0) + 1);
      if (
        !bestConfidence ||
        (CONF_RANK[e.confidence] > CONF_RANK[bestConfidence])
      ) {
        bestConfidence = e.confidence;
      }
    }
  }

  const dominantType = [...typeCount.entries()].sort((a, b) => b[1] - a[1])[0]?.[0] ?? null;

  return { count, dominantType, bestConfidence };
}

// ── Visual tokens ────────────────────────────────────────────────────────

const SEV_BORDER: Record<string, string> = {
  CRITICAL: "border-red-700/70 bg-red-950/30",
  HIGH:     "border-red-700/50 bg-red-950/20",
  MEDIUM:   "border-indigo-700/50 bg-indigo-950/30",
  LOW:      "border-gray-700 bg-gray-900/40",
  INFO:     "border-gray-800 bg-gray-900/30",
};

const SEV_TEXT: Record<string, string> = {
  CRITICAL: "text-red-300",
  HIGH:     "text-red-300/90",
  MEDIUM:   "text-indigo-200",
  LOW:      "text-gray-300",
  INFO:     "text-gray-400",
};

const BRIDGE_TYPE_LABEL: Record<string, string> = {
  runtime:            "runtime",
  route:              "route",
  container_exposure: "exposure",
  cve:                "CVE",
  secret:             "secret",
  port:               "port",
};

const BRIDGE_CONF_COLOR: Record<string, string> = {
  CONFIRMED: "text-red-400",
  LIKELY:    "text-indigo-400",
  POSSIBLE:  "text-gray-500",
};

// ── Components ───────────────────────────────────────────────────────────

export default function AttackPathFlow({
  nodes,
  edges,
  groupId,
}: {
  nodes:   AttackPathNode[];
  edges:   AttackPathEdge[];
  groupId: string;
}) {
  const aggs = aggregateByPhase(nodes);

  return (
    <div className="rounded-lg border border-gray-800 bg-gray-950/60 p-4">
      <div className="mb-3 flex items-center gap-2">
        <span className="text-[10px] font-semibold uppercase tracking-wider text-gray-500">
          Kill-chain flow
        </span>
        <span className="text-[10px] text-gray-600">·</span>
        <span className="text-[10px] text-gray-500">
          {nodes.length} findings, {edges.length} edges
        </span>
      </div>

      <div className="flex flex-wrap items-stretch gap-2 lg:flex-nowrap">
        {PHASES.map((phase, i) => (
          <Fragment key={phase}>
            <PhaseBlock phase={phase} agg={aggs[phase]} groupId={groupId} />
            {i < PHASES.length - 1 && (
              <PhaseArrow
                fromPhase={phase}
                toPhase={PHASES[i + 1]!}
                nodes={nodes}
                edges={edges}
              />
            )}
          </Fragment>
        ))}
      </div>
    </div>
  );
}

function PhaseBlock({
  phase, agg, groupId,
}: {
  phase:   Phase;
  agg:     PhaseAgg;
  groupId: string;
}) {
  const { label, Icon, caption } = PHASE_DEF[phase];
  const empty = agg.count === 0;

  if (empty) {
    return (
      <div className="flex-1 min-w-[140px] rounded-lg border border-dashed border-gray-800 bg-gray-950/30 p-3">
        <div className="flex items-center gap-1.5 text-gray-600">
          <Icon className="h-3.5 w-3.5" />
          <span className="text-xs font-semibold uppercase tracking-wide">{label}</span>
        </div>
        <div className="mt-1 text-[10px] text-gray-700">{caption}</div>
        <div className="mt-2 text-[10px] italic text-gray-700">No findings at this phase</div>
      </div>
    );
  }

  const borderClass = SEV_BORDER[agg.maxSeverity] ?? SEV_BORDER.INFO;
  const headlineClass = SEV_TEXT[agg.maxSeverity] ?? SEV_TEXT.INFO;
  const topNode = agg.topNode!;
  const headline =
    topNode.cveId ??
    (topNode.ruleId ? `${topNode.ruleId}` : null) ??
    topNode.title.slice(0, 60);

  // Per-block deep-link to the per-scan-type group on the chain detail page.
  // Lets the operator click into "the SAST findings in this phase" without
  // expanding everything else first.
  const targetScanType = topNode.scanType;
  const detailHref = `/attack-paths/${encodeURIComponent(groupId)}#scan-${targetScanType}`;

  return (
    <Link
      to={detailHref}
      className={`flex-1 min-w-[140px] rounded-lg border ${borderClass} p-3 transition-colors hover:border-indigo-500`}
    >
      <div className="flex items-center justify-between gap-1">
        <div className="flex items-center gap-1.5">
          <Icon className={`h-3.5 w-3.5 ${headlineClass}`} />
          <span className={`text-xs font-semibold uppercase tracking-wide ${headlineClass}`}>
            {label}
          </span>
        </div>
        {agg.hasConfirmed && (
          <span
            className="flex items-center gap-1 rounded-full border border-red-700 bg-red-950/40 px-1.5 py-0.5 text-[9px] font-bold text-red-300"
            title="At least one finding in this phase has scanner-reproduced Proof of Exploit"
          >
            <Flame className="h-2.5 w-2.5" />
            PoE
          </span>
        )}
      </div>

      <div className="mt-1.5 flex items-baseline gap-1.5">
        <span className={`text-2xl font-bold ${headlineClass}`}>{agg.count}</span>
        <span className="text-[11px] text-gray-500">
          finding{agg.count === 1 ? "" : "s"}
        </span>
      </div>

      <div className="mt-1 text-[10px] text-gray-500">
        {[...agg.scanTypes].slice(0, 3).join(" · ")}
      </div>

      <div className="mt-2 line-clamp-2 text-[11px] text-gray-300" title={topNode.title}>
        {headline}
      </div>

      {topNode.severity !== "INFO" && (
        <div className="mt-1.5">
          <span
            className={`inline-block rounded px-1.5 py-0.5 text-[9px] font-semibold uppercase tracking-wide ${
              topNode.severity === "CRITICAL" ? "bg-red-900/60 text-red-200"
            : topNode.severity === "HIGH"     ? "bg-red-950/40 text-red-300"
            : topNode.severity === "MEDIUM"   ? "bg-indigo-950/40 text-indigo-300"
            :                                    "bg-gray-800 text-gray-400"
            }`}
          >
            {topNode.severity}
          </span>
        </div>
      )}
    </Link>
  );
}

function PhaseArrow({
  fromPhase, toPhase, nodes, edges,
}: {
  fromPhase: Phase;
  toPhase:   Phase;
  nodes:     AttackPathNode[];
  edges:     AttackPathEdge[];
}) {
  const bridge = bridgesBetween(fromPhase, toPhase, nodes, edges);

  // No edges → muted dashed arrow (the phases exist but there's no
  // proven correlation between them in this chain).
  if (bridge.count === 0) {
    return (
      <div className="flex shrink-0 items-center justify-center px-1 text-gray-700">
        <ArrowRight className="h-4 w-4" strokeDasharray="2 2" />
      </div>
    );
  }

  const colorClass = bridge.bestConfidence ? BRIDGE_CONF_COLOR[bridge.bestConfidence] : "text-gray-500";
  const label = bridge.dominantType ? BRIDGE_TYPE_LABEL[bridge.dominantType] ?? bridge.dominantType : "";

  return (
    <div className="flex shrink-0 flex-col items-center justify-center gap-1 px-1">
      <ArrowRight className={`h-4 w-4 ${colorClass}`} />
      {label && (
        <div className={`text-[9px] uppercase tracking-wide ${colorClass}`}>
          {label}
        </div>
      )}
      <div className="text-[9px] text-gray-600">
        {bridge.count} edge{bridge.count === 1 ? "" : "s"}
      </div>
    </div>
  );
}

// ── Page-level filter helper ─────────────────────────────────────────────
//
// When `proofOnly` is true, return only chains that have at least one
// CONFIRMED-confidence finding (`hasConfirmed: true`). Filter is operator-
// driven via a toggle on the page header.
export function filterToProofChains<T extends { hasConfirmed: boolean }>(
  paths:     T[],
  proofOnly: boolean,
): T[] {
  if (!proofOnly) return paths;
  return paths.filter((p) => p.hasConfirmed);
}

/**
 * Standalone "Proof of Exploit only" toggle chip — drop into the page
 * toolbar. Lifts state from the parent so the URL can persist the
 * choice via search params.
 */
export function ProofOnlyToggle({
  value,
  onChange,
  count,
  totalCount,
}: {
  value:      boolean;
  onChange:   (v: boolean) => void;
  count:      number;
  totalCount: number;
}) {
  return (
    <button
      type="button"
      onClick={() => onChange(!value)}
      className={`flex items-center gap-1.5 rounded-full border px-3 py-1.5 text-xs font-medium transition-colors ${
        value
          ? "border-red-700 bg-red-950/40 text-red-200 hover:border-red-600"
          : "border-gray-700 bg-gray-900 text-gray-300 hover:border-indigo-600"
      }`}
      title={
        value
          ? `Showing ${count} chain${count === 1 ? "" : "s"} with confirmed proof of exploit`
          : `Toggle to filter to chains with at least one CONFIRMED finding`
      }
    >
      {value ? <Flame className="h-3 w-3" /> : <AlertCircle className="h-3 w-3" />}
      Proof of exploit only
      <span
        className={`rounded-full px-1.5 py-0.5 text-[10px] tabular-nums ${
          value ? "bg-red-900/60 text-red-100" : "bg-gray-800 text-gray-400"
        }`}
      >
        {value ? count : totalCount}
      </span>
    </button>
  );
}
