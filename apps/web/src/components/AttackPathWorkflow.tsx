/**
 * AttackPathWorkflow — Phase 27.5.y AI-generated step-by-step attack walk.
 *
 * Renders the AI's ordered workflow as a HORIZONTAL flow chart: each step
 * is a card laid out left-to-right, connected to the next by a curved
 * bezier arrow with phase-transition gradient stops + arrowhead. This is
 * the visual the user asked for: "graph + evidence... blocks with flow".
 *
 * Why horizontal:
 *   - reads as a kill-chain timeline (entry on the left, deepest impact
 *     on the right) which mirrors how attackers actually walk a target
 *   - 3-6 cards laid horizontally fit a typical wide chain card without
 *     wrapping; on narrow viewports the container scrolls horizontally
 *   - arrows-between-cards is more "diagram"-like than a numbered list
 *     with a single vertical connector
 *
 * Geometry — measured, not approximated:
 *   - Each step card has a `ref` so we can read its real `offsetLeft` /
 *     `offsetWidth` after layout. Arrow paths anchor on those measured
 *     positions, so they always land exactly on the right edge of card
 *     N and the left edge of card N+1.
 *   - A ResizeObserver re-measures when the chain card's container
 *     changes width (e.g. operator drags the browser window) so arrows
 *     don't drift out of sync with the cards.
 *   - The SVG canvas spans the full row and has `overflow: visible` so
 *     arrows can poke a few pixels outside their bounding box without
 *     being clipped.
 *
 * Visual polish:
 *   - Phase colours mirror AttackPathFlow (source/image=indigo,
 *     surface/runtime=red) so the operator's eye carries from one
 *     component to the next.
 *   - Each step card has a phase-coloured top strip + step-number badge
 *     in the corner.
 *   - Arrows use a per-arrow linearGradient (source-phase → dest-phase
 *     stops) so the colour transition is visible mid-arrow.
 *   - Arrows ENTERING a step backed by a CONFIRMED Proof-of-Exploit
 *     finding pulse subtly via a CSS animation — operator's eye lands
 *     on proof-bearing transitions first.
 *   - On mount, arrows draw themselves left-to-right via stroke-
 *     dasharray animation. Reinforces the kill-chain reading order.
 *
 * Why not import a graph library: pnpm install of reactflow hit the
 * Windows file-lock issue documented in CLAUDE.md (workspace symlink
 * EACCES). Hand-rolled SVG with curved bezier + gradient stops is
 * plenty for a 3-6-step linear flow and ships zero new bundle weight.
 */
import { useEffect, useLayoutEffect, useMemo, useRef, useState } from "react";
import { Code2, Box, Globe, Activity, ShieldAlert, Flame } from "lucide-react";
import type { AttackPathNode, WorkflowStep } from "@devsecops/types";

// ── Phase taxonomy (mirrors AttackPathFlow) ─────────────────────────────

type Phase = WorkflowStep["phase"];

const PHASE_DEF: Record<Phase, {
  label:        string;
  Icon:         typeof Code2;
  /** Arrow gradient stop colour. Keep in sync with AttackPathFlow. */
  stopColor:    string;
  /** Header strip background — picks up the phase tone strongly so the
   *  operator can phase-tag a card at-a-glance even with the strip
   *  collapsed off-screen. */
  stripClass:   string;
  /** Step-number badge inside the strip. */
  badgeClass:   string;
  /** Card body background — phase-tinted but mostly neutral so the
   *  evidence chips inside don't clash with the colour palette. */
  bodyClass:    string;
}> = {
  source: {
    label:      "Source",
    Icon:       Code2,
    stopColor:  "#6366f1",        // indigo-500
    stripClass: "bg-indigo-900/50 border-indigo-600/60",
    badgeClass: "bg-indigo-700 text-white",
    bodyClass:  "bg-indigo-950/15 border-indigo-900/40",
  },
  image: {
    label:      "Image",
    Icon:       Box,
    stopColor:  "#818cf8",        // indigo-400
    stripClass: "bg-indigo-800/50 border-indigo-500/60",
    badgeClass: "bg-indigo-600 text-white",
    bodyClass:  "bg-indigo-950/10 border-indigo-900/30",
  },
  surface: {
    label:      "Surface",
    Icon:       Globe,
    stopColor:  "#dc2626",        // red-600
    stripClass: "bg-red-900/50 border-red-600/60",
    badgeClass: "bg-red-700 text-white",
    bodyClass:  "bg-red-950/15 border-red-900/40",
  },
  runtime: {
    label:      "Runtime",
    Icon:       Activity,
    stopColor:  "#f87171",        // red-400 (lighter — runtime is "live")
    stripClass: "bg-red-800/55 border-red-500/60",
    badgeClass: "bg-red-600 text-white",
    bodyClass:  "bg-red-950/20 border-red-900/40",
  },
};

const SEV_CHIP: Record<string, string> = {
  CRITICAL: "border-red-700/70   bg-red-950/40 text-red-300",
  HIGH:     "border-red-700/50   bg-red-950/30 text-red-300/90",
  MEDIUM:   "border-indigo-700/50 bg-indigo-950/40 text-indigo-200",
  LOW:      "border-gray-700     bg-gray-900/40 text-gray-300",
  INFO:     "border-gray-800     bg-gray-900/30 text-gray-400",
};

// ── Component ────────────────────────────────────────────────────────────

export default function AttackPathWorkflow({
  workflow,
  nodes,
  onOpenFinding,
}: {
  workflow:      WorkflowStep[];
  nodes:         AttackPathNode[];
  /** Open a finding in the drawer. Wired up by the parent page so
   *  this component stays presentational + shareable across pages. */
  onOpenFinding: (findingId: string) => void;
}) {
  // Index nodes by ID for evidence-chip lookup (O(steps × evidence) walks
  // vs O(n) per chip).
  const nodeById = useMemo(() => new Map(nodes.map((n) => [n.findingId, n])), [nodes]);

  // Pre-compute "step has CONFIRMED evidence" so arrows entering a PoE
  // step can pulse without each arrow re-walking the evidence list.
  // NOTE: keep this above any early return — hooks must run in the
  // same order on every render.
  const stepHasPoE = useMemo(() => {
    return workflow.map((step) =>
      step.evidenceFindingIds.some((id) => nodeById.get(id)?.confidence === "CONFIRMED"),
    );
  }, [workflow, nodeById]);

  if (workflow.length === 0) return null;

  return (
    <div className="rounded-lg border border-gray-800 bg-gray-950/60 p-4">
      <div className="mb-4 flex items-center gap-2">
        <span className="text-[10px] font-semibold uppercase tracking-wider text-gray-500">
          Attack workflow
        </span>
        <span className="text-[10px] text-gray-600">·</span>
        <span className="text-[10px] text-gray-500">
          {workflow.length} step{workflow.length === 1 ? "" : "s"}, AI-generated and grounded in evidence
        </span>
      </div>

      <FlowCanvas workflow={workflow} stepHasPoE={stepHasPoE} nodeById={nodeById} onOpenFinding={onOpenFinding} />
    </div>
  );
}

// ── Flow canvas — measured layout, SVG arrows ────────────────────────────

interface ArrowGeom {
  /** Leaving step index (0-based) */
  from:    number;
  /** Entering step index */
  to:      number;
  /** SVG `d` path (cubic bezier, screen-space px) */
  d:       string;
  /** True when the destination step has CONFIRMED evidence — drives
   *  the pulse animation. */
  toIsPoE: boolean;
}

function FlowCanvas({
  workflow,
  stepHasPoE,
  nodeById,
  onOpenFinding,
}: {
  workflow:      WorkflowStep[];
  stepHasPoE:    boolean[];
  nodeById:      Map<string, AttackPathNode>;
  onOpenFinding: (findingId: string) => void;
}) {
  const containerRef = useRef<HTMLDivElement | null>(null);
  const stepRefs     = useRef<Array<HTMLDivElement | null>>([]);
  const [arrows, setArrows] = useState<ArrowGeom[]>([]);
  const [dims, setDims]     = useState<{ w: number; h: number }>({ w: 0, h: 0 });

  // Measure step positions and (re-)compute arrow paths whenever:
  //   - layout settles after first render
  //   - container width changes (e.g. window resize, sidebar toggle)
  //   - step count changes (rare — workflow regen)
  // Arrows are anchored on each card's RIGHT-MIDDLE → next card's
  // LEFT-MIDDLE so they always look "between cards" regardless of
  // card height differences.
  useLayoutEffect(() => {
    const measure = () => {
      const container = containerRef.current;
      if (!container) return;
      const cBox = container.getBoundingClientRect();
      const setW = container.scrollWidth;
      const positions = stepRefs.current.map((el) => {
        if (!el) return null;
        const r = el.getBoundingClientRect();
        return {
          left:   r.left   - cBox.left,
          right:  r.right  - cBox.left,
          top:    r.top    - cBox.top,
          bottom: r.bottom - cBox.top,
          midY:   r.top    - cBox.top + r.height / 2,
        };
      });

      const next: ArrowGeom[] = [];
      for (let i = 0; i < positions.length - 1; i++) {
        const a = positions[i];
        const b = positions[i + 1];
        if (!a || !b) continue;
        // Anchor: right-middle of A → left-middle of B. Curve via
        // cubic bezier with control points pulled to the midpoint X
        // and a slight vertical wiggle so the arrow looks "drawn"
        // rather than a straight horizontal line.
        const x1 = a.right;
        const y1 = a.midY;
        const x2 = b.left;
        const y2 = b.midY;
        const midX = (x1 + x2) / 2;
        const c1x = midX;
        const c1y = y1;
        const c2x = midX;
        const c2y = y2;
        const d = `M ${x1} ${y1} C ${c1x} ${c1y}, ${c2x} ${c2y}, ${x2} ${y2}`;
        next.push({ from: i, to: i + 1, d, toIsPoE: stepHasPoE[i + 1] ?? false });
      }
      setArrows(next);
      setDims({ w: setW, h: container.scrollHeight });
    };

    measure();
    // Re-measure on any container resize.
    const ro = new ResizeObserver(measure);
    if (containerRef.current) ro.observe(containerRef.current);
    // Cards' children (chips) load async — observe each card too so
    // the arrows snap when content reflows.
    for (const el of stepRefs.current) {
      if (el) ro.observe(el);
    }
    return () => ro.disconnect();
  }, [workflow.length, stepHasPoE]);

  // Tick to run the entrance animation. Forces a re-render after first
  // paint with `animateIn = true` so the stroke-dasharray transition
  // kicks off (instant transitions don't animate).
  const [animateIn, setAnimateIn] = useState(false);
  useEffect(() => {
    const t = setTimeout(() => setAnimateIn(true), 30);
    return () => clearTimeout(t);
  }, [arrows.length]);

  return (
    <div
      ref={containerRef}
      // overflow-x-auto: horizontal scroll on narrow viewports rather
      // than wrapping (wrapping breaks the kill-chain reading order).
      // pb-1 gives the scrollbar breathing room so it doesn't crowd
      // the bottom edge of the cards.
      className="relative overflow-x-auto pb-1"
    >
      <div className="relative flex items-stretch gap-12 px-1" style={{ minWidth: "fit-content" }}>
        {workflow.map((step, i) => (
          <StepCard
            key={step.stepNumber}
            step={step}
            hasPoE={stepHasPoE[i] ?? false}
            innerRef={(el) => { stepRefs.current[i] = el; }}
            nodeById={nodeById}
            onOpenFinding={onOpenFinding}
          />
        ))}

        {/* Arrow layer — sits absolute over the row. Its bounding box
            matches the row's content width + height so SVG coordinates
            stay in pixel-space with the measured anchor points. */}
        <svg
          className="pointer-events-none absolute inset-0"
          width={dims.w}
          height={dims.h}
          style={{ overflow: "visible" }}
          aria-hidden="true"
        >
          <defs>
            {arrows.map((a) => {
              const fromPhase = workflow[a.from]!.phase;
              const toPhase   = workflow[a.to]!.phase;
              return (
                <linearGradient
                  key={`g-${a.from}`}
                  id={`wf-grad-${a.from}`}
                  x1="0%" y1="0%" x2="100%" y2="0%"
                >
                  <stop offset="0%"   stopColor={PHASE_DEF[fromPhase].stopColor} stopOpacity="0.85" />
                  <stop offset="100%" stopColor={PHASE_DEF[toPhase].stopColor}   stopOpacity="1.0"  />
                </linearGradient>
              );
            })}
            {arrows.map((a) => (
              <marker
                key={`m-${a.to}`}
                id={`wf-arrow-${a.to}`}
                viewBox="0 0 10 10"
                refX="9"
                refY="5"
                markerWidth="6"
                markerHeight="6"
                orient="auto"
              >
                <path d="M 0 0 L 10 5 L 0 10 z" fill={PHASE_DEF[workflow[a.to]!.phase].stopColor} />
              </marker>
            ))}
          </defs>
          {arrows.map((a) => (
            <ArrowPath
              key={`p-${a.from}-${a.to}`}
              d={a.d}
              fromIdx={a.from}
              toIdx={a.to}
              toIsPoE={a.toIsPoE}
              animateIn={animateIn}
            />
          ))}
        </svg>
      </div>
    </div>
  );
}

// ── Arrow path — animated draw-on + optional PoE pulse ───────────────────

function ArrowPath({
  d, fromIdx, toIdx, toIsPoE, animateIn,
}: {
  d:         string;
  fromIdx:   number;
  toIdx:     number;
  toIsPoE:   boolean;
  animateIn: boolean;
}) {
  // pathLength normalizes the dash math regardless of actual length so
  // the entrance animation duration is consistent across short + long
  // bezier curves. We feed a fake pathLength of 100 and dash from 0 →
  // 100 — equivalent to drawing the whole stroke over the transition.
  return (
    <g>
      {/* Soft glow underlay — same path, wider stroke, low opacity.
          Adds depth without colour-shifting the gradient. */}
      <path
        d={d}
        stroke={`url(#wf-grad-${fromIdx})`}
        strokeWidth={6}
        strokeLinecap="round"
        fill="none"
        opacity={0.18}
      />
      {/* Main stroke. PoE-target arrows pulse via CSS-keyframe class. */}
      <path
        d={d}
        stroke={`url(#wf-grad-${fromIdx})`}
        strokeWidth={2.25}
        strokeLinecap="round"
        fill="none"
        markerEnd={`url(#wf-arrow-${toIdx})`}
        pathLength={100}
        strokeDasharray={100}
        strokeDashoffset={animateIn ? 0 : 100}
        style={{
          transition: "stroke-dashoffset 0.7s ease-out",
          transitionDelay: `${fromIdx * 0.18}s`,
        }}
        className={toIsPoE ? "wf-arrow-poe" : undefined}
      />
    </g>
  );
}

// ── Step card ────────────────────────────────────────────────────────────

function StepCard({
  step,
  hasPoE,
  innerRef,
  nodeById,
  onOpenFinding,
}: {
  step:          WorkflowStep;
  hasPoE:        boolean;
  innerRef:      (el: HTMLDivElement | null) => void;
  nodeById:      Map<string, AttackPathNode>;
  onOpenFinding: (findingId: string) => void;
}) {
  const def = PHASE_DEF[step.phase];
  const PhaseIcon = def.Icon;

  return (
    <div
      ref={innerRef}
      // Fixed width keeps the row geometry predictable for the SVG
      // arrow math; flex-shrink-0 prevents the row from compressing
      // cards under tight layouts.
      className={`relative w-72 shrink-0 rounded-lg border ${def.bodyClass} shadow-sm shadow-black/30`}
    >
      {/* Phase strip + step number badge */}
      <div className={`flex items-center justify-between rounded-t-lg border-b px-3 py-1.5 ${def.stripClass}`}>
        <div className="flex items-center gap-2">
          <span className={`flex h-5 w-5 items-center justify-center rounded-full text-[10px] font-bold ${def.badgeClass}`}>
            {step.stepNumber}
          </span>
          <span className="flex items-center gap-1 text-[11px] font-semibold uppercase tracking-wide text-white">
            <PhaseIcon className="h-3 w-3" />
            {def.label}
          </span>
        </div>
        <div className="flex items-center gap-1.5">
          {step.technique && (
            <span
              className="flex items-center gap-1 rounded border border-gray-700 bg-gray-900/80 px-1.5 py-0.5 font-mono text-[9px] text-gray-300"
              title={`MITRE ATT&CK ${step.technique}`}
            >
              <ShieldAlert className="h-2.5 w-2.5" />
              {step.technique}
            </span>
          )}
          {hasPoE && (
            <span
              className="flex items-center gap-1 rounded border border-red-600/70 bg-red-950/80 px-1.5 py-0.5 text-[9px] font-bold text-red-200"
              title="This step is backed by a CONFIRMED Proof-of-Exploit finding"
            >
              <Flame className="h-2.5 w-2.5" />
              POE
            </span>
          )}
        </div>
      </div>

      {/* Title + description */}
      <div className="px-3 pt-2">
        <div className="mb-1 text-sm font-semibold leading-snug text-gray-100">{step.title}</div>
        <div className="text-xs leading-relaxed text-gray-400">{step.description}</div>
      </div>

      {/* Evidence chips */}
      <div className="flex flex-wrap gap-1.5 px-3 pb-3 pt-2">
        {step.evidenceFindingIds.map((id) => {
          const node = nodeById.get(id);
          if (!node) return null;
          return <EvidenceChip key={id} node={node} onClick={() => onOpenFinding(id)} />;
        })}
      </div>
    </div>
  );
}

// ── Evidence chip ────────────────────────────────────────────────────────

function EvidenceChip({
  node,
  onClick,
}: {
  node:    AttackPathNode;
  onClick: () => void;
}) {
  const sevClass = SEV_CHIP[node.severity] ?? SEV_CHIP["INFO"]!;
  const label = node.title.length > 48 ? `${node.title.slice(0, 46)}…` : node.title;

  return (
    <button
      type="button"
      onClick={onClick}
      className={`inline-flex max-w-full items-center gap-1.5 rounded border px-2 py-1 text-[11px] transition-all hover:brightness-125 hover:shadow ${sevClass}`}
      title={`Open ${node.scanType} finding: ${node.title}`}
    >
      <span className="font-mono text-[9px] uppercase opacity-70">
        {node.scanType.replace("PENTEST_FULL", "PENTEST")}
      </span>
      <span className="truncate">{label}</span>
      {node.confidence === "CONFIRMED" && (
        <span className="rounded bg-red-900/60 px-1 text-[9px] font-semibold text-red-200">
          POE
        </span>
      )}
    </button>
  );
}
