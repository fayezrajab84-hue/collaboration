/**
 * AttackPathWorkflow — Phase 27.5.y AI-generated step-by-step attack walk.
 *
 * Renders the AI's ordered workflow as a HORIZONTAL flow chart: each step
 * is a card laid out left-to-right, connected to the next by a curved
 * bezier arrow. Visual goal: "graph + evidence... blocks with flow".
 *
 * Visual rebuild (post-feedback "looks ugly"):
 *   - Killed the saturated phase-colored top strip — too much heavy
 *     colour competing with severity-tinted evidence chips below it.
 *     Replaced with a muted card header (text-only phase + step number)
 *     and a 4px LEFT BORDER ACCENT in the phase colour. The accent
 *     colour-tags the card without flooding it.
 *   - Cards now stretch to equal height (flex items-stretch + flex-col
 *     body + mt-auto on chips block) so chips line up across cards.
 *   - Description text is smaller (text-[11px]) and tightly leading-snug
 *     so a 240-char step description fits 4-5 lines without overflowing.
 *   - Container has real left/right padding so the leftmost card
 *     doesn't clip against the edge on first render.
 *   - Arrows are beefier (stroke-3) with a stronger glow underlay so
 *     they read as "flow" rather than thin connectors.
 *
 * Geometry — measured, not approximated:
 *   - Each step card has a `ref`. useLayoutEffect reads each card's
 *     real `getBoundingClientRect()` after layout. Arrow paths anchor
 *     on the right edge of card N → left edge of card N+1.
 *   - ResizeObserver re-measures whenever any card OR the container
 *     resizes (chip lazy-load, browser resize, sidebar toggle).
 *
 * Why no graph library: pnpm install of reactflow hits the Windows
 * file-lock issue documented in CLAUDE.md (workspace symlink EACCES).
 * Hand-rolled SVG with measured bezier + gradient stops ships zero
 * new bundle weight.
 */
import { useEffect, useLayoutEffect, useMemo, useRef, useState } from "react";
import { Code2, Box, Globe, Activity, ShieldAlert, Flame } from "lucide-react";
import type { AttackPathNode, WorkflowStep } from "@devsecops/types";

// ── Phase taxonomy (mirrors AttackPathFlow) ─────────────────────────────

type Phase = WorkflowStep["phase"];

// ── Brand-aligned palette ───────────────────────────────────────────────
// Per `breachlens-brand-colors.md`: brand-indigo across the board; drop
// teal/amber/rose for new UI. We were using rose-500 for runtime — fixed.
//
// New story: source/image/surface use varying indigo shades (the "lab"
// tiers — code, image, scanned surface). Runtime is the ONE red callout
// (the "production / live attack" tier). The dramatic colour transition
// happens at the surface→runtime arrow: that's where the chain shifts
// from "we tested it" to "production observed it". Severity-red chips
// inside cards now operate on a different axis from the card's phase
// accent — no more visual collision.
const PHASE_DEF: Record<Phase, {
  label:        string;
  Icon:         typeof Code2;
  /** Arrow gradient stop colour. Keep aligned with the accent shade. */
  stopColor:    string;
  /** Tailwind class for the 4-px left border accent. */
  accentBorder: string;
  /** Phase text colour for the header chip. */
  accentText:   string;
}> = {
  source: {
    label:        "Source",
    Icon:         Code2,
    stopColor:    "#4f46e5",        // indigo-600
    accentBorder: "border-l-indigo-600",
    accentText:   "text-indigo-300",
  },
  image: {
    label:        "Image",
    Icon:         Box,
    stopColor:    "#6366f1",        // indigo-500
    accentBorder: "border-l-indigo-500",
    accentText:   "text-indigo-300",
  },
  surface: {
    label:        "Surface",
    Icon:         Globe,
    stopColor:    "#818cf8",        // indigo-400
    accentBorder: "border-l-indigo-400",
    accentText:   "text-indigo-200",
  },
  runtime: {
    label:        "Runtime",
    Icon:         Activity,
    stopColor:    "#ef4444",        // red-500 — sole red callout in the workflow
    accentBorder: "border-l-red-500",
    accentText:   "text-red-300",
  },
};

const SEV_CHIP: Record<string, string> = {
  CRITICAL: "border-red-700/50    bg-red-950/30   text-red-300",
  HIGH:     "border-red-700/40    bg-red-950/20   text-red-300/90",
  MEDIUM:   "border-indigo-700/40 bg-indigo-950/30 text-indigo-200",
  LOW:      "border-gray-700      bg-gray-900/40 text-gray-300",
  INFO:     "border-gray-800      bg-gray-900/30 text-gray-400",
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
  const nodeById = useMemo(() => new Map(nodes.map((n) => [n.findingId, n])), [nodes]);

  // Pre-compute PoE state per step. Three states (none / direct / linked)
  // capture the operator-facing distinction that "the step's own evidence
  // is CONFIRMED" is stronger proof than "the step corroborates a
  // CONFIRMED exploit elsewhere in the chain". Both deserve a flame
  // badge — the chain IS proven — but they earn different weight in
  // the UI (filled vs outlined chip + different tooltip).
  //
  // Why widen: the original rule (direct only) left RUNTIME steps
  // without a flame even when an upstream PENTEST CONFIRMED exploit +
  // Wazuh LIKELY runtime alert together prove live exploitation. Two
  // independent telemetry streams converging on the same conclusion
  // IS proof, even if neither qualifies alone. Narrowed to the
  // PENTEST/DAST→RUNTIME pattern only — SAST/CONTAINER CONFIRMED
  // upstream does NOT propagate, because static-analysis CONFIRMED
  // means "vulnerability exists" not "it's being exploited".
  //
  // Hooks must run in the same order on every render — keep above any
  // early return.
  const stepPoE = useMemo<("none" | "direct" | "linked")[]>(() => {
    const chainHasExploitProof = nodes.some(
      (n) =>
        n.confidence === "CONFIRMED" &&
        (n.scanType === "PENTEST_FULL" || n.scanType === "DAST"),
    );
    return workflow.map((step) => {
      const directPoE = step.evidenceFindingIds.some(
        (id) => nodeById.get(id)?.confidence === "CONFIRMED",
      );
      if (directPoE) return "direct";
      if (
        step.phase === "runtime" &&
        chainHasExploitProof &&
        step.evidenceFindingIds.length > 0
      ) {
        return "linked";
      }
      return "none";
    });
  }, [workflow, nodeById, nodes]);

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

      <FlowCanvas workflow={workflow} stepPoE={stepPoE} nodeById={nodeById} onOpenFinding={onOpenFinding} />
    </div>
  );
}

// ── Flow canvas — measured layout, SVG arrows ────────────────────────────

type PoEStatus = "none" | "direct" | "linked";

interface ArrowGeom {
  from:    number;
  to:      number;
  d:       string;
  /** Whether the destination step has PoE — drives the pulse animation.
   *  Both "direct" and "linked" pulse; the visual distinction lives in
   *  the chip on the card, not the arrow. */
  toIsPoE: boolean;
}

function FlowCanvas({
  workflow,
  stepPoE,
  nodeById,
  onOpenFinding,
}: {
  workflow:      WorkflowStep[];
  stepPoE:       PoEStatus[];
  nodeById:      Map<string, AttackPathNode>;
  onOpenFinding: (findingId: string) => void;
}) {
  const containerRef = useRef<HTMLDivElement | null>(null);
  const trackRef     = useRef<HTMLDivElement | null>(null);
  const stepRefs     = useRef<Array<HTMLDivElement | null>>([]);
  const [arrows, setArrows] = useState<ArrowGeom[]>([]);
  const [dims, setDims]     = useState<{ w: number; h: number }>({ w: 0, h: 0 });

  // Measure step positions and (re-)compute arrow paths whenever:
  //   - layout settles after first render
  //   - container width changes (e.g. window resize, sidebar toggle)
  //   - step count changes (rare — workflow regen)
  // Coordinates are relative to the TRACK div (which holds both the cards
  // and the SVG arrow layer), NOT the outer scroll container. This way
  // the SVG and cards stay aligned regardless of horizontal scroll.
  useLayoutEffect(() => {
    const measure = () => {
      const track = trackRef.current;
      if (!track) return;
      const tBox = track.getBoundingClientRect();
      const positions = stepRefs.current.map((el) => {
        if (!el) return null;
        const r = el.getBoundingClientRect();
        return {
          left:   r.left   - tBox.left,
          right:  r.right  - tBox.left,
          midY:   r.top    - tBox.top + r.height / 2,
        };
      });

      const next: ArrowGeom[] = [];
      for (let i = 0; i < positions.length - 1; i++) {
        const a = positions[i];
        const b = positions[i + 1];
        if (!a || !b) continue;
        const x1 = a.right;
        const y1 = a.midY;
        const x2 = b.left;
        const y2 = b.midY;
        // Horizontal cubic bezier: control points pulled to the
        // midpoint X with the same Y as their endpoints. Looks "flowy"
        // even when both endpoints are at the same height.
        const midX = (x1 + x2) / 2;
        const d = `M ${x1} ${y1} C ${midX} ${y1}, ${midX} ${y2}, ${x2} ${y2}`;
        next.push({
          from: i,
          to: i + 1,
          d,
          // Pulse for both direct + linked PoE. Both convey "this
          // chain has confirmed proof"; the chip on the card carries
          // the direct-vs-linked nuance.
          toIsPoE: (stepPoE[i + 1] ?? "none") !== "none",
        });
      }
      setArrows(next);
      setDims({ w: track.scrollWidth, h: track.scrollHeight });
    };

    measure();
    const ro = new ResizeObserver(measure);
    if (trackRef.current) ro.observe(trackRef.current);
    for (const el of stepRefs.current) {
      if (el) ro.observe(el);
    }
    return () => ro.disconnect();
  }, [workflow.length, stepPoE]);

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
      // Horizontal scroll container. p-1 around the track gives the
      // cards a small breathing-room margin from the rounded panel
      // edge so the leftmost card never clips against the border.
      className="relative -mx-1 overflow-x-auto pb-2"
    >
      <div
        ref={trackRef}
        className="relative flex items-stretch gap-10 px-2 pb-1"
        style={{ minWidth: "fit-content" }}
      >
        {workflow.map((step, i) => (
          <StepCard
            key={step.stepNumber}
            step={step}
            poe={stepPoE[i] ?? "none"}
            innerRef={(el) => { stepRefs.current[i] = el; }}
            nodeById={nodeById}
            onOpenFinding={onOpenFinding}
          />
        ))}

        {/* Arrow layer — covers the track. overflow visible so arrowheads
            can poke a few pixels past the bbox without clipping. */}
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
                  <stop offset="0%"   stopColor={PHASE_DEF[fromPhase].stopColor} stopOpacity="0.95" />
                  <stop offset="100%" stopColor={PHASE_DEF[toPhase].stopColor}   stopOpacity="1.0"  />
                </linearGradient>
              );
            })}
            {arrows.map((a) => (
              <marker
                key={`m-${a.to}`}
                id={`wf-arrow-${a.to}`}
                viewBox="0 0 12 12"
                refX="10"
                refY="6"
                markerWidth="6"
                markerHeight="6"
                orient="auto"
              >
                <path d="M 0 0 L 12 6 L 0 12 L 3 6 z" fill={PHASE_DEF[workflow[a.to]!.phase].stopColor} />
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
  return (
    <g>
      {/* Glow underlay — same path, wider, low opacity. Adds depth
          without colour-shifting the gradient. Calibrated to operator
          feedback: 14px was "too huge", 9px was "too quiet". 10px @
          0.28 hits the readable middle. */}
      <path
        d={d}
        stroke={`url(#wf-grad-${fromIdx})`}
        strokeWidth={10}
        strokeLinecap="round"
        fill="none"
        opacity={0.28}
      />
      {/* Main stroke. PoE-target arrows pulse via CSS-keyframe class.
          2.75px is the sweet spot — beefy enough that the gradient
          reads, restrained enough that it doesn't compete with cards. */}
      <path
        d={d}
        stroke={`url(#wf-grad-${fromIdx})`}
        strokeWidth={2.75}
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
  poe,
  innerRef,
  nodeById,
  onOpenFinding,
}: {
  step:          WorkflowStep;
  poe:           PoEStatus;
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
      // cards under tight layouts. flex-col + items-stretch on the
      // parent makes all cards equal height; mt-auto on the chip
      // block pushes evidence to the bottom across heights.
      className={`relative flex w-72 shrink-0 flex-col rounded-lg border border-gray-800 border-l-4 bg-gray-900/60 ${def.accentBorder} shadow-sm shadow-black/40`}
    >
      {/* Header row: phase + step number + technique + PoE flame.
          Single-line, low chrome — phase colour comes from the LEFT
          BORDER and the icon/text, not a heavy filled strip. */}
      <div className="flex items-center justify-between border-b border-gray-800/70 px-3 py-2">
        <div className={`flex items-center gap-1.5 text-[11px] font-semibold uppercase tracking-wide ${def.accentText}`}>
          <PhaseIcon className="h-3.5 w-3.5" />
          {def.label}
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
          {poe !== "none" && (
            <span
              className={
                poe === "direct"
                  // Filled red — this step's own evidence is CONFIRMED.
                  ? "flex items-center gap-1 rounded border border-red-600/60 bg-red-950/60 px-1.5 py-0.5 text-[9px] font-bold text-red-200"
                  // Outlined red — this step corroborates a CONFIRMED
                  // exploit elsewhere in the chain (e.g. RUNTIME alerts
                  // matching a CONFIRMED PENTEST exploit). Same alarm
                  // colour, lighter visual weight to signal "linked
                  // proof, not own proof".
                  : "flex items-center gap-1 rounded border border-red-600/70 bg-transparent px-1.5 py-0.5 text-[9px] font-bold text-red-300"
              }
              title={
                poe === "direct"
                  ? "Backed by a CONFIRMED Proof-of-Exploit finding in this step"
                  : "Corroborates a CONFIRMED PENTEST/DAST exploit elsewhere in this chain"
              }
            >
              <Flame className="h-2.5 w-2.5" />
              {poe === "direct" ? "POE" : "POE↗"}
            </span>
          )}
          <span className="rounded-full bg-gray-800 px-1.5 py-0.5 text-[10px] font-semibold text-gray-300">
            {step.stepNumber}
          </span>
        </div>
      </div>

      {/* Title + description */}
      <div className="px-3 pt-3">
        <div className="mb-1.5 text-[13px] font-semibold leading-snug text-gray-100">
          {step.title}
        </div>
        <div className="text-[11px] leading-snug text-gray-400">
          {step.description}
        </div>
      </div>

      {/* Evidence chips. mt-auto pushes them to the card bottom so a
          row of mismatched-height cards still has chips aligned. */}
      <div className="mt-auto flex flex-wrap gap-1.5 px-3 pb-3 pt-3">
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
  // Smart label: lead with packageName@version for package-based findings.
  // Reason: Trivy-style titles ("openssl 3.5.5-1 — 7 vulns") collapse across
  // binary packages that share the same source version — DVWA has
  // libssl3t64 + openssl + openssl-provider-legacy all titled identically,
  // and the differentiator lives in `packageName`, not the title. Leading
  // with packageName makes those chips visually distinct without bumping
  // the truncation budget. Falls back to truncated title for SAST/PENTEST/
  // DAST/RUNTIME findings (no packageName).
  const label = (() => {
    if (node.packageName) {
      const v = node.packageVersion ? `@${node.packageVersion}` : "";
      return `${node.packageName}${v}`;
    }
    return node.title.length > 56 ? `${node.title.slice(0, 54)}…` : node.title;
  })();

  return (
    <button
      type="button"
      onClick={onClick}
      className={`inline-flex max-w-full items-center gap-1.5 rounded border px-1.5 py-1 text-[10px] transition-all hover:brightness-125 hover:shadow ${sevClass}`}
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
