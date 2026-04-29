/**
 * AttackPathWorkflow — Phase 27.5.y AI-generated step-by-step attack walk.
 *
 * Renders the AI's ordered workflow as a visual flow chart: each step is
 * a card connected to the next by a curved SVG arrow. Phase colours match
 * AttackPathFlow's block diagram (source/image=indigo, surface/runtime=red)
 * so the operator's eye carries from one component to the next.
 *
 * Layout: vertical flow (step 1 at top, step N at bottom). The arrow
 * between adjacent steps is rendered as an SVG path that:
 *   - curves from the bottom of the previous step's circle to the top of
 *     the next step's circle (gives the "branching/flowing" feel)
 *   - colours by phase TRANSITION — gradient from source-phase color to
 *     destination-phase color so an operator can read the kill-chain
 *     progression at a glance
 *   - terminates with an arrowhead marker
 *
 * Vertical (rather than horizontal) is deliberate:
 *   - 3-6 steps fits naturally in the chain card's expanded view without
 *     horizontal scrolling
 *   - a step's evidence-chip cluster wants more horizontal room than
 *     a column-narrow card would give it
 *   - it reads top-to-bottom like a runbook
 *
 * Why not import a graph library: pnpm install hits the Windows
 * file-lock issue documented in CLAUDE.md. SVG-by-hand is plenty for a
 * 3-6 step linear flow and ships zero new bundle weight.
 */
import { Code2, Box, Globe, Activity, ShieldAlert, Flame } from "lucide-react";
import type { AttackPathNode, WorkflowStep } from "@devsecops/types";

// ── Phase taxonomy (mirrors AttackPathFlow) ─────────────────────────────

type Phase = WorkflowStep["phase"];

const PHASE_DEF: Record<Phase, {
  label:        string;
  Icon:         typeof Code2;
  /** Stop colour for the SVG gradient — used at both the card border and
   *  the arrow leaving this phase. Keep these in sync with the same
   *  phase colours in AttackPathFlow.tsx. */
  stopColor:    string;
  /** Tailwind utility classes for the step circle (border + bg + text). */
  circleClass:  string;
  /** Tailwind utility classes for the phase chip in card header. */
  chipClass:    string;
  /** Light bg behind the card body, picks up the phase tone subtly. */
  bodyBgClass:  string;
}> = {
  source: {
    label:       "Source",
    Icon:        Code2,
    stopColor:   "#6366f1",     // indigo-500
    circleClass: "border-indigo-500 bg-indigo-950/60 text-indigo-200",
    chipClass:   "bg-indigo-950/60 text-indigo-200 border-indigo-700/60",
    bodyBgClass: "bg-indigo-950/15",
  },
  image: {
    label:       "Image",
    Icon:        Box,
    stopColor:   "#818cf8",     // indigo-400
    circleClass: "border-indigo-400 bg-indigo-950/50 text-indigo-200",
    chipClass:   "bg-indigo-950/50 text-indigo-200 border-indigo-700/50",
    bodyBgClass: "bg-indigo-950/10",
  },
  surface: {
    label:       "Surface",
    Icon:        Globe,
    stopColor:   "#dc2626",     // red-600
    circleClass: "border-red-600 bg-red-950/60 text-red-200",
    chipClass:   "bg-red-950/60 text-red-200 border-red-700/60",
    bodyBgClass: "bg-red-950/15",
  },
  runtime: {
    label:       "Runtime",
    Icon:        Activity,
    stopColor:   "#f87171",     // red-400 (lighter — runtime is "live")
    circleClass: "border-red-500 bg-red-950/70 text-red-200",
    chipClass:   "bg-red-950/70 text-red-200 border-red-600/60",
    bodyBgClass: "bg-red-950/20",
  },
};

// ── Severity → chip color (matches the rest of the app) ─────────────────

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
  // Index nodes by ID once for evidence-chip lookup (O(steps × evidence)
  // walks vs O(n) scan per chip).
  const nodeById = new Map(nodes.map((n) => [n.findingId, n]));

  if (workflow.length === 0) return null;

  // Pre-compute "step has CONFIRMED evidence" — lights up the flame badge
  // so the operator's eye lands on proof-bearing steps first.
  const stepHasPoE = (step: WorkflowStep) =>
    step.evidenceFindingIds.some((id) => nodeById.get(id)?.confidence === "CONFIRMED");

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

      <div className="relative">
        {/* SVG layer for connector arrows. Sits absolutely behind the
            step cards. Each connector is a curved bezier from the
            previous step circle's bottom to the next step circle's top.
            */}
        <FlowConnectors workflow={workflow} />

        <ol className="relative space-y-5">
          {workflow.map((step, i) => (
            <Step
              key={step.stepNumber}
              step={step}
              isLast={i === workflow.length - 1}
              hasPoE={stepHasPoE(step)}
              nodeById={nodeById}
              onOpenFinding={onOpenFinding}
            />
          ))}
        </ol>
      </div>
    </div>
  );
}

// ── Connector arrows (SVG layer) ─────────────────────────────────────────
//
// Drawn behind the cards using absolute positioning + percent
// coordinates. The arrow goes from approximately the left edge below
// step (i)'s circle to the left edge above step (i+1)'s circle, with
// a slight bezier curve so it doesn't look like a straight line.
//
// The only thing that's actually phase-colour-aware is the gradient
// stops; the path geometry itself is reusable.

function FlowConnectors({ workflow }: { workflow: WorkflowStep[] }) {
  if (workflow.length < 2) return null;

  return (
    <svg
      className="pointer-events-none absolute inset-0 h-full w-full"
      preserveAspectRatio="none"
      aria-hidden="true"
    >
      {/* One arrowhead marker per step pair — coloured by destination
          phase so the arrow visually "lands" in the next phase's hue. */}
      <defs>
        {workflow.slice(1).map((step) => (
          <marker
            key={`arrow-${step.stepNumber}`}
            id={`wf-arrow-${step.stepNumber}`}
            viewBox="0 0 10 10"
            refX="8"
            refY="5"
            markerWidth="6"
            markerHeight="6"
            orient="auto"
          >
            <path d="M 0 0 L 10 5 L 0 10 z" fill={PHASE_DEF[step.phase].stopColor} />
          </marker>
        ))}
        {workflow.slice(0, -1).map((step, i) => {
          const next = workflow[i + 1]!;
          return (
            <linearGradient
              key={`grad-${step.stepNumber}`}
              id={`wf-grad-${step.stepNumber}`}
              x1="0%" y1="0%" x2="0%" y2="100%"
            >
              <stop offset="0%"  stopColor={PHASE_DEF[step.phase].stopColor} stopOpacity="0.7" />
              <stop offset="100%" stopColor={PHASE_DEF[next.phase].stopColor} stopOpacity="0.95" />
            </linearGradient>
          );
        })}
      </defs>
      {/*
        We can't compute exact pixel coordinates without measuring the
        rendered DOM — instead, we use the fact that each step <li> is a
        fixed gap apart (space-y-5 = 20px gap, ~110px card + circle). We
        draw the arrows as percent-of-track absolute SVG which scales
        naturally as cards grow.

        The geometry approximation is "good enough" for visual guidance —
        the arrow lands close to but not pixel-perfect on the next
        circle. Operator gets the directional cue regardless.
      */}
      {workflow.slice(0, -1).map((step, i) => {
        const next = workflow[i + 1]!;
        const totalGaps = workflow.length - 1;
        // Each gap occupies an even slice of the SVG height. Start of
        // gap i is at `i / totalGaps`, end at `(i+1) / totalGaps`. We
        // adjust the start downward + end upward by a small offset so
        // the arrow leaves the bottom of one circle and enters the top
        // of the next instead of overshooting.
        const yStart = ((i + 0.10) / totalGaps) * 100;
        const yEnd   = ((i + 0.90) / totalGaps) * 100;
        // Curve: start at x=15px (under circle, which sits at left:0
        // with a 32px width centred at 16px), bow out to x=30px in the
        // middle, end at x=15px. Subtle but readable.
        const xStart = 15.5;
        const xEnd   = 15.5;
        const xCtrl  = 30;
        const yCtrl  = (yStart + yEnd) / 2;
        const d = `M ${xStart} ${yStart}% Q ${xCtrl} ${yCtrl}%, ${xEnd} ${yEnd}%`;
        return (
          <path
            key={`path-${step.stepNumber}`}
            d={d}
            stroke={`url(#wf-grad-${step.stepNumber})`}
            strokeWidth={2}
            fill="none"
            strokeLinecap="round"
            markerEnd={`url(#wf-arrow-${next.stepNumber})`}
            opacity={0.9}
          />
        );
      })}
    </svg>
  );
}

// ── Step ─────────────────────────────────────────────────────────────────

function Step({
  step,
  isLast,
  hasPoE,
  nodeById,
  onOpenFinding,
}: {
  step:          WorkflowStep;
  isLast:        boolean;
  hasPoE:        boolean;
  nodeById:      Map<string, AttackPathNode>;
  onOpenFinding: (findingId: string) => void;
}) {
  const def = PHASE_DEF[step.phase];
  const PhaseIcon = def.Icon;

  return (
    <li className="relative flex gap-3">
      {/* Step-number circle. The SVG connector enters/exits at this
          circle's left edge. Width: 32px, sits at left:0 of the row. */}
      <div
        className={`relative z-10 flex h-8 w-8 shrink-0 items-center justify-center rounded-full border-2 text-[11px] font-semibold ${def.circleClass}`}
        title={def.label}
      >
        {step.stepNumber}
      </div>

      <div className={`min-w-0 flex-1 rounded-md border border-gray-800 ${def.bodyBgClass}`}>
        {/* Top strip: phase chip + technique + PoE flame */}
        <div className="flex flex-wrap items-center gap-2 border-b border-gray-800/60 px-3 py-1.5 text-[10px] uppercase tracking-wider">
          <span className={`flex items-center gap-1 rounded border px-1.5 py-0.5 ${def.chipClass}`}>
            <PhaseIcon className="h-3 w-3" />
            {def.label}
          </span>
          {step.technique && (
            <span
              className="flex items-center gap-1 rounded border border-gray-700 bg-gray-900 px-1.5 py-0.5 font-mono text-[9px] text-gray-300"
              title={`MITRE ATT&CK ${step.technique}`}
            >
              <ShieldAlert className="h-2.5 w-2.5" />
              {step.technique}
            </span>
          )}
          {hasPoE && (
            <span
              className="ml-auto flex items-center gap-1 rounded border border-red-700/60 bg-red-950/60 px-1.5 py-0.5 font-semibold text-red-200"
              title="This step is backed by a CONFIRMED Proof-of-Exploit finding"
            >
              <Flame className="h-2.5 w-2.5" />
              POE
            </span>
          )}
        </div>

        {/* Title + description */}
        <div className="px-3 py-2">
          <div className="mb-1 text-sm font-medium text-gray-100">{step.title}</div>
          <div className="mb-2 text-xs leading-relaxed text-gray-400">{step.description}</div>

          {/* Evidence chips — one per cited finding ID. Click-through to
              the existing FindingDetailDrawer. Skips IDs that don't
              resolve (defense in depth — schema already strips invalid
              IDs server-side, but a chain rebuild between AI gen and
              render could orphan an ID). */}
          <div className="flex flex-wrap gap-1.5">
            {step.evidenceFindingIds.map((id) => {
              const node = nodeById.get(id);
              if (!node) return null;
              return (
                <EvidenceChip
                  key={id}
                  node={node}
                  onClick={() => onOpenFinding(id)}
                />
              );
            })}
          </div>
        </div>
      </div>

      {/* Spacer for SVG arrow on non-last steps */}
      {!isLast && <div className="absolute -bottom-5 h-5" />}
    </li>
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
  // Build a tight inline label: scanner badge + truncated title. The
  // chip stays one line; the full evidence is one click away.
  const label = node.title.length > 60 ? `${node.title.slice(0, 58)}…` : node.title;

  return (
    <button
      type="button"
      onClick={onClick}
      className={`inline-flex max-w-full items-center gap-1.5 rounded border px-2 py-1 text-[11px] transition-all hover:brightness-125 hover:shadow-sm ${sevClass}`}
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
