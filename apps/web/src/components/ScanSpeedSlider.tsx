/**
 * ScanSpeedSlider — Acunetix-style 3-stop slider that hides the
 * scanner-name jargon (DAST / PENTEST_FULL / depth=AGGRESSIVE) behind
 * a single conceptual axis (fast → standard → deep).
 *
 * Why three stops, not four:
 *   Acunetix's 4-stop slider blurs Moderate vs Thorough. Operators
 *   bounce between them and pick the wrong one. Three stops force a
 *   real choice — quick read vs full audit vs active exploit.
 *
 * The slider value maps deterministically to the existing API calls:
 *
 *   FAST     →  domainsApi.triggerScan(id)              (DAST, ~10 min)
 *   STANDARD →  domainsApi.triggerPentest(id, STANDARD) (~25 min)
 *   DEEP     →  domainsApi.triggerPentest(id, AGGRESSIVE) (~45 min)
 *
 * The component is presentational — the parent owns the mutation +
 * "in-flight" disabled state. That keeps this reusable from list rows,
 * detail pages, and the future Application-level "scan all domains"
 * button without re-wiring routing or toasts each time.
 */
import { Zap, Shield, Crosshair, Clock } from "lucide-react";

export type ScanSpeed = "FAST" | "STANDARD" | "DEEP";

// Monochromatic indigo scale — single axis from light/airy (Fast) →
// bold/glowing (Deep). Earlier draft used a 3-hue palette (emerald /
// indigo / rose) but that fights the slider's own progression: the
// hue change reads as "different things", not "more of the same".
// A single hue with rising saturation + opacity reads as intensity,
// matching the operator's mental model — same scan family, more or
// less of it.
//
// Brand also stays clean: every UI element is brand-indigo, no
// off-palette colours leaking onto a primary action surface.
const SPEED_META: Record<ScanSpeed, {
  label:         string;
  time:          string;
  icon:          typeof Zap;
  oneLiner:      string;
  runs:          string[];
  /** Anything we explicitly do NOT do at this speed — sets expectations. */
  skips?:        string[];
  /** Tailwind colour for the active stop + button. */
  accentText:    string;
  accentBg:      string;
  accentBorder:  string;
  accentRing:    string;
  /** Solid + hover for the run button — sits on dark, not on accentBg. */
  buttonBg:      string;
  buttonHover:   string;
  /** Numeric weight (300 → 100) for the small "•" bullet next to runs[]. */
  bulletColor:   string;
}> = {
  FAST: {
    label: "Fast",
    time: "~10 min",
    icon: Zap,
    oneLiner: "Quick attack-surface read against discovered URLs.",
    runs: [
      "ZAP spider — find every page reachable from the homepage",
      "ZAP active scanner — XSS, SQLi, path traversal, header issues",
    ],
    skips: ["Network-level checks (nmap, nikto, testssl)"],
    accentText:   "text-indigo-300",
    accentBg:     "bg-indigo-950/25",     // light wash — barely tinted
    accentBorder: "border-indigo-900/40",
    accentRing:   "ring-indigo-700/30",
    buttonBg:     "bg-indigo-700",
    buttonHover:  "hover:bg-indigo-600",
    bulletColor:  "bg-indigo-300",
  },
  STANDARD: {
    label: "Standard",
    time: "~25 min",
    icon: Shield,
    oneLiner: "Full scanner suite — coverage without active exploit.",
    runs: [
      "ZAP spider + active scan",
      "nuclei (3000+ templates)",
      "nikto + testssl",
      "Targeted OWASP checks (CORS, IDOR, SSTI, mass-assignment)",
    ],
    skips: ["Active exploit payloads (sqlmap / xsstrike / dalfox)"],
    accentText:   "text-indigo-200",
    accentBg:     "bg-indigo-950/55",     // mid — visible but mellow
    accentBorder: "border-indigo-800/60",
    accentRing:   "ring-indigo-500/40",
    buttonBg:     "bg-indigo-700",
    buttonHover:  "hover:bg-indigo-600",
    bulletColor:  "bg-indigo-200",
  },
  DEEP: {
    label: "Deep",
    time: "~45 min",
    icon: Crosshair,
    oneLiner: "Everything in Standard + active exploitation.",
    runs: [
      "Everything in Standard",
      "sqlmap — proves SQL injection with extracted data",
      "xsstrike + dalfox — proves XSS with reflected payload",
      "OWASP Top 10 expansion — commix, SSTImap, SSRFmap, JWT attacks, XXE, deserialization",
    ],
    skips: ["Nothing — this is the full pipeline."],
    accentText:   "text-indigo-100",
    accentBg:     "bg-indigo-950/95",     // densest dark — solid heavy fill
    accentBorder: "border-indigo-600/70", // crisp visible border on dense bg
    accentRing:   "ring-indigo-500/50",
    buttonBg:     "bg-indigo-800",        // darker/denser button = heavier action
    buttonHover:  "hover:bg-indigo-700",
    bulletColor:  "bg-indigo-100",
  },
};

const STOPS: ScanSpeed[] = ["FAST", "STANDARD", "DEEP"];

export default function ScanSpeedSlider({
  value,
  onChange,
  onRun,
  isRunning,
  inFlightLabel,
}: {
  value:          ScanSpeed;
  onChange:       (next: ScanSpeed) => void;
  onRun:          () => void;
  isRunning:      boolean;
  /** When the parent is waiting on a triggerScan/Pentest, show this label
   *  instead of "Run scan" so the operator knows which knob is held. */
  inFlightLabel?: string;
}) {
  const meta = SPEED_META[value];
  const Icon = meta.icon;

  return (
    <div className="rounded-xl border border-gray-800 bg-gray-900/60 p-5 shadow-sm">
      <div className="mb-3 flex items-center justify-between">
        <h2 className="text-sm font-semibold text-gray-200">Run a scan</h2>
        <span className="flex items-center gap-1 text-xs text-gray-500">
          <Clock className="h-3 w-3" />
          {meta.time}
        </span>
      </div>

      {/* ── Slider track ────────────────────────────────────────────── */}
      <div className="relative mt-4 mb-7">
        {/* Background track */}
        <div className="absolute inset-x-0 top-1/2 h-0.5 -translate-y-1/2 rounded-full bg-gray-800" />
        {/* Active fill — width grows with selection; gradient deepens
            from light indigo (Fast end) to dark indigo (Deep end) so the
            track itself reinforces "deeper = darker" left-to-right. */}
        <div
          className={`absolute left-0 top-1/2 h-0.5 -translate-y-1/2 rounded-full bg-gradient-to-r from-indigo-400 via-indigo-600 to-indigo-900 transition-all duration-200 ${
            value === "FAST"     ? "w-0"
            : value === "STANDARD" ? "w-1/2"
            :                        "w-full"
          }`}
        />
        {/* Stop dots + labels */}
        <div className="relative flex justify-between">
          {STOPS.map((stop) => {
            const isActive = stop === value;
            const stopMeta = SPEED_META[stop];
            const StopIcon = stopMeta.icon;
            return (
              <button
                key={stop}
                type="button"
                onClick={() => onChange(stop)}
                disabled={isRunning}
                className="group flex flex-col items-center disabled:cursor-not-allowed disabled:opacity-60"
              >
                <span
                  className={`relative z-10 flex h-7 w-7 items-center justify-center rounded-full border-2 transition-all ${
                    isActive
                      ? `${stopMeta.accentBorder} ${stopMeta.accentBg} ${stopMeta.accentText} shadow-lg ring-4 ring-opacity-30 ${stopMeta.accentRing}`
                      : "border-gray-700 bg-gray-900 text-gray-500 group-hover:border-gray-500 group-hover:text-gray-300"
                  }`}
                >
                  <StopIcon className="h-3.5 w-3.5" />
                </span>
                <span
                  className={`mt-2 text-xs font-medium transition-colors ${
                    isActive ? stopMeta.accentText : "text-gray-500 group-hover:text-gray-300"
                  }`}
                >
                  {stopMeta.label}
                </span>
                <span className="mt-0.5 text-[10px] text-gray-600">{stopMeta.time}</span>
              </button>
            );
          })}
        </div>
      </div>

      {/* ── Description for selected stop ─────────────────────────────── */}
      <div className={`rounded-lg border ${meta.accentBorder} ${meta.accentBg} p-4`}>
        <div className="mb-2 flex items-center gap-2">
          <Icon className={`h-4 w-4 ${meta.accentText}`} />
          <span className={`text-sm font-semibold ${meta.accentText}`}>{meta.label}</span>
          <span className="text-xs text-gray-500">·</span>
          <span className="text-xs text-gray-400">{meta.oneLiner}</span>
        </div>

        <div className="grid gap-3 sm:grid-cols-2">
          <div>
            <div className="mb-1 text-[10px] font-semibold uppercase tracking-wider text-gray-500">
              Includes
            </div>
            <ul className="space-y-1 text-xs text-gray-300">
              {meta.runs.map((r) => (
                <li key={r} className="flex items-start gap-1.5">
                  <span className={`mt-1 inline-block h-1 w-1 flex-shrink-0 rounded-full ${meta.bulletColor}`} />
                  <span>{r}</span>
                </li>
              ))}
            </ul>
          </div>
          {meta.skips && meta.skips.length > 0 && (
            <div>
              <div className="mb-1 text-[10px] font-semibold uppercase tracking-wider text-gray-500">
                Skips
              </div>
              <ul className="space-y-1 text-xs text-gray-500">
                {meta.skips.map((s) => (
                  <li key={s} className="flex items-start gap-1.5">
                    <span className="mt-1 inline-block h-1 w-1 flex-shrink-0 rounded-full bg-gray-600" />
                    <span>{s}</span>
                  </li>
                ))}
              </ul>
            </div>
          )}
        </div>
      </div>

      {/* ── Run button ─────────────────────────────────────────────── */}
      <div className="mt-4 flex items-center justify-end">
        <button
          onClick={onRun}
          disabled={isRunning}
          className={`inline-flex items-center gap-2 rounded-lg px-4 py-2 text-sm font-semibold text-white transition-colors disabled:cursor-not-allowed disabled:opacity-60 ${meta.buttonBg} ${meta.buttonHover}`}
        >
          <Icon className="h-4 w-4" />
          {isRunning ? (inFlightLabel ?? "Queuing…") : `Run ${meta.label} Scan`}
        </button>
      </div>
    </div>
  );
}

// SPEED_META intentionally not exported — Vite Fast Refresh doesn't
// support non-component exports from a component file. If another module
// needs the metadata table (e.g. a list-page tooltip), move it into its
// own file (e.g. `scanSpeedMeta.ts`) rather than re-exporting from here.
