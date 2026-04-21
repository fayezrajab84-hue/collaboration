import { cn } from "../lib/utils";

// Severity badge — neutral gray body with a single coloured dot, matching the
// dot-on-neutral pattern used across TargetTag, the "merged" chips, the AI
// triage column, and the HTML report. The colour still registers instantly
// while the row no longer looks like a saturated pill.
const DOT: Record<string, string> = {
  CRITICAL: "bg-red-400",
  HIGH:     "bg-orange-400",
  MEDIUM:   "bg-amber-400",
  LOW:      "bg-sky-400",
  INFO:     "bg-gray-400",
};

export default function SeverityBadge({
  severity,
  className,
}: {
  severity: string;
  className?: string;
}) {
  const dot = DOT[severity] ?? DOT["INFO"]!;
  return (
    <span
      className={cn(
        "inline-flex items-center gap-1.5 rounded px-2 py-0.5 text-xs font-semibold uppercase tracking-wide",
        "bg-gray-800/70 text-gray-300 border border-gray-700/60",
        className,
      )}
    >
      <span className={cn("h-1.5 w-1.5 rounded-full", dot)} />
      {severity}
    </span>
  );
}
