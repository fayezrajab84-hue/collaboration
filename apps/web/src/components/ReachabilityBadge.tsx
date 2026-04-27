/**
 * Reachability badge — Phase 14.
 *
 * Reads Finding.reachability + Finding.reachabilityEvidence and renders
 * a compact pill that tells the user whether the vulnerable package is
 * actually imported in the source code.
 *
 * Color logic:
 *   REACHABLE      → indigo (brand) — operational priority
 *   NOT_REACHABLE  → muted gray — can be deferred
 *   UNKNOWN        → outlined gray — old finding, no scanner data
 *   NOT_APPLICABLE → null (don't render — irrelevant for non-SCA findings)
 *
 * Hover/title shows the evidence (which files import the package) when
 * present. The full evidence list with click-through links lives in
 * the FindingDetailDrawer; this badge is the at-a-glance signal.
 */
import { cn } from "../lib/utils";
import { Activity, Eye, EyeOff, HelpCircle } from "lucide-react";

type Reachability = "REACHABLE" | "NOT_REACHABLE" | "UNKNOWN" | "NOT_APPLICABLE" | undefined | null;

const STYLES: Record<Exclude<Reachability, undefined | null | "NOT_APPLICABLE">, { bg: string; icon: typeof Activity; label: string; tooltip: string }> = {
  REACHABLE: {
    bg:      "bg-indigo-900/40 border border-indigo-700/60 text-indigo-200",
    icon:    Eye,
    label:   "Reachable",
    tooltip: "Package is imported in the source code — patch this first.",
  },
  NOT_REACHABLE: {
    bg:      "bg-gray-800/60 border border-gray-700 text-gray-400",
    icon:    EyeOff,
    label:   "Not reachable",
    tooltip: "Package present in the lockfile but not imported anywhere in source. Lower triage priority.",
  },
  UNKNOWN: {
    bg:      "bg-gray-900/40 border border-gray-800 text-gray-500",
    icon:    HelpCircle,
    label:   "Unknown",
    tooltip: "Reachability could not be determined — finding pre-dates Phase 14 or scanner returned no import data. Will be classified on next re-scan.",
  },
};

export default function ReachabilityBadge({
  reachability,
  evidence,
  className,
  size = "sm",
}: {
  reachability: Reachability;
  evidence?:    string[] | null;
  className?:   string;
  size?:        "xs" | "sm";
}) {
  if (!reachability || reachability === "NOT_APPLICABLE") return null;
  const style = STYLES[reachability];
  if (!style) return null;
  const Icon = style.icon;
  const evidenceCount = evidence?.length ?? 0;

  const tooltip = evidenceCount > 0
    ? `${style.tooltip}\n\nImported in: ${evidence!.slice(0, 5).join(", ")}${evidenceCount > 5 ? `, … +${evidenceCount - 5} more` : ""}`
    : style.tooltip;

  const pad = size === "xs" ? "px-1.5 py-0.5 text-[10px]" : "px-2 py-0.5 text-xs";
  const iconSize = size === "xs" ? "h-2.5 w-2.5" : "h-3 w-3";

  return (
    <span
      className={cn(
        "inline-flex items-center gap-1 rounded font-medium",
        pad,
        style.bg,
        className,
      )}
      title={tooltip}
    >
      <Icon className={iconSize} />
      {style.label}
      {evidenceCount > 0 && (
        <span className="ml-0.5 opacity-70">·{evidenceCount}</span>
      )}
    </span>
  );
}
