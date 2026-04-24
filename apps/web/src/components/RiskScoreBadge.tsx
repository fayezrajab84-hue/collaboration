import { riskScoreStyle } from "../lib/colors";

interface Props {
  score:   number | null | undefined;
  reason?: string | null;
  size?:   "sm" | "md";
}

export default function RiskScoreBadge({ score, reason, size = "sm" }: Props) {
  if (score == null) return null;

  const { label, text, bar } = riskScoreStyle(score);
  const isMd = size === "md";

  return (
    <div
      className="group relative inline-flex items-center gap-2 cursor-default"
      title={reason ?? undefined}
    >
      {/* Mini bar — the only strong color cue */}
      <div className={`${isMd ? "w-14 h-1.5" : "w-10 h-1"} rounded-full bg-gray-800 overflow-hidden`}>
        <div className={`h-full rounded-full ${bar} transition-all`} style={{ width: `${score}%` }} />
      </div>
      <span className={`font-semibold tabular-nums ${isMd ? "text-sm" : "text-xs"} ${text}`}>{score}</span>
      <span className={`${isMd ? "text-[11px]" : "text-[10px]"} uppercase tracking-wide text-gray-500`}>{label}</span>
      {/* Tooltip on hover */}
      {reason && (
        <div className="pointer-events-none absolute bottom-full left-0 z-50 mb-1.5 hidden w-64 rounded-lg border border-gray-700 bg-gray-900 p-2.5 text-xs text-gray-300 shadow-xl group-hover:block">
          {reason}
        </div>
      )}
    </div>
  );
}
