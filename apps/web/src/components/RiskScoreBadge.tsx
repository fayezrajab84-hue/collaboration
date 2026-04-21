import { Sparkles } from "lucide-react";
import { riskScoreStyle } from "../lib/colors";

interface Props {
  score:   number | null | undefined;
  reason?: string | null;
  size?:   "sm" | "md";
}

export default function RiskScoreBadge({ score, reason, size = "sm" }: Props) {
  if (score == null) return null;

  const { label, ring, bg, text, bar } = riskScoreStyle(score);
  const isMd = size === "md";

  return (
    <div
      className={`group relative inline-flex items-center gap-1.5 rounded-lg border ${ring} ${bg} ${isMd ? "px-3 py-1.5" : "px-2 py-1"} cursor-default`}
      title={reason ?? undefined}
    >
      <Sparkles className={`flex-shrink-0 ${isMd ? "h-3.5 w-3.5" : "h-3 w-3"} ${text}`} />
      <div className="flex items-center gap-1">
        {/* Mini bar */}
        <div className={`${isMd ? "w-12 h-1.5" : "w-8 h-1"} rounded-full bg-gray-700 overflow-hidden`}>
          <div className={`h-full rounded-full ${bar} transition-all`} style={{ width: `${score}%` }} />
        </div>
        <span className={`font-bold tabular-nums ${isMd ? "text-sm" : "text-xs"} ${text}`}>{score}</span>
        <span className={`${isMd ? "text-xs" : "text-[10px]"} ${text} opacity-80`}>{label}</span>
      </div>
      {/* Tooltip on hover */}
      {reason && (
        <div className="pointer-events-none absolute bottom-full left-0 z-50 mb-1.5 hidden w-64 rounded-lg border border-gray-700 bg-gray-900 p-2.5 text-xs text-gray-300 shadow-xl group-hover:block">
          {reason}
        </div>
      )}
    </div>
  );
}
