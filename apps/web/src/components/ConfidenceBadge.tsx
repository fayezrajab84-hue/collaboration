import type { Confidence } from "@devsecops/types";

interface Props {
  confidence: Confidence;
  className?: string;
}

const CONFIG: Record<Confidence, { label: string; className: string }> = {
  CONFIRMED: {
    label: "Confirmed",
    className: "bg-red-900/40 text-red-300 border border-red-700/50",
  },
  LIKELY: {
    label: "Likely",
    className: "bg-amber-900/40 text-amber-300 border border-amber-700/50",
  },
  POSSIBLE: {
    label: "Possible",
    className: "bg-gray-800 text-gray-400 border border-gray-700",
  },
};

export default function ConfidenceBadge({ confidence, className = "" }: Props) {
  const cfg = CONFIG[confidence] ?? CONFIG.POSSIBLE;
  return (
    <span
      className={`inline-flex items-center rounded px-2 py-0.5 text-xs font-medium ${cfg.className} ${className}`}
    >
      {cfg.label}
    </span>
  );
}
