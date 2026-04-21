import { Link } from "react-router-dom";
import type { FindingCounts } from "@devsecops/types";

interface Props {
  counts?: FindingCounts;
  /** When provided, each badge links to the Findings page pre-filtered by target + severity */
  targetType?: "repo" | "container" | "domain";
  targetId?: string;
}

const BADGES: Array<{ key: keyof FindingCounts; bg: string; text: string; title: string }> = [
  { key: "CRITICAL", bg: "bg-red-950/70",    text: "text-red-400",    title: "Critical" },
  { key: "HIGH",     bg: "bg-orange-950/70", text: "text-orange-400", title: "High" },
  { key: "MEDIUM",   bg: "bg-amber-950/70",  text: "text-amber-400",  title: "Medium" },
  { key: "LOW",      bg: "bg-green-950/70",  text: "text-green-500",  title: "Low" },
];

export default function FindingCountBadges({ counts, targetType, targetId }: Props) {
  if (!counts) {
    return <span className="text-xs text-gray-600">—</span>;
  }

  const total = (counts.CRITICAL ?? 0) + (counts.HIGH ?? 0) + (counts.MEDIUM ?? 0) + (counts.LOW ?? 0);
  if (total === 0) {
    return <span className="text-xs text-gray-600">No findings</span>;
  }

  return (
    <div className="flex items-center gap-1.5">
      {BADGES.map(({ key, bg, text, title }) => {
        const count = counts[key] ?? 0;
        if (count === 0) return null;

        const cls = `inline-flex h-6 min-w-[1.5rem] items-center justify-center rounded-full px-1.5 text-xs font-semibold transition-opacity hover:opacity-80 ${bg} ${text}`;
        const label = `${title}: ${count} — click to view`;

        if (targetType && targetId) {
          const params = new URLSearchParams({
            target: `${targetType}:${targetId}`,
            severity: key,
          });
          return (
            <Link
              key={key}
              to={`/findings?${params.toString()}`}
              title={label}
              onClick={(e) => e.stopPropagation()}
              className={cls}
            >
              {count}
            </Link>
          );
        }

        return (
          <span key={key} title={`${title}: ${count}`} className={cls}>
            {count}
          </span>
        );
      })}
    </div>
  );
}
