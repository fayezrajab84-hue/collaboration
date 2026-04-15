import type { FindingCounts } from "@devsecops/types";

interface Props {
  counts?: FindingCounts;
}

const BADGES: Array<{ key: keyof FindingCounts; bg: string; text: string; title: string }> = [
  { key: "CRITICAL", bg: "bg-red-950/70",    text: "text-red-400",    title: "Critical" },
  { key: "HIGH",     bg: "bg-orange-950/70", text: "text-orange-400", title: "High" },
  { key: "MEDIUM",   bg: "bg-amber-950/70",  text: "text-amber-400",  title: "Medium" },
  { key: "LOW",      bg: "bg-green-950/70",  text: "text-green-500",  title: "Low" },
];

export default function FindingCountBadges({ counts }: Props) {
  if (!counts) {
    return <span className="text-xs text-gray-600">—</span>;
  }

  return (
    <div className="flex items-center gap-1.5">
      {BADGES.map(({ key, bg, text, title }) => (
        <span
          key={key}
          title={`${title}: ${counts[key]}`}
          className={`inline-flex h-6 min-w-[1.5rem] items-center justify-center rounded-full px-1.5 text-xs font-semibold ${bg} ${text}`}
        >
          {counts[key]}
        </span>
      ))}
    </div>
  );
}
