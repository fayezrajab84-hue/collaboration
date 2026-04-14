import { cn } from "../lib/utils";

const SEVERITY_STYLES: Record<string, string> = {
  CRITICAL: "bg-red-900/60 text-red-300 border border-red-700",
  HIGH:     "bg-orange-900/60 text-orange-300 border border-orange-700",
  MEDIUM:   "bg-amber-900/60 text-amber-300 border border-amber-700",
  LOW:      "bg-green-900/60 text-green-300 border border-green-700",
  INFO:     "bg-gray-800 text-gray-400 border border-gray-700",
};

export default function SeverityBadge({
  severity,
  className,
}: {
  severity: string;
  className?: string;
}) {
  return (
    <span
      className={cn(
        "inline-flex items-center rounded px-2 py-0.5 text-xs font-semibold uppercase tracking-wide",
        SEVERITY_STYLES[severity] ?? SEVERITY_STYLES["INFO"],
        className
      )}
    >
      {severity}
    </span>
  );
}
