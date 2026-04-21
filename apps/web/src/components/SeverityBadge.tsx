import { cn } from "../lib/utils";
import { SEVERITY_BADGE } from "../lib/colors";

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
        SEVERITY_BADGE[severity] ?? SEVERITY_BADGE["INFO"],
        className
      )}
    >
      {severity}
    </span>
  );
}
