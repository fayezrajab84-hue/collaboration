import { cn } from "../lib/utils";
import { FINDING_STATUS_BADGE } from "../lib/colors";

export default function FindingStatusBadge({
  status,
  className,
}: {
  status: string;
  className?: string;
}) {
  const cfg = FINDING_STATUS_BADGE[status] ?? FINDING_STATUS_BADGE["OPEN"];
  return (
    <span
      className={cn(
        "inline-flex items-center rounded px-2 py-0.5 text-xs font-medium",
        cfg.cls,
        className
      )}
    >
      {cfg.label}
    </span>
  );
}
