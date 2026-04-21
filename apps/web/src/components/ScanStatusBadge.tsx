import { cn } from "../lib/utils";
import { SCAN_STATUS_BADGE } from "../lib/colors";

export default function ScanStatusBadge({ status }: { status: string }) {
  const isRunning = status === "RUNNING";
  return (
    <span
      className={cn(
        "inline-flex items-center gap-1.5 rounded px-2 py-0.5 text-xs font-medium",
        SCAN_STATUS_BADGE[status] ?? SCAN_STATUS_BADGE["PENDING"]
      )}
    >
      {isRunning && (
        <span className="h-2 w-2 animate-pulse rounded-full bg-indigo-400" />
      )}
      {status}
    </span>
  );
}
