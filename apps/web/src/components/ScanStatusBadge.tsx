import { cn } from "../lib/utils";

const STATUS_STYLES: Record<string, string> = {
  PENDING:   "bg-gray-800 text-gray-400",
  RUNNING:   "bg-indigo-900/60 text-indigo-300",
  COMPLETED: "bg-green-900/60 text-green-300",
  FAILED:    "bg-red-900/60 text-red-300",
  CANCELLED: "bg-gray-800 text-gray-500",
};

export default function ScanStatusBadge({ status }: { status: string }) {
  const isRunning = status === "RUNNING";
  return (
    <span
      className={cn(
        "inline-flex items-center gap-1.5 rounded px-2 py-0.5 text-xs font-medium",
        STATUS_STYLES[status] ?? STATUS_STYLES["PENDING"]
      )}
    >
      {isRunning && (
        <span className="h-2 w-2 animate-pulse rounded-full bg-indigo-400" />
      )}
      {status}
    </span>
  );
}
