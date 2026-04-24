import { cn } from "../lib/utils";

interface StatsCardProps {
  label: string;
  value: number | string;
  icon?: React.ReactNode;
  className?: string;
  valueClassName?: string;
  onClick?: () => void;
  hint?: string;
}

export default function StatsCard({ label, value, icon, className, valueClassName, onClick, hint }: StatsCardProps) {
  const clickable = typeof onClick === "function";
  const classes = cn(
    "rounded-lg border border-gray-800 bg-gray-900 p-5 transition-colors",
    clickable && "cursor-pointer hover:border-indigo-700 hover:bg-gray-900/80 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-indigo-500",
    className,
  );
  const Inner = (
    <>
      <div className="flex items-center justify-between">
        <p className="text-sm font-medium text-gray-400">{label}</p>
        {icon && <span className="text-gray-500">{icon}</span>}
      </div>
      <p className={cn("mt-2 text-3xl font-bold tabular-nums text-white", valueClassName)}>
        {value}
      </p>
      {hint && <p className="mt-1 text-xs text-gray-500">{hint}</p>}
    </>
  );

  if (clickable) {
    return (
      <button type="button" onClick={onClick} className={cn(classes, "text-left w-full")}>
        {Inner}
      </button>
    );
  }
  return <div className={classes}>{Inner}</div>;
}
