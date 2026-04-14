import { cn } from "../lib/utils";

interface StatsCardProps {
  label: string;
  value: number | string;
  icon?: React.ReactNode;
  className?: string;
  valueClassName?: string;
}

export default function StatsCard({ label, value, icon, className, valueClassName }: StatsCardProps) {
  return (
    <div className={cn("rounded-lg border border-gray-800 bg-gray-900 p-5", className)}>
      <div className="flex items-center justify-between">
        <p className="text-sm font-medium text-gray-400">{label}</p>
        {icon && <span className="text-gray-500">{icon}</span>}
      </div>
      <p className={cn("mt-2 text-3xl font-bold tabular-nums text-white", valueClassName)}>
        {value}
      </p>
    </div>
  );
}
