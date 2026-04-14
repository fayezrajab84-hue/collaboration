import { useQuery } from "@tanstack/react-query";
import { PieChart, Pie, Cell, Tooltip, ResponsiveContainer, Legend } from "recharts";
import { ShieldAlert, GitBranch, Box, Globe, Clock } from "lucide-react";
import { findingsApi, reposApi, containersApi, domainsApi, scansApi } from "../lib/api";
import StatsCard from "../components/StatsCard";
import SeverityBadge from "../components/SeverityBadge";
import ScanStatusBadge from "../components/ScanStatusBadge";
import { formatRelative } from "../lib/utils";

const SEVERITY_COLORS: Record<string, string> = {
  CRITICAL: "#dc2626", HIGH: "#ea580c", MEDIUM: "#d97706", LOW: "#65a30d", INFO: "#6b7280",
};

export default function DashboardPage() {
  const { data: stats } = useQuery({ queryKey: ["findings", "stats"], queryFn: findingsApi.stats });
  const { data: repos } = useQuery({ queryKey: ["repos"], queryFn: reposApi.list });
  const { data: containers } = useQuery({ queryKey: ["containers"], queryFn: containersApi.list });
  const { data: domains } = useQuery({ queryKey: ["domains"], queryFn: domainsApi.list });
  const { data: scans } = useQuery({ queryKey: ["scans"], queryFn: () => scansApi.list(1, 10) });
  const { data: recentFindings } = useQuery({
    queryKey: ["findings", "recent"],
    queryFn: () => findingsApi.list({ limit: 5, page: 1 }),
  });

  const severityData = (stats?.severityCounts ?? []).map((s) => ({
    name: s.severity,
    value: s._count,
    color: SEVERITY_COLORS[s.severity] ?? "#6b7280",
  }));

  const totalFindings = severityData.reduce((a, b) => a + b.value, 0);
  const criticalCount = severityData.find((s) => s.name === "CRITICAL")?.value ?? 0;
  const highCount = severityData.find((s) => s.name === "HIGH")?.value ?? 0;

  return (
    <div className="p-6 space-y-6">
      <h1 className="text-xl font-bold text-white">Dashboard</h1>

      {/* Stats */}
      <div className="grid grid-cols-2 gap-4 lg:grid-cols-4">
        <StatsCard
          label="Total Findings"
          value={totalFindings}
          icon={<ShieldAlert className="h-5 w-5" />}
        />
        <StatsCard
          label="Critical / High"
          value={`${criticalCount} / ${highCount}`}
          valueClassName="text-red-400"
          icon={<ShieldAlert className="h-5 w-5" />}
        />
        <StatsCard
          label="Repositories"
          value={repos?.length ?? 0}
          icon={<GitBranch className="h-5 w-5" />}
        />
        <StatsCard
          label="Containers + Domains"
          value={(containers?.length ?? 0) + (domains?.length ?? 0)}
          icon={<Globe className="h-5 w-5" />}
        />
      </div>

      <div className="grid grid-cols-1 gap-6 lg:grid-cols-2">
        {/* Severity chart */}
        <div className="rounded-lg border border-gray-800 bg-gray-900 p-5">
          <h2 className="mb-4 text-sm font-semibold text-white">Findings by Severity</h2>
          {severityData.length > 0 ? (
            <ResponsiveContainer width="100%" height={220}>
              <PieChart>
                <Pie
                  data={severityData}
                  dataKey="value"
                  nameKey="name"
                  cx="50%"
                  cy="50%"
                  innerRadius={55}
                  outerRadius={85}
                >
                  {severityData.map((entry) => (
                    <Cell key={entry.name} fill={entry.color} />
                  ))}
                </Pie>
                <Tooltip
                  contentStyle={{ background: "#111827", border: "1px solid #374151", borderRadius: 6 }}
                  labelStyle={{ color: "#e5e7eb" }}
                  itemStyle={{ color: "#9ca3af" }}
                />
                <Legend formatter={(v) => <span className="text-xs text-gray-400">{v}</span>} />
              </PieChart>
            </ResponsiveContainer>
          ) : (
            <div className="flex h-48 items-center justify-center text-sm text-gray-500">
              No findings yet — run a scan to get started.
            </div>
          )}
        </div>

        {/* Recent scans */}
        <div className="rounded-lg border border-gray-800 bg-gray-900 p-5">
          <h2 className="mb-4 text-sm font-semibold text-white">Recent Scans</h2>
          {scans?.data.length ? (
            <div className="space-y-2">
              {scans.data.slice(0, 6).map((scan) => (
                <div
                  key={scan.id}
                  className="flex items-center justify-between rounded bg-gray-800/60 px-3 py-2"
                >
                  <div className="min-w-0">
                    <p className="truncate text-xs font-medium text-gray-200">{scan.targetType}</p>
                    <p className="text-xs text-gray-500">{formatRelative(scan.createdAt)}</p>
                  </div>
                  <ScanStatusBadge status={scan.status} />
                </div>
              ))}
            </div>
          ) : (
            <div className="flex h-48 items-center justify-center text-sm text-gray-500">
              No scans yet.
            </div>
          )}
        </div>
      </div>

      {/* Recent critical findings */}
      {(recentFindings?.data.length ?? 0) > 0 && (
        <div className="rounded-lg border border-gray-800 bg-gray-900 p-5">
          <h2 className="mb-4 text-sm font-semibold text-white">Recent Findings</h2>
          <div className="overflow-x-auto">
            <table className="w-full text-sm">
              <thead>
                <tr className="border-b border-gray-800 text-left text-xs text-gray-500">
                  <th className="pb-2 pr-4 font-medium">Severity</th>
                  <th className="pb-2 pr-4 font-medium">Title</th>
                  <th className="pb-2 pr-4 font-medium">Type</th>
                  <th className="pb-2 font-medium">First seen</th>
                </tr>
              </thead>
              <tbody>
                {recentFindings?.data.map((f) => (
                  <tr key={f.id} className="border-b border-gray-800/50">
                    <td className="py-2 pr-4"><SeverityBadge severity={f.severity} /></td>
                    <td className="py-2 pr-4 max-w-xs truncate text-gray-200">{f.title}</td>
                    <td className="py-2 pr-4 text-xs text-gray-400">{f.scanType}</td>
                    <td className="py-2 text-xs text-gray-500">{formatRelative(f.firstSeen)}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>
      )}
    </div>
  );
}
