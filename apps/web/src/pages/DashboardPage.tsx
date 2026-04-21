import { useQuery } from "@tanstack/react-query";
import { PieChart, Pie, Cell, Tooltip, ResponsiveContainer, Legend } from "recharts";
import { ShieldAlert, GitBranch, Box, Globe, ArrowRight } from "lucide-react";
import { Link, useNavigate } from "react-router-dom";
import { findingsApi, reposApi, containersApi, domainsApi, scansApi } from "../lib/api";

import StatsCard from "../components/StatsCard";
import SeverityBadge from "../components/SeverityBadge";
import ScanStatusBadge from "../components/ScanStatusBadge";
import { formatRelative } from "../lib/utils";
import type { Finding, ScanJob } from "@devsecops/types";

const SCAN_TYPE_ICONS: Record<string, React.ReactNode> = {
  REPOSITORY: <GitBranch className="h-3.5 w-3.5 shrink-0" />,
  CONTAINER:  <Box className="h-3.5 w-3.5 shrink-0" />,
  DOMAIN:     <Globe className="h-3.5 w-3.5 shrink-0" />,
};

function ScanTargetName({ scan }: { scan: ScanJob }) {
  const name = scan.repository?.fullName ?? scan.container?.imageRef ?? scan.domain?.domain;
  return (
    <div className="flex min-w-0 items-center gap-1.5 text-xs text-gray-300">
      {SCAN_TYPE_ICONS[scan.targetType]}
      <span className="truncate">{name ?? scan.targetType}</span>
    </div>
  );
}

function TargetTag({ finding }: { finding: Finding }) {
  if (finding.repository)
    return (
      <span className="inline-flex items-center gap-1 rounded bg-indigo-900/50 px-2 py-0.5 text-xs text-indigo-300 max-w-[140px] truncate">
        <GitBranch className="h-3 w-3 shrink-0" /><span className="truncate">{finding.repository.fullName}</span>
      </span>
    );
  if (finding.container)
    return (
      <span className="inline-flex items-center gap-1 rounded bg-cyan-900/50 px-2 py-0.5 text-xs text-cyan-300 max-w-[140px] truncate">
        <Box className="h-3 w-3 shrink-0" /><span className="truncate">{finding.container.imageRef}</span>
      </span>
    );
  if (finding.domain)
    return (
      <span className="inline-flex items-center gap-1 rounded bg-emerald-900/50 px-2 py-0.5 text-xs text-emerald-300 max-w-[140px] truncate">
        <Globe className="h-3 w-3 shrink-0" /><span className="truncate">{finding.domain.domain}</span>
      </span>
    );
  return <span className="text-gray-600">—</span>;
}

const SEVERITY_COLORS: Record<string, string> = {
  CRITICAL: "#dc2626", HIGH: "#ea580c", MEDIUM: "#d97706", LOW: "#65a30d", INFO: "#6b7280",
};

export default function DashboardPage() {
  const navigate = useNavigate();
  const { data: stats } = useQuery({ queryKey: ["findings", "stats"], queryFn: findingsApi.stats });
  const { data: repos } = useQuery({ queryKey: ["repos"], queryFn: reposApi.list });
  const { data: containers } = useQuery({ queryKey: ["containers"], queryFn: containersApi.list });
  const { data: domains } = useQuery({ queryKey: ["domains"], queryFn: domainsApi.list });
  const { data: scans } = useQuery({
    queryKey: ["scans"],
    queryFn: () => scansApi.list(1, 10),
    refetchInterval: (query) => {
      const d = query.state.data;
      if (!d) return false;
      return d.data.some((s) => s.status === "PENDING" || s.status === "RUNNING") ? 3000 : false;
    },
  });
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
      <h1 className="text-3xl font-bold text-white">Dashboard</h1>

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
          <div className="mb-4 flex items-center justify-between">
            <h2 className="text-sm font-semibold text-white">Recent Scans</h2>
            <Link to="/scans" className="flex items-center gap-1 text-xs text-indigo-400 hover:text-indigo-300">
              View all <ArrowRight className="h-3 w-3" />
            </Link>
          </div>
          {scans?.data.length ? (
            <div className="space-y-2">
              {scans.data.slice(0, 6).map((scan) => (
                <div
                  key={scan.id}
                  className="flex items-center justify-between rounded bg-gray-800/60 px-3 py-2"
                >
                  <div className="min-w-0 mr-3 flex-1">
                    <ScanTargetName scan={scan} />
                    <p className="mt-0.5 text-xs text-gray-500">{formatRelative(scan.createdAt)}</p>
                    {(scan.status === "PENDING" || scan.status === "RUNNING") && (() => {
                      const done = scan.completedScans ?? 0;
                      const total = scan.totalScans || 1;
                      const pct = Math.round((done / total) * 100);
                      const indeterminate = pct === 0 && scan.status === "RUNNING";
                      return (
                        <div className="mt-1 h-1 w-full overflow-hidden rounded-full bg-gray-700">
                          {!indeterminate ? (
                            <div
                              className="h-full rounded-full bg-indigo-500 transition-all duration-500"
                              style={{ width: `${Math.max(pct, 2)}%` }}
                            />
                          ) : (
                            <div className="h-full w-1/3 animate-pulse rounded-full bg-indigo-600/60" />
                          )}
                        </div>
                      );
                    })()}
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

      {/* Recent findings — always visible */}
      <div className="rounded-lg border border-gray-800 bg-gray-900 p-5">
        <div className="mb-4 flex items-center justify-between">
          <h2 className="text-sm font-semibold text-white">Recent Findings</h2>
          <Link to="/findings" className="flex items-center gap-1 text-xs text-indigo-400 hover:text-indigo-300">
            View all <ArrowRight className="h-3 w-3" />
          </Link>
        </div>
        {(recentFindings?.data.length ?? 0) > 0 ? (
          <div className="overflow-x-auto">
            <table className="w-full text-sm">
              <thead>
                <tr className="border-b border-gray-800 text-left text-xs text-gray-500">
                  <th className="pb-2 pr-4 font-medium">Severity</th>
                  <th className="pb-2 pr-4 font-medium">Title</th>
                  <th className="pb-2 pr-4 font-medium">Target</th>
                  <th className="pb-2 pr-4 font-medium">Type</th>
                  <th className="pb-2 font-medium">First seen</th>
                </tr>
              </thead>
              <tbody>
                {recentFindings?.data.map((f) => (
                  <tr
                    key={f.id}
                    className="cursor-pointer border-b border-gray-800/50 hover:bg-gray-800/40 transition-colors"
                    onClick={() => navigate(`/findings?id=${f.id}`)}
                  >
                    <td className="py-2 pr-4"><SeverityBadge severity={f.severity} /></td>
                    <td className="py-2 pr-4 max-w-xs truncate text-gray-200">{f.title}</td>
                    <td className="py-2 pr-4"><TargetTag finding={f} /></td>
                    <td className="py-2 pr-4 text-xs text-gray-400">{f.scanType}</td>
                    <td className="py-2 text-xs text-gray-500">{formatRelative(f.firstSeen)}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        ) : (
          <div className="flex h-24 items-center justify-center text-sm text-gray-500">
            No findings yet — run a scan to get started.
          </div>
        )}
      </div>
    </div>
  );
}
