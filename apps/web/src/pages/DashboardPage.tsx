import { useQuery } from "@tanstack/react-query";
import { PieChart, Pie, Cell, Tooltip, ResponsiveContainer, Legend } from "recharts";
import { ShieldAlert, GitBranch, Box, Globe, ArrowRight, Flame, Plus, Target } from "lucide-react";
import { Link, useNavigate } from "react-router-dom";
import { findingsApi, reposApi, containersApi, domainsApi, scansApi } from "../lib/api";
import { SEVERITY_CHART } from "../lib/colors";

import StatsCard from "../components/StatsCard";
import SeverityBadge from "../components/SeverityBadge";
import ScanStatusBadge from "../components/ScanStatusBadge";
import TargetTag from "../components/TargetTag";
import { formatRelative } from "../lib/utils";
import type { ScanJob } from "@devsecops/types";

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

// Chart hex colors — imported from canonical colors.ts
const SEVERITY_COLORS = SEVERITY_CHART;

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
  const { data: noisyTargets } = useQuery({
    queryKey: ["findings", "top-targets"],
    queryFn: () => findingsApi.topTargets(5),
  });
  const { data: noisyRules } = useQuery({
    queryKey: ["findings", "top-rules"],
    queryFn: () => findingsApi.topRules(5),
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

      {/* Stats — all clickable, route to filtered views */}
      <div className="grid grid-cols-2 gap-4 lg:grid-cols-5">
        <StatsCard
          label="Total Findings"
          value={totalFindings}
          icon={<ShieldAlert className="h-5 w-5" />}
          onClick={() => navigate("/findings")}
          hint={totalFindings > 0 ? "View all" : undefined}
        />
        <StatsCard
          label="Critical"
          value={criticalCount}
          valueClassName="text-red-400"
          icon={<ShieldAlert className="h-5 w-5 text-red-500/70" />}
          onClick={() => navigate("/findings?severity=CRITICAL&status=OPEN")}
          hint={criticalCount > 0 ? "Open & critical" : undefined}
        />
        <StatsCard
          label="High"
          value={highCount}
          valueClassName="text-orange-400"
          icon={<ShieldAlert className="h-5 w-5 text-orange-500/70" />}
          onClick={() => navigate("/findings?severity=HIGH&status=OPEN")}
          hint={highCount > 0 ? "Open & high" : undefined}
        />
        <StatsCard
          label="Repositories"
          value={repos?.length ?? 0}
          icon={<GitBranch className="h-5 w-5" />}
          onClick={() => navigate("/repositories")}
        />
        <StatsCard
          label="Containers + Domains"
          value={(containers?.length ?? 0) + (domains?.length ?? 0)}
          icon={<Globe className="h-5 w-5" />}
          onClick={() => navigate((containers?.length ?? 0) >= (domains?.length ?? 0) ? "/containers" : "/domains")}
        />
      </div>

      <div className="grid grid-cols-1 gap-6 lg:grid-cols-3">
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
            <div className="flex h-48 flex-col items-center justify-center gap-3 text-center text-sm text-gray-500">
              <ShieldAlert className="h-8 w-8 text-gray-700" />
              <p>No findings yet.</p>
              {(repos?.length ?? 0) + (containers?.length ?? 0) + (domains?.length ?? 0) === 0 ? (
                <Link to="/repositories" className="inline-flex items-center gap-1 rounded bg-indigo-700 px-3 py-1.5 text-xs text-white hover:bg-indigo-600">
                  <Plus className="h-3 w-3" /> Add your first target
                </Link>
              ) : (
                <Link to="/scans" className="inline-flex items-center gap-1 rounded bg-indigo-700 px-3 py-1.5 text-xs text-white hover:bg-indigo-600">
                  Start a scan <ArrowRight className="h-3 w-3" />
                </Link>
              )}
            </div>
          )}
        </div>

        {/* Noisiest targets */}
        <div className="rounded-lg border border-gray-800 bg-gray-900 p-5">
          <div className="mb-4 flex items-center justify-between">
            <h2 className="flex items-center gap-1.5 text-sm font-semibold text-white">
              <Flame className="h-3.5 w-3.5 text-orange-400" />
              Top Risk Targets
            </h2>
            <span className="text-[10px] uppercase tracking-wider text-gray-500">Open Critical + High</span>
          </div>
          {noisyTargets && noisyTargets.length > 0 ? (
            <div className="space-y-1.5">
              {noisyTargets.map((t) => {
                const typeParam =
                  t.targetType === "REPOSITORY" ? "repo"
                  : t.targetType === "CONTAINER" ? "container"
                  : "domain";
                const icon =
                  t.targetType === "REPOSITORY" ? <GitBranch className="h-3.5 w-3.5 text-gray-500" />
                  : t.targetType === "CONTAINER" ? <Box className="h-3.5 w-3.5 text-gray-500" />
                  : <Globe className="h-3.5 w-3.5 text-gray-500" />;
                const maxCount = Math.max(...noisyTargets.map((n) => n.count));
                const pct = Math.round((t.count / maxCount) * 100);
                return (
                  <Link
                    key={`${t.targetType}:${t.targetId}`}
                    to={`/findings?target=${typeParam}:${t.targetId}&status=OPEN`}
                    className="group block rounded px-3 py-2 hover:bg-gray-800/60"
                  >
                    <div className="flex items-center gap-2">
                      {icon}
                      <span className="flex-1 min-w-0 truncate text-xs text-gray-300 group-hover:text-white">{t.targetName}</span>
                      <span className="tabular-nums text-xs font-semibold text-orange-300">{t.count}</span>
                    </div>
                    <div className="mt-1.5 h-1 w-full overflow-hidden rounded-full bg-gray-800">
                      <div className="h-full rounded-full bg-orange-500/70" style={{ width: `${Math.max(pct, 4)}%` }} />
                    </div>
                  </Link>
                );
              })}
            </div>
          ) : (
            <div className="flex h-48 items-center justify-center text-center text-sm text-gray-500">
              No critical or high findings yet.
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
            <div className="flex h-48 flex-col items-center justify-center gap-3 text-center text-sm text-gray-500">
              <p>No scans yet.</p>
              <Link to="/repositories" className="inline-flex items-center gap-1 rounded bg-indigo-700 px-3 py-1.5 text-xs text-white hover:bg-indigo-600">
                <Plus className="h-3 w-3" /> Add a target
              </Link>
            </div>
          )}
        </div>
      </div>

      {/* Top Noisy Rules — candidates for suppression/tuning */}
      <div className="rounded-lg border border-gray-800 bg-gray-900 p-5">
        <div className="mb-4 flex items-center justify-between">
          <h2 className="flex items-center gap-1.5 text-sm font-semibold text-white">
            <Target className="h-3.5 w-3.5 text-indigo-400" />
            Suppression Candidates
          </h2>
          <span className="text-[10px] uppercase tracking-wider text-gray-500">
            Rules producing the most open Critical + High
          </span>
        </div>
        {noisyRules && noisyRules.length > 0 ? (
          <div className="space-y-1.5">
            {(() => {
              const maxCount = Math.max(...noisyRules.map((r) => r.count));
              return noisyRules.map((r) => {
                const pct = Math.round((r.count / maxCount) * 100);
                return (
                  <Link
                    key={r.ruleId}
                    to={`/findings?search=${encodeURIComponent(r.ruleId)}&status=OPEN`}
                    className="group block rounded px-3 py-2 hover:bg-gray-800/60"
                  >
                    <div className="flex items-center gap-3">
                      <span className="shrink-0 rounded bg-gray-800 px-1.5 py-0.5 text-[10px] font-mono text-gray-400 group-hover:text-gray-200">
                        {r.scanType}
                      </span>
                      <div className="min-w-0 flex-1">
                        <p className="truncate text-xs font-medium text-gray-200 group-hover:text-white">{r.title}</p>
                        <p className="truncate text-[10px] font-mono text-gray-500">{r.ruleId}</p>
                      </div>
                      <span className="tabular-nums text-xs font-semibold text-indigo-300">{r.count}</span>
                    </div>
                    <div className="mt-1.5 h-1 w-full overflow-hidden rounded-full bg-gray-800">
                      <div className="h-full rounded-full bg-indigo-500/70" style={{ width: `${Math.max(pct, 4)}%` }} />
                    </div>
                  </Link>
                );
              });
            })()}
          </div>
        ) : (
          <div className="flex h-32 items-center justify-center text-center text-sm text-gray-500">
            No critical or high findings with a ruleId yet.
          </div>
        )}
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
                    <td className="py-2 pr-4"><TargetTag finding={f} maxWidth="max-w-[140px]" /></td>
                    <td className="py-2 pr-4 text-xs text-gray-400">{f.scanType}</td>
                    <td className="py-2 text-xs text-gray-500">{formatRelative(f.firstSeen)}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        ) : (
          <div className="flex h-24 flex-col items-center justify-center gap-2 text-sm text-gray-500">
            <p>No findings yet.</p>
            <Link to="/repositories" className="inline-flex items-center gap-1 text-xs text-indigo-400 hover:text-indigo-300">
              <Plus className="h-3 w-3" /> Add a target to get started
            </Link>
          </div>
        )}
      </div>
    </div>
  );
}
