import { useQuery } from "@tanstack/react-query";
import { BarChart, Bar, XAxis, YAxis, CartesianGrid, Tooltip, ResponsiveContainer } from "recharts";
import { ShieldAlert, GitBranch, Box, Globe, ArrowRight, Flame, Plus, Target, Code2, Activity, AlertTriangle, Filter, ChevronDown, Check, Cloud as CloudIcon, Github, Lock, Unlock, Archive, Package } from "lucide-react";
import { Link, useNavigate, useSearchParams } from "react-router-dom";
import { findingsApi, reposApi, containersApi, domainsApi, scansApi, runtimeApi, cloudAccountsApi, type RuntimeDashboardResponse } from "../lib/api";
import { wasExploitSuccessful, hasActiveAttack } from "../lib/findings";
import ExploitSuccessBadge from "../components/ExploitSuccessBadge";
import ActiveAttackBadge from "../components/ActiveAttackBadge";
import { SEVERITY_CHART } from "../lib/colors";

import StatsCard from "../components/StatsCard";
import SeverityBadge from "../components/SeverityBadge";
import ScanStatusBadge from "../components/ScanStatusBadge";
import TargetTag from "../components/TargetTag";
import RepoPostureDrawer from "../components/RepoPostureDrawer";
import { useState } from "react";
import { formatRelative } from "../lib/utils";
import type { ScanJob, Finding } from "@devsecops/types";

// Code/Web/Runtime split — mirrored from FindingsPage so the dashboard
// renders the same slice of data the user lands on after clicking through.
const CODE_SCAN_TYPES    = ["SAST", "SCA", "SECRET", "IAC", "CONTAINER"];
const WEB_SCAN_TYPES     = ["DAST", "PENTEST_FULL"];
const RUNTIME_SCAN_TYPES = ["RUNTIME"];
const CLOUD_SCAN_TYPES   = ["CLOUD"];   // Phase 29 — CSPM
// Phase 29 Slice C1 — GitHub posture findings live as a sub-pivot of the
// Code tab. POSTURE_SCAN_TYPES is the scope when sub === "posture";
// CODE_SCAN_TYPES stays the default vulnerabilities pivot.
const POSTURE_SCAN_TYPES = ["GITHUB_POSTURE"];
const WEB_TYPES_SET      = new Set(WEB_SCAN_TYPES);
const RUNTIME_TYPES_SET  = new Set(RUNTIME_SCAN_TYPES);
const CLOUD_TYPES_SET    = new Set(CLOUD_SCAN_TYPES);
const POSTURE_TYPES_SET  = new Set(POSTURE_SCAN_TYPES);

// Web target Globe rendered in light silver (gray-300) — same shade used
// across every Globe in the app (dashboard tabs, stats cards, TargetTag,
// ScansPage), so the web semantic reads consistently without competing with
// the indigo action accent.
const SCAN_TYPE_ICONS: Record<string, React.ReactNode> = {
  REPOSITORY: <GitBranch className="h-3.5 w-3.5 shrink-0" />,
  CONTAINER:  <Box className="h-3.5 w-3.5 shrink-0" />,
  DOMAIN:     <Globe className="h-3.5 w-3.5 shrink-0 text-gray-300" />,
};

// Dedupe runtime findings by ATTACK CATEGORY.
//
// Wazuh ships ~6 different rule IDs for SQL injection (rule 31103,
// 31152, 31164, 31165, 31170, 31171), several for XSS, multiple for
// "common web attack", etc. By ruleId, "we have an SQL injection"
// counts as 6 exploits — that's how my previous version reported 15
// when only 3 logical attack patterns were present. Operators think in
// attack TYPES (SQL injection, XSS, privilege escalation), not in
// vendor rule taxonomies.
//
// The classifier maps each finding's title to one of the categories
// below. Findings that don't match any pattern fall through to "Other"
// keyed by ruleId — distinct uncategorised rules still count
// individually so we don't accidentally collapse two unrelated rare
// exploits into one bucket.
const ATTACK_CATEGORIES: Array<{ category: string; pattern: RegExp }> = [
  { category: "sql-injection",       pattern: /\bSQL[ -]?injection\b|sqli\b/i },
  { category: "xss",                  pattern: /\bxss\b|cross[- ]site[- ]scripting/i },
  { category: "command-injection",    pattern: /\bcommand[ -]injection\b/i },
  { category: "path-traversal",       pattern: /\bpath[ -]traversal\b|directory[- ]traversal/i },
  { category: "lfi",                  pattern: /\blocal[ -]file[ -]inclusion\b|\blfi\b/i },
  { category: "rfi",                  pattern: /\bremote[ -]file[ -]inclusion\b|\brfi\b/i },
  { category: "rce",                  pattern: /\brce\b|\bremote[ -]code[ -]execution\b/i },
  { category: "privilege-escalation", pattern: /\bprivilege[s]?[ -]escalat(?:ion|ed)\b|sudo[ -]to[ -]root/i },
  { category: "ssrf",                 pattern: /\bssrf\b|server[- ]side[- ]request[- ]forgery/i },
  { category: "ssti",                 pattern: /\bssti\b|server[- ]side[- ]template/i },
  { category: "xxe",                  pattern: /\bxxe\b|xml[- ]external[- ]entity/i },
  { category: "deserialization",      pattern: /\bdeserializ(?:ation|ed)\b/i },
  { category: "common-web-attack",    pattern: /\bcommon[ -]web[ -]attack\b|web[ -]attack[ -]returned/i },
  { category: "auth-bypass",          pattern: /\bauth(?:entication)?[ -]bypass\b|brute[ -]force/i },
  { category: "malware-c2",           pattern: /\bmalicious[ -]ip\b|\bbackdoor\b|\bc2\b|command[ -]and[ -]control/i },
];

function categorizeAttack(finding: Finding): string {
  const text = `${finding.title ?? ""} ${finding.description ?? ""}`;
  for (const { category, pattern } of ATTACK_CATEGORIES) {
    if (pattern.test(text)) return category;
  }
  // Uncategorised — key by ruleId so distinct rare rules don't collapse.
  return `other:${finding.ruleId ?? finding.id}`;
}

function uniqByRule(findings: Finding[]): Finding[] {
  const seen = new Set<string>();
  const out: Finding[] = [];
  for (const f of findings) {
    const key = categorizeAttack(f);
    if (seen.has(key)) continue;
    seen.add(key);
    out.push(f);
  }
  return out;
}

// ── Code Categories stacked bar chart ────────────────────────────────────
//
// Stacked column per scan type, segments colored by severity. Answers
// "where are my CRITICALs concentrated?" at a glance — Container is
// usually the tallest bar with a red base, SCA second, SECRET sometimes
// dominates if the repo leaked credentials.
//
// Color choices:
//   - X-axis labels = scan type (SAST, SCA, Secrets, IaC, Container)
//   - Stack segments use canonical SEVERITY colors (red / orange /
//     amber / sky / gray) — same as the severity-bar chart had, same
//     as SeverityBadge uses, so the colour vocabulary is consistent
//     across the entire app. The brand-indigo per-category palette I
//     tried first looked pretty but lost the severity signal — the
//     whole point of stacking is to read severity composition, so
//     severity must drive the colour.
//   - Each bar segment is clickable via the legend below the chart
//     (recharts doesn't bubble click events from individual stack
//     segments cleanly).
const CODE_CATEGORY_LABEL: Record<string, string> = {
  SAST:      "SAST",
  SCA:       "SCA",
  SECRET:    "Secrets",
  IAC:       "IaC",
  CONTAINER: "Container",
};

// Severity stack palette — final refinement after iterations:
//   - Started: bright *-400 rainbow (too candy)
//   - Tried:   red/orange/indigo three-tier (still busy)
//   - Now:     single-hue HEATMAP — red at varying intensity, with
//              MEDIUM demoted to a near-invisible slate baseline.
//
// Mature SOC dashboards (Datadog, Splunk Security Cloud) use this
// pattern because it answers the only question that matters: "how
// much of this column is CRITICAL?" One eye-movement, one colour.
// MEDIUM as a slate baseline gives the bar mass without competing
// for attention; HIGH is muted red; CRITICAL caps the bar in solid
// red so it's the visual anchor.
const SEVERITY_STACK_ORDER: Array<{ key: string; label: string; color: string }> = [
  // Bottom-up: MEDIUM → CRITICAL. CRITICAL and HIGH colours swapped
  // per operator preference — HIGH gets the brighter alarm red (it
  // dominates by volume so the brighter shade reads), CRITICAL gets
  // the deeper red as its alarm cap.
  { key: "MEDIUM",   label: "Medium",   color: "#334155" }, // slate-700 — neutral baseline
  { key: "HIGH",     label: "High",     color: "#dc2626" }, // red-600 — alarm body
  { key: "CRITICAL", label: "Critical", color: "#7f1d1d" }, // red-900 — deep cap
];

function CodeCategoriesWidget({
  scanTypeCounts,
  severityByScanType,
}: {
  scanTypeCounts?: Array<{ scanType: string; _count: number }>;
  severityByScanType?: Array<{ scanType: string; severity: string; _count: number }>;
}) {
  const navigate = useNavigate();

  // Pivot the cross-product into recharts row shape:
  //   { name: "SCA", LOW: 12, MEDIUM: 4, HIGH: 5, CRITICAL: 2 }
  const pivot = new Map<string, Record<string, number | string>>();
  for (const row of severityByScanType ?? []) {
    if (!Object.prototype.hasOwnProperty.call(CODE_CATEGORY_LABEL, row.scanType)) continue;
    const label = CODE_CATEGORY_LABEL[row.scanType] ?? row.scanType;
    const cur = pivot.get(label) ?? { name: label, scanType: row.scanType };
    cur[row.severity] = ((cur[row.severity] as number | undefined) ?? 0) + row._count;
    pivot.set(label, cur);
  }
  // Ensure every category is present even if zero so the X axis is stable.
  for (const [key, label] of Object.entries(CODE_CATEGORY_LABEL)) {
    if (!pivot.has(label)) pivot.set(label, { name: label, scanType: key });
  }
  // Stable display order — alphabetical by category name.
  const chartData = [...pivot.values()].sort((a, b) =>
    String(a.name).localeCompare(String(b.name))
  );

  // Per-category total for the legend below.
  const totals = (scanTypeCounts ?? [])
    .filter((s) => Object.prototype.hasOwnProperty.call(CODE_CATEGORY_LABEL, s.scanType))
    .map((s) => ({
      key:   s.scanType,
      label: CODE_CATEGORY_LABEL[s.scanType] ?? s.scanType,
      total: s._count,
    }))
    .sort((a, b) => b.total - a.total);
  const grandTotal = totals.reduce((a, b) => a + b.total, 0);

  if (grandTotal === 0) {
    return (
      <>
        <div className="mb-4 flex items-center justify-between">
          <h2 className="text-sm font-semibold text-white">Code Findings by Category</h2>
        </div>
        <div className="flex h-48 flex-col items-center justify-center gap-2 text-center text-sm text-gray-500">
          <ShieldAlert className="h-8 w-8 text-gray-700" />
          <p>No code findings yet.</p>
          <p className="text-xs text-gray-600">Add a repo and run a scan to see the breakdown.</p>
        </div>
      </>
    );
  }

  return (
    <>
      <div className="mb-4 flex items-center justify-between">
        <h2 className="flex items-center gap-1.5 text-sm font-semibold text-white">
          <Code2 className="h-3.5 w-3.5 text-indigo-400" />
          Code Findings by Category
        </h2>
        <span className="text-[10px] uppercase tracking-wider text-gray-500">
          {grandTotal.toLocaleString()} total · severity composition
        </span>
      </div>

      <ResponsiveContainer width="100%" height={280}>
        {/* Wider columns: tightened category gap to 8% and bumped
            maxBarSize so the 5-category chart fills the space rather
            than leaving the bars looking pinched. */}
        <BarChart
          data={chartData}
          margin={{ top: 16, right: 24, bottom: 8, left: -8 }}
          barCategoryGap="8%"
          maxBarSize={110}
        >
          <CartesianGrid stroke="#1f2937" strokeDasharray="2 4" vertical={false} opacity={0.5} />
          <XAxis
            dataKey="name"
            tick={{ fontSize: 11, fill: "#9ca3af" }}
            axisLine={false}
            tickLine={false}
            tickMargin={10}
          />
          <YAxis
            tick={{ fontSize: 10, fill: "#4b5563" }}
            axisLine={false}
            tickLine={false}
            width={36}
          />
          <Tooltip
            cursor={{ fill: "#1f293730" }}
            contentStyle={{
              background:    "#111827",
              border:        "1px solid #1f2937",
              borderRadius:  8,
              padding:       "8px 12px",
              boxShadow:     "0 4px 12px rgba(0,0,0,0.4)",
            }}
            labelStyle={{ color: "#f3f4f6", fontWeight: 600, marginBottom: 4 }}
            itemStyle={{ color: "#9ca3af", padding: "1px 0" }}
            formatter={(value: number, name: string) => [value.toLocaleString(), name]}
          />
          {SEVERITY_STACK_ORDER.map(({ key, label, color }) => (
            <Bar
              key={key}
              dataKey={key}
              name={label}
              stackId="severity"
              fill={color}
              // Round only the topmost segment so each column has a
              // single rounded cap (rounds-on-each-segment looks
              // staircase-y on stacked bars).
              radius={key === "CRITICAL" ? [3, 3, 0, 0] : 0}
            />
          ))}
        </BarChart>
      </ResponsiveContainer>

      {/* Footer — clickable category totals + severity legend.
          Increased gap, fainter chrome, smaller legend swatches so the
          chart itself stays the dominant element on the card. */}
      <div className="mt-4 flex flex-wrap items-center justify-between gap-x-4 gap-y-2">
        <ul className="flex flex-wrap gap-1.5">
          {totals.map((t) => (
            <li key={t.key}>
              <button
                type="button"
                onClick={() => navigate(`/findings?tab=code&scanType=${t.key}`)}
                className="inline-flex items-center gap-2 rounded-md border border-gray-800/80 bg-transparent px-2.5 py-1 text-[11px] text-gray-400 transition-colors hover:border-indigo-700/70 hover:text-indigo-200"
              >
                <span>{t.label}</span>
                <span className="font-mono text-gray-600">{t.total.toLocaleString()}</span>
              </button>
            </li>
          ))}
        </ul>
        <ul className="flex items-center gap-3 text-[10px] uppercase tracking-wide text-gray-500">
          {SEVERITY_STACK_ORDER.slice().reverse().map(({ key, label, color }) => (
            <li key={key} className="inline-flex items-center gap-1.5">
              <span
                className="h-1.5 w-3 rounded-sm"
                style={{ backgroundColor: color }}
                aria-hidden
              />
              {label}
            </li>
          ))}
        </ul>
      </div>
    </>
  );
}

// ── Exploits widget ──────────────────────────────────────────────────────
//
// Replaces the previous "Severity bars" + "Top Risk Targets" widgets
// with a single actionable view: the recent CONFIRMED exploits scoped
// to the active tab. The operator's first question on a SOC dashboard
// is "what's actually exploitable right now?" — this widget answers it
// directly instead of forcing them to read severity counts and infer.
//
// Per-tab data source:
//   Code/Web → findingsApi.list({ confidence: "CONFIRMED", scanType: <tab> })
//             — covers SAST/SCA/SECRET/IAC/CONTAINER for Code, DAST/PENTEST_FULL for Web.
//             Maps cleanly to the EXPLOIT badge predicate `wasExploitSuccessful`.
//   Runtime  → findingsApi.list({ scanType: "RUNTIME", severity: "CRITICAL,HIGH" })
//             — RUNTIME exploits typically have confidence=POSSIBLE (scanner
//             didn't reproduce, IDS observed). Filtering by severity gives
//             the highest-signal subset; the EXPLOIT badge then renders for
//             the ones that actually qualify (the predicate evaluates
//             evidence client-side per row).
// ── CSPM (Cloud) widget ─────────────────────────────────────────────────
//
// Phase 29 — replaces the Exploits widget for the Cloud tab. Three sub-
// panels stacked in the 2-column grid slot:
//
//   1. Top Affected Services  — group findings by Prowler service prefix
//                                (defender / monitor / network / storage /
//                                vm / iam / etc). Bar chart sorted by count.
//                                Operators triage CSPM by service first
//                                ("fix Defender") before drilling into
//                                individual checks.
//
//   2. Compliance Coverage    — top frameworks by % of findings tagged.
//                                Each finding maps to ~12 frameworks; this
//                                view shows where audit prep most needs
//                                to start ("CIS Azure 5.0 has 80% of our
//                                misconfigs flagged").
//
//   3. Top Failing Checks     — most-recurring ruleId with severity chip
//                                and count. Surfaces concrete patterns
//                                like "network_flow_log_captured_sent
//                                fails on 4 watchers" — the actionable
//                                remediation queue.
//
// Empty state when no cloud findings exist — points to the Cloud
// Accounts page so the operator can configure + scan.

function CloudCspmWidget({
  findings,
  isLoading,
}: {
  findings:  Finding[];
  isLoading: boolean;
}) {
  const navigate = useNavigate();

  // ── Aggregations (memo-free; the widget renders rarely + the
  //    findings list is bounded at ~100 by the parent query) ─────────────
  const total = findings.length;

  // Service grouping — Prowler check IDs follow `{service}_{rest_of_check}`.
  // Take the first underscore-delimited token as the service prefix.
  const serviceCounts = new Map<string, number>();
  for (const f of findings) {
    const svc = (f.ruleId ?? "").split("_")[0] || "other";
    serviceCounts.set(svc, (serviceCounts.get(svc) ?? 0) + 1);
  }
  const topServices = [...serviceCounts.entries()]
    .sort((a, b) => b[1] - a[1])
    .slice(0, 6);
  const maxServiceCount = topServices[0]?.[1] ?? 1;

  // Compliance framework hit counts — extract distinct framework keys
  // from each finding's evidence.compliance map and tally how many
  // findings hit each.
  const fwCounts = new Map<string, number>();
  for (const f of findings) {
    const ev = (f.evidence ?? {}) as Record<string, unknown>;
    const compliance = (ev["compliance"] ?? {}) as Record<string, unknown>;
    for (const fw of Object.keys(compliance)) {
      fwCounts.set(fw, (fwCounts.get(fw) ?? 0) + 1);
    }
  }
  const topFrameworks = [...fwCounts.entries()]
    .sort((a, b) => b[1] - a[1])
    .slice(0, 7);

  // Top failing checks — group by ruleId, display the human-readable
  // TITLE from one of the findings in the group (e.g. "Storage account
  // has shared key access enabled.") rather than the raw Prowler ruleId
  // ("storage_account_key_access_disabled"). Operator feedback: the
  // ruleId alone reads as technical jargon. We keep the ruleId as a
  // small monospace subtitle for click-through search compatibility.
  const checkCounts = new Map<string, { count: number; severity: string; title: string }>();
  for (const f of findings) {
    const id = f.ruleId ?? "unknown";
    const cur = checkCounts.get(id) ?? { count: 0, severity: f.severity, title: f.title || id };
    cur.count++;
    // Keep the highest-severity instance (CRITICAL > HIGH > MEDIUM > LOW > INFO)
    const sevRank: Record<string, number> = { CRITICAL: 4, HIGH: 3, MEDIUM: 2, LOW: 1, INFO: 0 };
    if ((sevRank[f.severity] ?? 0) > (sevRank[cur.severity] ?? 0)) cur.severity = f.severity;
    // Prefer a title from a higher-severity instance (and fall back to
    // the first non-empty title we see).
    if (!cur.title || cur.title === id) cur.title = f.title || cur.title;
    checkCounts.set(id, cur);
  }
  const topChecks = [...checkCounts.entries()]
    .sort((a, b) => b[1].count - a[1].count)
    .slice(0, 5);

  // ── Empty state ────────────────────────────────────────────────────
  if (!isLoading && total === 0) {
    return (
      <div className="flex h-full flex-col items-center justify-center text-center">
        <CloudIcon className="mx-auto mb-3 h-10 w-10 text-gray-700" />
        <h3 className="text-sm font-semibold text-white">No cloud findings yet</h3>
        <p className="mt-1 max-w-md text-xs text-gray-500">
          Add a cloud account and trigger a CSPM scan. Prowler will evaluate
          ~250 Azure (or AWS/GCP) misconfiguration checks against your subscription.
        </p>
        <button
          onClick={() => navigate("/cloud-accounts")}
          className="mt-4 inline-flex items-center gap-1.5 rounded bg-indigo-700 px-3 py-1.5 text-sm font-medium text-white hover:bg-indigo-600"
        >
          <Plus className="h-4 w-4" /> Configure cloud account
        </button>
      </div>
    );
  }

  return (
    <>
      <div className="mb-4 flex items-center justify-between">
        <h2 className="flex items-center gap-1.5 text-sm font-semibold text-white">
          <CloudIcon className="h-3.5 w-3.5 text-indigo-400" />
          Cloud Misconfigurations
        </h2>
        <span className="text-[10px] uppercase tracking-wider text-gray-500">
          {total} open {total === 1 ? "finding" : "findings"}
        </span>
      </div>

      <div className="grid grid-cols-1 gap-5 lg:grid-cols-2">
        {/* Top Affected Services */}
        <div>
          <div className="mb-2 text-[10px] uppercase tracking-wider text-gray-500">
            Top affected services
          </div>
          <div className="space-y-1.5">
            {topServices.map(([svc, count]) => {
              const pct = Math.round((count / maxServiceCount) * 100);
              return (
                <button
                  key={svc}
                  onClick={() => navigate(`/findings?tab=cloud&search=${encodeURIComponent(svc)}`)}
                  className="block w-full text-left"
                  title={`Filter findings to '${svc}' service`}
                >
                  <div className="mb-0.5 flex items-center justify-between text-[11px]">
                    <span className="font-mono text-gray-300">{svc}</span>
                    <span className="tabular-nums font-semibold text-gray-200">{count}</span>
                  </div>
                  <div className="h-1.5 w-full overflow-hidden rounded-full bg-gray-800">
                    <div
                      className="h-full rounded-full bg-indigo-500/70"
                      style={{ width: `${pct}%` }}
                    />
                  </div>
                </button>
              );
            })}
            {topServices.length === 0 && (
              <div className="text-xs text-gray-500">—</div>
            )}
          </div>
        </div>

        {/* Compliance Coverage */}
        <div>
          <div className="mb-2 text-[10px] uppercase tracking-wider text-gray-500">
            Compliance coverage · {fwCounts.size} frameworks mapped
          </div>
          <div className="space-y-1.5">
            {topFrameworks.map(([fw, count]) => {
              const pct = Math.round((count / Math.max(total, 1)) * 100);
              const label = fw.replace(/-\d.*$/, "");
              return (
                <div key={fw}>
                  <div className="mb-0.5 flex items-center justify-between text-[11px]">
                    <span
                      className="truncate font-medium text-gray-300"
                      title={`${fw}: ${count} of ${total} findings tagged`}
                    >
                      {label}
                    </span>
                    <span className="tabular-nums text-gray-500">
                      {pct}%
                      <span className="ml-1 text-gray-600">·</span>
                      <span className="ml-1 tabular-nums text-gray-300">{count}</span>
                    </span>
                  </div>
                  <div className="h-1.5 w-full overflow-hidden rounded-full bg-gray-800">
                    <div
                      className="h-full rounded-full bg-rose-500/60"
                      style={{ width: `${pct}%` }}
                    />
                  </div>
                </div>
              );
            })}
            {topFrameworks.length === 0 && (
              <div className="text-xs text-gray-500">No compliance mappings</div>
            )}
          </div>
        </div>
      </div>

      {/* Top Failing Checks — full width below the two columns */}
      <div className="mt-5 border-t border-gray-800 pt-4">
        <div className="mb-2 text-[10px] uppercase tracking-wider text-gray-500">
          Top failing checks
        </div>
        <div className="space-y-1.5">
          {topChecks.map(([ruleId, { count, severity, title }]) => (
            <button
              key={ruleId}
              onClick={() => navigate(`/findings?tab=cloud&search=${encodeURIComponent(ruleId)}`)}
              className="flex w-full items-center justify-between gap-3 rounded border border-gray-800 bg-gray-900/40 px-3 py-1.5 text-left transition-colors hover:border-gray-700 hover:bg-gray-900/60"
              title={`${title}\n\n${ruleId}`}
            >
              <span className="flex items-center gap-2 min-w-0">
                <SeverityBadge severity={severity} />
                <span className="min-w-0 flex-1">
                  {/* Lead line: human-readable title (operator-facing). */}
                  <span className="block truncate text-xs text-gray-100">{title}</span>
                  {/* Subline: Prowler ruleId in monospace (technical
                      reference + matches what the search filter
                      receives on click). Only shows when title differs
                      from ruleId so we don't double-print. */}
                  {title !== ruleId && (
                    <span className="block truncate font-mono text-[10px] text-gray-500">{ruleId}</span>
                  )}
                </span>
              </span>
              <span className="tabular-nums rounded bg-gray-800 px-1.5 py-0.5 text-[10px] font-semibold text-gray-300">
                {count}
              </span>
            </button>
          ))}
          {topChecks.length === 0 && (
            <div className="text-xs text-gray-500">—</div>
          )}
        </div>
      </div>
    </>
  );
}

// ── Phase 29 Slice C1 — GitHub posture widget ───────────────────────────
//
// Mirrors CloudCspmWidget's shape (Top Failing Checks + secondary
// breakdown) but tailored to the 24-check GitHub posture surface:
//
//   - The "service" axis is uninteresting (only 3 services: organization /
//     repository / githubactions). Replaced with a "Top affected repos"
//     section because the operator's actual triage axis is "which repo
//     needs attention first".
//   - No compliance frameworks section. Prowler's GitHub provider doesn't
//     ship framework mappings on these checks (yet); when it does, this
//     widget gains a third column.
//   - Stat header: total findings + distinct repos affected.
function GitHubPostureWidget({
  findings,
  isLoading,
}: {
  findings:  Finding[];
  isLoading: boolean;
}) {
  const navigate = useNavigate();
  // Phase 29 Slice C1.4 — drawer state for the per-repo posture checklist.
  // Selected key matches the keying scheme used in the Top Affected Repos
  // aggregation below: real repositoryId for repo rows, "__org__" for the
  // bucket of org-level findings.
  const [drawerKey, setDrawerKey] = useState<string | null>(null);

  const total = findings.length;

  // Distinct repos affected — operator-relevant unit. Org-level findings
  // (targetType === GITHUB_ACCOUNT) don't have a repositoryId; bucket
  // them under a synthetic "(organization)" key so they're not lost.
  //
  // Phase 29 Slice C1.5a — also pull visibility (private?) + archived?
  // + pushedAt off the FIRST finding's evidence.github.repository for
  // each repo. All findings on the same repo carry the same snapshot,
  // so the first one wins.
  type RepoBucket = {
    count:     number;
    severity:  string;
    label:     string;
    private:   boolean | null;
    archived:  boolean | null;
    pushedAt:  string | null;
  };
  const repoCounts = new Map<string, RepoBucket>();
  for (const f of findings) {
    const repoId = (f as Record<string, unknown>)["repositoryId"] as string | undefined;
    const repoFullName = ((f as Record<string, unknown>)["repository"] as Record<string, unknown> | undefined)?.["fullName"] as string | undefined;
    const ev = (f.evidence ?? {}) as Record<string, unknown>;
    const gh = (ev["github"] ?? {}) as Record<string, unknown>;
    const repoMeta = (gh["repository"] ?? null) as Record<string, unknown> | null;

    // Phase 29 Slice C1.5a — bucket-key resolution mirrors postureMetrics:
    // FK > evidence.github.repository.fullName > "__org__" sentinel.
    // Posture scans don't auto-create Repository rows so the FK is
    // usually null for these findings — without falling back to fullName,
    // every finding fell into __org__ and the Top Affected Repos chart
    // showed "(organization-level)" for everything.
    const evidenceFullName = (repoMeta?.["fullName"] as string | undefined) ?? null;
    const key = repoId
      ?? (evidenceFullName ? `gh:${evidenceFullName}` : "__org__");
    const label = repoFullName
      ?? evidenceFullName
      ?? (key === "__org__" ? "(organization-level)" : "(unknown repo)");

    const cur = repoCounts.get(key) ?? {
      count: 0,
      severity: f.severity,
      label,
      private:  (repoMeta?.["private"]  as boolean | undefined) ?? null,
      archived: (repoMeta?.["archived"] as boolean | undefined) ?? null,
      pushedAt: (repoMeta?.["pushedAt"] as string | undefined) ?? null,
    };
    cur.count++;
    const sevRank: Record<string, number> = { CRITICAL: 4, HIGH: 3, MEDIUM: 2, LOW: 1, INFO: 0 };
    if ((sevRank[f.severity] ?? 0) > (sevRank[cur.severity] ?? 0)) cur.severity = f.severity;
    // Backfill metadata if the first finding didn't have it (older
    // findings without rich evidence get refreshed on the next scan).
    if (cur.private === null && repoMeta?.["private"] !== undefined) cur.private = repoMeta["private"] as boolean;
    if (cur.archived === null && repoMeta?.["archived"] !== undefined) cur.archived = repoMeta["archived"] as boolean;
    if (cur.pushedAt === null && repoMeta?.["pushedAt"] !== undefined) cur.pushedAt = repoMeta["pushedAt"] as string;
    repoCounts.set(key, cur);
  }
  const topRepos = [...repoCounts.entries()]
    .sort((a, b) => b[1].count - a[1].count)
    .slice(0, 6);

  // Format pushedAt as a compact relative for the widget bar rows.
  const formatPush = (iso: string | null): string => {
    if (!iso) return "";
    try {
      const d = new Date(iso);
      const days = Math.floor((Date.now() - d.getTime()) / (1000 * 60 * 60 * 24));
      if (days < 1)   return "today";
      if (days < 2)   return "yesterday";
      if (days < 30)  return `${days}d ago`;
      if (days < 365) return `${Math.floor(days / 30)}mo ago`;
      return `${Math.floor(days / 365)}y ago`;
    } catch { return ""; }
  };

  // Top failing checks — same logic as CloudCspmWidget. Group by ruleId,
  // surface human-readable title with ruleId subtitle for technical
  // reference + click-through search compatibility.
  const checkCounts = new Map<string, { count: number; severity: string; title: string }>();
  for (const f of findings) {
    const id = f.ruleId ?? "unknown";
    const cur = checkCounts.get(id) ?? { count: 0, severity: f.severity, title: f.title || id };
    cur.count++;
    const sevRank: Record<string, number> = { CRITICAL: 4, HIGH: 3, MEDIUM: 2, LOW: 1, INFO: 0 };
    if ((sevRank[f.severity] ?? 0) > (sevRank[cur.severity] ?? 0)) cur.severity = f.severity;
    if (!cur.title || cur.title === id) cur.title = f.title || cur.title;
    checkCounts.set(id, cur);
  }
  const topChecks = [...checkCounts.entries()]
    .sort((a, b) => b[1].count - a[1].count)
    .slice(0, 10);  // 10 per the plan doc — operator-relevant subset of 24

  // Empty state
  if (!isLoading && total === 0) {
    return (
      <div className="flex h-full flex-col items-center justify-center text-center">
        <Code2 className="mx-auto mb-3 h-10 w-10 text-gray-700" />
        <h3 className="text-sm font-semibold text-white">No GitHub posture findings yet</h3>
        <p className="mt-1 max-w-md text-xs text-gray-500">
          Add a GitHub account and trigger a posture scan. Prowler will evaluate
          24 checks across your organization, repositories, and workflows
          (MFA enforcement, branch protection, secret scanning, dependabot,
          CODEOWNERS, signed commits, etc.).
        </p>
        <button
          onClick={() => navigate("/github-accounts")}
          className="mt-4 inline-flex items-center gap-1.5 rounded bg-indigo-700 px-3 py-1.5 text-sm font-medium text-white hover:bg-indigo-600"
        >
          <Plus className="h-4 w-4" /> Configure GitHub account
        </button>
      </div>
    );
  }

  return (
    <>
      <div className="mb-4 flex items-center justify-between">
        <h2 className="flex items-center gap-1.5 text-sm font-semibold text-white">
          <Code2 className="h-3.5 w-3.5 text-indigo-400" />
          GitHub Posture Misconfigurations
        </h2>
        <span className="text-[10px] uppercase tracking-wider text-gray-500">
          {total} open · {repoCounts.size - (repoCounts.has("__org__") ? 1 : 0)} repo{repoCounts.size === 2 ? "" : "s"} affected
        </span>
      </div>

      {/* Top affected repos — primary triage axis for posture findings */}
      <div>
        <div className="mb-2 text-[10px] uppercase tracking-wider text-gray-500">
          Top affected repositories
        </div>
        <div className="space-y-1.5">
          {topRepos.map(([key, bucket]) => {
            const { count, label, private: isPrivate, archived, pushedAt } = bucket;
            const max = topRepos[0]?.[1].count ?? 1;
            const pct = Math.round((count / max) * 100);
            const isOrg = key === "__org__";
            const pushedLabel = formatPush(pushedAt);
            return (
              <button
                key={key}
                onClick={() => setDrawerKey(key)}
                className="block w-full text-left"
                title={`View posture checklist for ${label}`}
              >
                <div className="mb-0.5 flex items-center justify-between gap-2 text-[11px]">
                  <span className="flex min-w-0 items-center gap-1.5">
                    <span className="truncate font-mono text-gray-300">{label}</span>
                    {/* Phase 29 Slice C1.5a — visibility chips. Public is
                        amber-tinted (urgency signal); Private is neutral
                        gray. Archived chip stacks if the repo is read-only
                        — those are still scannable but typically lower
                        triage priority. */}
                    {!isOrg && isPrivate === false && (
                      <span className="inline-flex items-center gap-0.5 rounded border border-amber-800/40 bg-amber-900/30 px-1 py-0.5 text-[9px] font-medium text-amber-300" title="Public repo — broken posture has the widest blast radius">
                        <Unlock className="h-2 w-2" /> Public
                      </span>
                    )}
                    {!isOrg && isPrivate === true && (
                      <span className="inline-flex items-center gap-0.5 rounded bg-gray-800 px-1 py-0.5 text-[9px] font-medium text-gray-400">
                        <Lock className="h-2 w-2" /> Private
                      </span>
                    )}
                    {archived && (
                      <span className="inline-flex items-center gap-0.5 rounded bg-gray-800 px-1 py-0.5 text-[9px] font-medium text-gray-500">
                        <Archive className="h-2 w-2" /> Archived
                      </span>
                    )}
                  </span>
                  <span className="flex shrink-0 items-center gap-2">
                    {pushedLabel && !isOrg && (
                      <span className="text-[10px] text-gray-500" title={pushedAt ?? undefined}>
                        push {pushedLabel}
                      </span>
                    )}
                    <span className="tabular-nums font-semibold text-gray-200">{count}</span>
                  </span>
                </div>
                <div className="h-1.5 w-full overflow-hidden rounded-full bg-gray-800">
                  <div
                    className="h-full rounded-full bg-indigo-500/70"
                    style={{ width: `${pct}%` }}
                  />
                </div>
              </button>
            );
          })}
          {topRepos.length === 0 && (
            <div className="text-xs text-gray-500">—</div>
          )}
        </div>
      </div>

      {/* Top failing checks — full width below */}
      <div className="mt-5 border-t border-gray-800 pt-4">
        <div className="mb-2 text-[10px] uppercase tracking-wider text-gray-500">
          Top failing checks · {checkCounts.size} of 24 distinct
        </div>
        <div className="space-y-1.5">
          {topChecks.map(([ruleId, { count, severity, title }]) => (
            <button
              key={ruleId}
              onClick={() => navigate(`/findings?tab=code&sub=posture&search=${encodeURIComponent(ruleId)}`)}
              className="flex w-full items-center justify-between gap-3 rounded border border-gray-800 bg-gray-900/40 px-3 py-1.5 text-left transition-colors hover:border-gray-700 hover:bg-gray-900/60"
              title={`${title}\n\n${ruleId}`}
            >
              <span className="flex items-center gap-2 min-w-0">
                <SeverityBadge severity={severity} />
                <span className="min-w-0 flex-1">
                  <span className="block truncate text-xs text-gray-100">{title}</span>
                  {title !== ruleId && (
                    <span className="block truncate font-mono text-[10px] text-gray-500">{ruleId}</span>
                  )}
                </span>
              </span>
              <span className="tabular-nums rounded bg-gray-800 px-1.5 py-0.5 text-[10px] font-semibold text-gray-300">
                {count}
              </span>
            </button>
          ))}
          {topChecks.length === 0 && (
            <div className="text-xs text-gray-500">—</div>
          )}
        </div>
      </div>

      {/* Phase 29 Slice C1.4 — Per-repo (or per-org) posture checklist drawer.
          Opens when a Top Affected Repos row is clicked. Renders all 24
          checks with ✓/✗ status; clicking a FAIL row routes to the
          existing FindingDetailDrawer for triage. */}
      {drawerKey != null && (
        <RepoPostureDrawer
          open={true}
          onClose={() => setDrawerKey(null)}
          scope={drawerKey === "__org__" ? "organization" : "repository"}
          targetLabel={
            drawerKey === "__org__"
              ? "(organization-level)"
              : (repoCounts.get(drawerKey)?.label ?? drawerKey)
          }
          findings={findings}
          repositoryId={drawerKey === "__org__" ? undefined : drawerKey}
        />
      )}
    </>
  );
}

function ExploitsWidget({
  tab, runtimeDash, exploits, isLoading,
}: {
  tab: "code" | "web" | "runtime" | "cloud";
  runtimeDash?: RuntimeDashboardResponse;
  // Pre-filtered exploits from the parent — already passes the badge
  // predicate (wasExploitSuccessful for Code/Web, hasActiveAttack for
  // Runtime). Sharing this list with the parent's stat card keeps the
  // count + the rendered rows consistent.
  exploits:    Finding[];
  isLoading:   boolean;
}) {
  const navigate = useNavigate();
  const exploitsBadged = exploits;

  const tabLabel =
    tab === "runtime" ? "Runtime"
    : tab === "web"   ? "Web"
    : tab === "cloud" ? "Cloud"
    :                   "Code";

  return (
    <>
      <div className="mb-4 flex items-center justify-between">
        <h2 className="flex items-center gap-1.5 text-sm font-semibold text-white">
          <AlertTriangle className="h-3.5 w-3.5 text-red-400" />
          {tab === "runtime" ? "Runtime Attacks" : `${tabLabel} Exploits`}
        </h2>
        <span className="text-[10px] uppercase tracking-wider text-gray-500">
          {tab === "runtime" ? "Observed · Attack-tagged" : "Recent Confirmed"}
        </span>
      </div>

      {/* Runtime-specific: tactic chip strip stays as a quick scan above
          the list since it answers the kill-chain question at a glance.
          Code/Web don't have an equivalent; their list is enough. */}
      {tab === "runtime" && (runtimeDash?.mitreTactics?.length ?? 0) > 0 && (
        <div className="mb-3 flex flex-wrap gap-1.5">
          {runtimeDash!.mitreTactics.slice(0, 6).map((t) => (
            <button
              key={t.tactic}
              type="button"
              onClick={() => navigate(`/findings?tab=runtime&mitreTactic=${encodeURIComponent(t.tactic)}`)}
              className="inline-flex items-center gap-1 rounded-full border border-indigo-900/50 bg-indigo-950/30 px-2 py-0.5 text-[10px] text-indigo-300 hover:border-indigo-700 hover:text-indigo-200"
              title={`Filter runtime findings to ${t.tactic}`}
            >
              {t.tactic}
              <span className="font-mono text-indigo-400/80">{t.count}</span>
            </button>
          ))}
        </div>
      )}

      {isLoading ? (
        <div className="flex h-48 items-center justify-center text-xs text-gray-500">Loading…</div>
      ) : exploitsBadged.length === 0 ? (
        <div className="flex h-48 flex-col items-center justify-center gap-2 text-center text-sm text-gray-500">
          <ShieldAlert className="h-8 w-8 text-gray-700" />
          <p>
            {tab === "runtime"
              ? "No attack-tagged runtime alerts."
              : `No confirmed ${tabLabel.toLowerCase()} exploits.`}
          </p>
          <p className="text-xs text-gray-600">
            {tab === "runtime"
              ? "Wazuh hasn't fired any rules in the attack/exploit/intrusion groups, and no offensive MITRE tactics have been classified."
              : "Run a scan and any reproduced exploits will land here."}
          </p>
        </div>
      ) : (() => {
        // For Runtime: surface EXPLOITs first, then ATTACKs.
        // The operator's eye should land on landed-attacks first;
        // attempted-but-not-landed attacks go below.
        // Within each group keep recency order (already sorted by
        // lastSeen desc from the API).
        const ordered = tab === "runtime"
          ? [
              ...exploitsBadged.filter(wasExploitSuccessful),
              ...exploitsBadged.filter((f) => !wasExploitSuccessful(f)),
            ]
          : exploitsBadged;
        return (
        <ul className="divide-y divide-gray-800/60">
          {ordered.slice(0, 8).map((f) => (
            <li key={f.id}>
              <button
                type="button"
                onClick={() => navigate(`/findings?tab=${tab}&id=${f.id}`)}
                className="flex w-full items-center gap-3 px-1 py-2 text-left transition-colors hover:bg-gray-800/40"
              >
                <SeverityBadge severity={f.severity} />
                <div className="min-w-0 flex-1">
                  <div className="flex items-center gap-2">
                    <div className="truncate text-sm text-gray-200">{f.title}</div>
                    {/* Tier badge — EXPLOIT (landed) wins over ATTACK
                        (attempted) so the operator sees the highest-tier
                        signal per row. Same predicates the Findings table
                        uses, so badge meaning stays consistent across the
                        platform. */}
                    {wasExploitSuccessful(f)
                      ? <ExploitSuccessBadge size="sm" />
                      : hasActiveAttack(f) && <ActiveAttackBadge size="sm" />}
                  </div>
                  <div className="mt-0.5 flex items-center gap-2 text-[11px] text-gray-500">
                    <span className="font-mono">{f.scanner}</span>
                    {f.targetName && <><span>·</span><span className="truncate">{f.targetName}</span></>}
                    <span>·</span>
                    <span>{formatRelative(f.lastSeen)}</span>
                  </div>
                </div>
                <ArrowRight className="h-3.5 w-3.5 flex-shrink-0 text-gray-600" />
              </button>
            </li>
          ))}
        </ul>
        );
      })()}

      {exploitsBadged.length > 0 && (
        <Link
          // Match the link's destination filter to the widget's
          // displayed set so card-count + destination-count agree:
          //   Runtime  → severity=CRITICAL,HIGH,MEDIUM (matches the
          //              filteredExploits floor we apply on the
          //              dashboard; without it the destination shows
          //              all 61 runtime findings including LOW/INFO
          //              noise that the dashboard correctly hides)
          //   Code/Web → confidence=CONFIRMED (CONFIRMED-confidence
          //              filter; for Web that's the canonical exploit
          //              source — RUNTIME doesn't carry CONFIRMED).
          to={
            tab === "runtime"
              // No tag here — show both EXPLOIT + ATTACK rows since
              // the widget displays both. Severity floor matches.
              ? `/findings?tab=runtime&severity=CRITICAL,HIGH,MEDIUM`
              : `/findings?tab=${tab}&confidence=CONFIRMED`
          }
          className="mt-3 inline-flex items-center gap-1 text-xs text-indigo-400 hover:text-indigo-300"
        >
          {tab === "runtime"
            ? "View all runtime findings"
            : `View all confirmed ${tabLabel.toLowerCase()} findings`}
          <ArrowRight className="h-3 w-3" />
        </Link>
      )}
    </>
  );
}

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

// ── Target filter dropdown ─────────────────────────────────────────────────
//
// Combined picker across repos / containers / domains. We deliberately
// don't render three separate dropdowns — operators think in terms of
// "this asset", not "this kind of asset", and a single combined picker
// makes the URL state simple (`target=repo:<id>` etc).
//
// Disclosure UI uses a native `<details>` element so the click-outside-to-
// close + keyboard accessibility comes for free, no portal / focus-trap
// dance needed.
function TargetFilter({
  value, repos, containers, domains, onChange,
}: {
  value:      string;
  repos:      Array<{ id: string; fullName?: string; name?: string }>;
  containers: Array<{ id: string; imageRef: string }>;
  domains:    Array<{ id: string; domain: string }>;
  onChange:   (kind: "repo" | "container" | "domain" | null, id: string | null) => void;
}) {
  // Show the active selection's name in the trigger so the operator can
  // see what they've scoped to without opening the menu.
  const m = value.match(/^(repo|container|domain):([\w-]+)$/);
  const activeKind = m ? (m[1] as "repo" | "container" | "domain") : null;
  const activeId   = m ? m[2]! : null;
  const activeName =
    activeKind === "repo"      ? (repos.find((r)      => r.id === activeId)?.fullName ?? repos.find((r)      => r.id === activeId)?.name)
  : activeKind === "container" ? containers.find((c)  => c.id === activeId)?.imageRef
  : activeKind === "domain"    ? domains.find((d)     => d.id === activeId)?.domain
  :                              null;
  const label = value && activeName ? activeName : "All targets";

  return (
    <details className="relative group">
      <summary className="flex cursor-pointer list-none items-center gap-1.5 rounded-lg border border-gray-700 bg-gray-900 px-3 py-1.5 text-xs font-medium text-gray-300 hover:border-indigo-600 hover:text-white">
        <Filter className="h-3.5 w-3.5" />
        <span className="max-w-[180px] truncate">{label}</span>
        <ChevronDown className="h-3 w-3 opacity-60" />
      </summary>
      <div className="absolute left-0 z-30 mt-1 max-h-96 w-72 overflow-y-auto rounded-lg border border-gray-700 bg-gray-900 shadow-xl">
        <button
          onClick={(e) => { e.preventDefault(); onChange(null, null); (e.currentTarget.closest("details") as HTMLDetailsElement | null)?.removeAttribute("open"); }}
          className={`flex w-full items-center justify-between border-b border-gray-800 px-3 py-2 text-left text-xs ${
            !value ? "bg-indigo-950/40 text-indigo-200" : "text-gray-300 hover:bg-gray-800"
          }`}
        >
          <span>All targets</span>
          {!value && <Check className="h-3.5 w-3.5" />}
        </button>

        <TargetGroup
          title="Repositories" icon={<GitBranch className="h-3 w-3" />}
          rows={repos.map((r) => ({ id: r.id, label: r.fullName ?? r.name ?? r.id }))}
          activeId={activeKind === "repo" ? activeId : null}
          onPick={(id) => onChange("repo", id)}
        />
        <TargetGroup
          title="Containers" icon={<Box className="h-3 w-3" />}
          rows={containers.map((c) => ({ id: c.id, label: c.imageRef }))}
          activeId={activeKind === "container" ? activeId : null}
          onPick={(id) => onChange("container", id)}
        />
        <TargetGroup
          title="Domains" icon={<Globe className="h-3 w-3" />}
          rows={domains.map((d) => ({ id: d.id, label: d.domain }))}
          activeId={activeKind === "domain" ? activeId : null}
          onPick={(id) => onChange("domain", id)}
        />
      </div>
    </details>
  );
}

function TargetGroup({
  title, icon, rows, activeId, onPick,
}: {
  title:    string;
  icon:     React.ReactNode;
  rows:     Array<{ id: string; label: string }>;
  activeId: string | null;
  onPick:   (id: string) => void;
}) {
  if (rows.length === 0) return null;
  return (
    <div className="border-b border-gray-800 last:border-b-0">
      <div className="flex items-center gap-1.5 bg-gray-950 px-3 py-1.5 text-[10px] uppercase tracking-wide text-gray-500">
        {icon}
        {title}
        <span className="ml-auto opacity-60">{rows.length}</span>
      </div>
      {rows.map((r) => (
        <button
          key={r.id}
          onClick={(e) => {
            e.preventDefault();
            onPick(r.id);
            (e.currentTarget.closest("details") as HTMLDetailsElement | null)?.removeAttribute("open");
          }}
          className={`flex w-full items-center justify-between px-3 py-1.5 text-left text-xs ${
            activeId === r.id ? "bg-indigo-950/40 text-indigo-200" : "text-gray-300 hover:bg-gray-800"
          }`}
        >
          <span className="truncate font-mono">{r.label}</span>
          {activeId === r.id && <Check className="h-3.5 w-3.5 flex-shrink-0" />}
        </button>
      ))}
    </div>
  );
}

export default function DashboardPage() {
  const navigate = useNavigate();
  // URL-driven tab so refreshes / shared links preserve which view the user
  // was on. Default to Code since most users add a repo first.
  const [searchParams, setSearchParams] = useSearchParams();
  const tabRaw = searchParams.get("tab");
  const tab: "code" | "web" | "runtime" | "cloud" =
    tabRaw === "web"     ? "web"
    : tabRaw === "runtime" ? "runtime"
    : tabRaw === "cloud"   ? "cloud"
    :                      "code";
  // Phase 29 Slice C1 — sub-pivot inside the Code tab. Same convention as
  // FindingsPage: default "vulnerabilities" preserves existing behaviour;
  // "posture" filters Recent Findings + stats to GITHUB_POSTURE.
  const subRaw = searchParams.get("sub");
  const sub: "vulnerabilities" | "posture" =
    subRaw === "posture" ? "posture" : "vulnerabilities";
  const setTab = (t: "code" | "web" | "runtime" | "cloud") => {
    setSearchParams((prev) => {
      if (t === "code") prev.delete("tab"); else prev.set("tab", t);
      // Sub-pivot is Code-tab-only; clear when leaving Code.
      if (t !== "code") prev.delete("sub");
      return prev;
    });
  };
  const setSub = (s: "vulnerabilities" | "posture") => {
    setSearchParams((prev) => {
      if (s === "vulnerabilities") prev.delete("sub"); else prev.set("sub", s);
      return prev;
    });
  };

  // Per-target scope filter — single combined dropdown across repos /
  // containers / domains. URL form: `?target=repo:<id>` (or container,
  // domain). Backend already supports repoId / containerId / domainId on
  // /findings, /findings/summary/stats, /findings/summary/top-rules. The
  // dropdown is tab-agnostic so the operator can mix scopes (e.g. show
  // me CONTAINER findings on a specific repo's image).
  const targetRaw = searchParams.get("target") ?? "";
  const [targetKind, targetId] = (() => {
    const m = targetRaw.match(/^(repo|container|domain):([\w-]+)$/);
    return m ? [m[1] as "repo" | "container" | "domain", m[2]!] : [null, null];
  })();
  const setTarget = (kind: "repo" | "container" | "domain" | null, id: string | null) => {
    setSearchParams((prev) => {
      if (!kind || !id) prev.delete("target");
      else prev.set("target", `${kind}:${id}`);
      return prev;
    });
  };
  // Translate the URL form into the per-field shape the API client wants.
  const targetParams = targetKind === "repo"      ? { repoId:      targetId! }
                     : targetKind === "container" ? { containerId: targetId! }
                     : targetKind === "domain"    ? { domainId:    targetId! }
                     :                              {};

  // Phase 29 Slice C1 — Code tab Posture sub-pivot narrows scope to GITHUB_POSTURE.
  // All downstream stats/exploits/findings queries inherit this via tabScanCsv.
  const tabScanTypes =
    tab === "web"     ? WEB_SCAN_TYPES
    : tab === "runtime" ? RUNTIME_SCAN_TYPES
    : tab === "cloud"   ? CLOUD_SCAN_TYPES
    : tab === "code" && sub === "posture" ? POSTURE_SCAN_TYPES
    :                    CODE_SCAN_TYPES;
  const tabScanCsv    = tabScanTypes.join(",");

  // Tab-scoped stats (severity / status / confidence). scanTypeCounts comes
  // back unscoped so we can derive the Code/Web tab badges in the header.
  // Target params (repo/container/domain) are applied here too, so the
  // cards re-count when the operator picks a single asset.
  const { data: stats } = useQuery({
    queryKey: ["findings", "stats", tab, targetRaw],
    queryFn: () => findingsApi.stats({ scanType: tabScanCsv, ...targetParams }),
  });
  // Unscoped stats — used only to render the Code / Web counts in the tab
  // strip itself. Tiny payload, cached separately, so switching tabs doesn't
  // refetch it.
  const { data: globalStats } = useQuery({
    queryKey: ["findings", "stats", "global"],
    queryFn: () => findingsApi.stats(),
  });
  const { data: repos } = useQuery({ queryKey: ["repos"], queryFn: reposApi.list });
  const { data: containers } = useQuery({ queryKey: ["containers"], queryFn: containersApi.list });
  const { data: domains } = useQuery({ queryKey: ["domains"], queryFn: domainsApi.list });
  // Phase 29 — cloud accounts for the CSPM tab's "Cloud Accounts" stats card.
  const { data: cloudAccounts } = useQuery({ queryKey: ["cloud-accounts"], queryFn: cloudAccountsApi.list });
  const { data: scans } = useQuery({
    queryKey: ["scans"],
    queryFn: () => scansApi.list(1, 20),
    refetchInterval: (query) => {
      const d = query.state.data;
      if (!d) return false;
      return d.data.some((s) => s.status === "PENDING" || s.status === "RUNNING") ? 3000 : false;
    },
  });
  // Tab-scoped recent findings — filtered server-side via scanType. Cache key
  // includes the tab + target so switching doesn't show stale rows.
  const { data: recentFindings } = useQuery({
    // Phase 29 Slice C1.5a — keyed on `sub` so the Code-tab Vulnerabilities
    // ↔ Posture sub-pivot triggers a refetch (without it, switching pivots
    // showed stale rows from the previous sub).
    queryKey: ["findings", "recent", tab, sub, targetRaw],
    queryFn: () => findingsApi.list({
      limit: 5, page: 1,
      scanType: tabScanCsv as never,
      ...targetParams,
    } as never),
  });
  // Top rules — kept; powers the lower-row "noisy rules" widget. The
  // Top Risk Targets list was removed when the Exploits widget took
  // over its grid slot — operators care about *which exploits* are
  // active more than which targets are noisiest.
  const { data: noisyRulesAll } = useQuery({
    queryKey: ["findings", "top-rules"],
    queryFn: () => findingsApi.topRules(20),
  });
  // Runtime-specific aggregation — only fetched when the Runtime tab is
  // active. Drives the MITRE-tactic chip strip inside the Exploits
  // widget (kill-chain summary above the exploit list).
  const { data: runtimeDash } = useQuery({
    queryKey: ["runtime-dashboard"],
    queryFn:  runtimeApi.dashboard,
    enabled:  tab === "runtime",
    refetchInterval: 30_000,
  });

  // Exploits query — lifted from inside ExploitsWidget so the parent
  // can compute the SAME filtered-exploit count for the lead stat card.
  // Without this, the card showed `confidenceCounts.CONFIRMED` (25) but
  // the widget showed only the 3 findings that actually had
  // `evidence.url + evidence.attack` populated; the operator's instinct
  // that "card and widget should match" was correct, the implementation
  // just wasn't honouring it.
  //
  // For non-RUNTIME we fetch the full tab-confirmed set (limit 100,
  // covers reasonable scale for a single org's scanner output) so the
  // count and the list both come from the same authoritative dataset.
  const exploitsQuery = useQuery({
    queryKey: ["dashboard-exploits", tab, sub, targetRaw],
    queryFn: () => findingsApi.list(
      tab === "runtime"
        ? { scanType: "RUNTIME" as never, limit: 100, ...targetParams }
      // Phase 29 — Cloud tab fetches CLOUD-scoped findings (no
      // confidence filter; Prowler checks are deterministic, every
      // FAIL is a misconfig, not a probabilistic exploit). Bumped
      // limit to 250 to cover the full Prowler check set without
      // truncation in the dashboard's CSPM widget.
        : tab === "cloud"
          ? { scanType: "CLOUD" as never, limit: 250, ...targetParams }
        // Phase 29 Slice C1 — Code tab Posture sub-pivot: same shape as
        // Cloud (deterministic Prowler checks, no confidence filter).
        // The widget aggregates by check + repository instead of treating
        // each FAIL as a probabilistic exploit.
        : tab === "code" && sub === "posture"
          ? { scanType: "GITHUB_POSTURE" as never, limit: 250, ...targetParams }
          : {
              scanType: (tab === "web" ? "DAST,PENTEST_FULL" : "SAST,SCA,SECRET,IAC,CONTAINER") as never,
              confidence: "CONFIRMED" as never,
              limit: 100,
              ...targetParams,
            },
    ),
    refetchInterval: 60_000,
  });
  // Apply the same predicate the badges use, so card-count and
  // widget-row-count agree by construction. For Runtime, additionally
  // drop LOW/INFO severity — a LOW-severity Wazuh detection shouldn't
  // earn the EXPLOIT escalation regardless of HTTP/audit signals
  // (Wazuh's rule.level <7 means "info / debug" — not real attack
  // surface). This stops "LOW · EXPLOIT" rows that read as
  // contradictory.
  const filteredExploits = (exploitsQuery.data?.data ?? []).filter((f) => {
    // Phase 29 — Cloud tab: NO predicate filter. Every FAIL Prowler
    // returned is a real misconfig; the CloudCspmWidget aggregates
    // services / frameworks / checks across the full set.
    if (tab === "cloud") return true;
    // Phase 29 Slice C1 — Code tab Posture sub-pivot follows the same
    // rule. Every Prowler GitHub check FAIL is deterministic; the
    // GitHubPostureWidget renders the full set without confidence
    // filtering.
    if (tab === "code" && sub === "posture") return true;
    if (tab !== "runtime") return wasExploitSuccessful(f);
    if (!hasActiveAttack(f)) return false;
    return f.severity === "CRITICAL" || f.severity === "HIGH" || f.severity === "MEDIUM";
  });
  const filteredExploitsCount = filteredExploits.length;

  // Per-tab slice for the noisy-rules widget.
  //
  // Phase 29 Slice C1.5a — sub-pivot scoping. Posture findings (GITHUB_POSTURE)
  // are DETERMINISTIC Prowler checks, not probabilistic detections. They
  // shouldn't appear in "Suppression Candidates" at all — there's nothing
  // to suppress, the failing setting either is or isn't. So:
  //   sub=posture       → empty (hide the widget below via the empty array)
  //   sub=vulnerabilities → exclude POSTURE in addition to web/runtime/cloud
  //                         so GitHub posture rules don't leak into the
  //                         Code-tier suppression list.
  const noisyRules   = (noisyRulesAll ?? []).filter((r) =>
    tab === "web"     ? WEB_TYPES_SET.has(r.scanType)
    : tab === "runtime" ? RUNTIME_TYPES_SET.has(r.scanType)
    : tab === "cloud"   ? CLOUD_TYPES_SET.has(r.scanType)
    : tab === "code" && sub === "posture" ? false  // suppression doesn't apply to deterministic checks
    // Code-Vulnerabilities — exclude web/runtime/cloud/posture so only
    // SAST/SCA/Secret/IAC/Container rules surface as noise candidates.
    :                    !WEB_TYPES_SET.has(r.scanType) && !RUNTIME_TYPES_SET.has(r.scanType) && !CLOUD_TYPES_SET.has(r.scanType) && !POSTURE_TYPES_SET.has(r.scanType),
  ).slice(0, 5);
  const tabScans = (scans?.data ?? []).filter((s) =>
    tab === "web"     ? s.targetType === "DOMAIN"
    : tab === "runtime" ? (s.scanTypes ?? []).includes("RUNTIME")
    : tab === "cloud"   ? s.targetType === "CLOUD_ACCOUNT"
    // Phase 29 Slice C1.5a — Code+Posture only shows GITHUB_ACCOUNT scans.
    : tab === "code" && sub === "posture" ? s.targetType === "GITHUB_ACCOUNT"
    // Code-Vulnerabilities — exclude DOMAIN + CLOUD_ACCOUNT + GITHUB_ACCOUNT
    // scans (those belong to Web / Cloud / Code-Posture respectively).
    // Without the GITHUB_ACCOUNT exclusion, GitHub posture scans showed
    // up under Recent Code Findings (operator-reported bug).
    :                    s.targetType !== "DOMAIN" && s.targetType !== "CLOUD_ACCOUNT" && s.targetType !== "GITHUB_ACCOUNT",
  ).slice(0, 6);

  const severityData = (stats?.severityCounts ?? []).map((s) => ({
    name: s.severity,
    value: s._count,
    color: SEVERITY_COLORS[s.severity] ?? "#6b7280",
  }));

  const totalFindings = severityData.reduce((a, b) => a + b.value, 0);
  const criticalCount = severityData.find((s) => s.name === "CRITICAL")?.value ?? 0;
  const highCount = severityData.find((s) => s.name === "HIGH")?.value ?? 0;

  // Phase 29 Slice C1.5b — code-vulnerabilities story metrics. Anchors
  // the 4 story cards on Code-Vulnerabilities sub-pivot to concrete
  // patterns (secrets / critical exposure / easy SCA wins / OWASP A03)
  // instead of generic severity counts. Numbers come from the existing
  // /findings/summary/stats endpoint, extended in Slice C1.5b with two
  // new aggregations:
  //   fixAvailableScaCount — SCA findings where the scanner already
  //                          supplied a fixVersion. Drives "Easy Wins".
  //   owaspA03Count        — SAST findings whose CWE maps to OWASP A03
  //                          Injection. Drives the OWASP card.
  const codeStoryMetrics = (() => {
    if (!(tab === "code" && sub === "vulnerabilities")) return null;
    if (!stats) return null;

    // Secret findings — every one is high-priority by nature (a
    // committed credential is a leak path regardless of scanner
    // confidence). Sum across statuses; the stats payload already
    // excludes FALSE_POSITIVE / IGNORED.
    const secretsCount = (stats.scanTypeCounts ?? [])
      .filter((s) => s.scanType === "SECRET")
      .reduce((a, b) => a + b._count, 0);

    // Critical exposure: SCA + CONTAINER critical findings only.
    // SAST critical is rare (Semgrep mostly emits HIGH/MEDIUM); IaC
    // critical is also uncommon. The two scan types here are the
    // ones operators actually triage with urgency.
    const sevByType = (stats.severityByScanType ?? []) as Array<{
      scanType: string; severity: string; _count: number;
    }>;
    const criticalExposure = sevByType
      .filter((r) => (r.scanType === "SCA" || r.scanType === "CONTAINER") && r.severity === "CRITICAL")
      .reduce((a, b) => a + b._count, 0);

    const statsExt = stats as unknown as { fixAvailableScaCount?: number; owaspA03Count?: number };
    const easyScaWins = statsExt.fixAvailableScaCount ?? 0;
    const owaspA03    = statsExt.owaspA03Count ?? 0;

    // Total SCA count for the "X of Y" framing on the Easy Wins card.
    const scaTotal = (stats.scanTypeCounts ?? [])
      .filter((s) => s.scanType === "SCA")
      .reduce((a, b) => a + b._count, 0);

    return { secretsCount, criticalExposure, easyScaWins, owaspA03, scaTotal };
  })();

  // Phase 29 Slice C1.5a — posture-specific metrics for the stats cards
  // when sub=posture. Computed from filteredExploits (already scoped to
  // GITHUB_POSTURE) so card-counts and widget-counts agree by construction.
  //
  // The headline cards are STORY-DRIVEN — concrete patterns operators
  // recognise + can act on, not abstract criticality counts. Each card
  // maps to ONE specific Prowler ruleId so a click filters findings to
  // the matching subset.
  const postureMetrics = (() => {
    if (!(tab === "code" && sub === "posture")) return null;
    // Reverse-index: ruleId → set of repositoryIds failing that rule.
    // Uses Set so re-counted rows (rare but possible across re-scans)
    // don't double-count.
    const reposByRule = new Map<string, Set<string>>();
    const reposWithIssues = new Set<string>();
    const publicReposAtRisk = new Set<string>();
    const publicReposExposed = new Set<string>(); // public + multiple HIGH+ failing
    const reposWithIssuesById = new Map<string, { isPublic: boolean | null; failingRules: Set<string>; topSev: string }>();
    let orgLevelMfaFailing = false;
    let orgLevelIssues = 0;

    const sevRank: Record<string, number> = { CRITICAL: 4, HIGH: 3, MEDIUM: 2, LOW: 1, INFO: 0 };

    for (const f of filteredExploits) {
      const repoIdFk = (f as Record<string, unknown>)["repositoryId"] as string | undefined;
      const ev = (f.evidence ?? {}) as Record<string, unknown>;
      const gh = (ev["github"] ?? {}) as Record<string, unknown>;
      const repo = (gh["repository"] ?? null) as { private?: boolean; fullName?: string } | null;
      const rule = f.ruleId ?? "";

      // Phase 29 Slice C1.5a — bucket key resolution:
      //   1. Repository.id FK if the operator registered the repo as a
      //      first-class asset (rare for posture-only orgs)
      //   2. evidence.github.repository.fullName as a stable synthetic
      //      key — Prowler gives us this per finding, so repo-level
      //      checks always have it
      //   3. "__org__" only when neither is present — that's a real
      //      org-level finding (the 5 organization_* Prowler checks)
      //
      // Without #2, every finding fell into __org__ since we don't
      // currently auto-create Repository rows from posture scans.
      const repoBucketKey = repoIdFk
        ?? (typeof repo?.fullName === "string" ? `gh:${repo.fullName}` : undefined);

      if (!repoBucketKey) {
        orgLevelIssues++;
        if (rule === "organization_members_mfa_required") orgLevelMfaFailing = true;
        continue;
      }
      reposWithIssues.add(repoBucketKey);

      // Per-rule repo-set for the story cards.
      if (rule) {
        if (!reposByRule.has(rule)) reposByRule.set(rule, new Set());
        reposByRule.get(rule)!.add(repoBucketKey);
      }

      // Per-repo aggregate so we can compute "exposed public repos"
      // (public + MULTIPLE failing rules) — that's the strongest
      // correlation story.
      const isPublic = repo?.private === false ? true : repo?.private === true ? false : null;
      const cur = reposWithIssuesById.get(repoBucketKey)
        ?? { isPublic, failingRules: new Set<string>(), topSev: f.severity };
      if (rule) cur.failingRules.add(rule);
      if ((sevRank[f.severity] ?? 0) > (sevRank[cur.topSev] ?? 0)) cur.topSev = f.severity;
      if (cur.isPublic === null && isPublic !== null) cur.isPublic = isPublic;
      reposWithIssuesById.set(repoBucketKey, cur);

      if (isPublic === true && (f.severity === "CRITICAL" || f.severity === "HIGH")) {
        publicReposAtRisk.add(repoBucketKey);
      }
    }

    // Correlation: public repos with ≥2 distinct HIGH+ failing rules.
    // "Naked and public" — single biggest blast-radius pattern.
    for (const [id, agg] of reposWithIssuesById.entries()) {
      if (agg.isPublic === true && agg.failingRules.size >= 2 && (agg.topSev === "CRITICAL" || agg.topSev === "HIGH")) {
        publicReposExposed.add(id);
      }
    }

    return {
      reposAtRisk:        reposWithIssues.size,
      publicReposAtRisk:  publicReposAtRisk.size,
      publicReposExposed: publicReposExposed.size,
      orgLevelIssues,
      orgLevelMfaFailing,
      // ruleId → repo-count helpers used by the story cards.
      reposWithoutBranchProtection: reposByRule.get("repository_default_branch_protection_enabled")?.size ?? 0,
      reposAllowingForcePush:       reposByRule.get("repository_default_branch_disallows_force_push")?.size ?? 0,
      reposWithoutSecretScanning:   reposByRule.get("repository_secret_scanning_enabled")?.size ?? 0,
      reposWithoutDependabot:       reposByRule.get("repository_dependency_scanning_enabled")?.size ?? 0,
      reposWithoutCodeowners:       reposByRule.get("repository_default_branch_requires_codeowners_review")?.size ?? 0,
      reposWithoutSignedCommits:    reposByRule.get("repository_default_branch_requires_signed_commits")?.size ?? 0,
    };
  })();

  // Header counts for the tab strip — derived from globalStats.scanTypeCounts.
  const webFindings = (globalStats?.scanTypeCounts ?? [])
    .filter((s) => WEB_TYPES_SET.has(s.scanType))
    .reduce((a, b) => a + b._count, 0);
  const runtimeFindings = (globalStats?.scanTypeCounts ?? [])
    .filter((s) => RUNTIME_TYPES_SET.has(s.scanType))
    .reduce((a, b) => a + b._count, 0);
  const cloudFindings = (globalStats?.scanTypeCounts ?? [])
    .filter((s) => CLOUD_TYPES_SET.has(s.scanType))
    .reduce((a, b) => a + b._count, 0);
  const codeFindings = (globalStats?.scanTypeCounts ?? [])
    .filter((s) => !WEB_TYPES_SET.has(s.scanType) && !RUNTIME_TYPES_SET.has(s.scanType) && !CLOUD_TYPES_SET.has(s.scanType))
    .reduce((a, b) => a + b._count, 0);

  return (
    <div className="p-6 space-y-6">
      <div className="flex items-center justify-between flex-wrap gap-3">
        <div className="flex items-center gap-3">
          <h1 className="text-3xl font-bold text-white">Dashboard</h1>
          {/* Per-target scope — single combined dropdown across repos /
              containers / domains. Selecting one re-scopes every card,
              chart, exploits widget, and recent-findings list to that
              asset. URL-driven (`?target=repo:<id>`) so refreshes and
              shared links preserve scope. */}
          <TargetFilter
            value={targetRaw}
            repos={repos ?? []}
            containers={containers ?? []}
            domains={domains ?? []}
            onChange={setTarget}
          />
        </div>
        {/* Tab strip — Code (file-based) vs Web (URL-based). Counts come
            from the unscoped globalStats so they remain stable across the
            active tab and accurately advertise what's in each view. */}
        <div className="flex rounded-lg border border-gray-800 bg-gray-900 p-1 gap-1">
          <button
            onClick={() => setTab("code")}
            className={`flex items-center gap-1.5 rounded-md px-3 py-1.5 text-xs font-medium transition-colors ${
              tab === "code" ? "bg-indigo-700 text-white" : "text-gray-400 hover:text-white"
            }`}
            title="SAST · SCA · Secrets · IaC · Container"
          >
            <Code2 className="h-3.5 w-3.5" />
            Code
            <span className={`tabular-nums rounded-full px-1.5 py-0.5 text-[10px] ${
              tab === "code" ? "bg-indigo-500/30 text-indigo-100" : "bg-gray-800 text-gray-500"
            }`}>{codeFindings.toLocaleString()}</span>
          </button>
          <button
            onClick={() => setTab("web")}
            className={`flex items-center gap-1.5 rounded-md px-3 py-1.5 text-xs font-medium transition-colors ${
              tab === "web" ? "bg-indigo-700 text-white" : "text-gray-400 hover:text-white"
            }`}
            title="DAST · Pentest"
          >
            <Globe className="h-3.5 w-3.5 text-gray-300" />
            Web
            <span className={`tabular-nums rounded-full px-1.5 py-0.5 text-[10px] ${
              tab === "web" ? "bg-indigo-500/30 text-indigo-100" : "bg-gray-800 text-gray-500"
            }`}>{webFindings.toLocaleString()}</span>
          </button>
          <button
            onClick={() => setTab("runtime")}
            className={`flex items-center gap-1.5 rounded-md px-3 py-1.5 text-xs font-medium transition-colors ${
              tab === "runtime" ? "bg-indigo-700 text-white" : "text-gray-400 hover:text-white"
            }`}
            title="Wazuh runtime alerts from production hosts"
          >
            <Activity className="h-3.5 w-3.5" />
            Runtime
            <span className={`tabular-nums rounded-full px-1.5 py-0.5 text-[10px] ${
              tab === "runtime" ? "bg-indigo-500/30 text-indigo-100" : "bg-gray-800 text-gray-500"
            }`}>{runtimeFindings.toLocaleString()}</span>
          </button>
          <button
            onClick={() => setTab("cloud")}
            className={`flex items-center gap-1.5 rounded-md px-3 py-1.5 text-xs font-medium transition-colors ${
              tab === "cloud" ? "bg-indigo-700 text-white" : "text-gray-400 hover:text-white"
            }`}
            title="CSPM — Prowler misconfig findings (Azure / AWS / GCP)"
          >
            <CloudIcon className="h-3.5 w-3.5" />
            Cloud
            <span className={`tabular-nums rounded-full px-1.5 py-0.5 text-[10px] ${
              tab === "cloud" ? "bg-indigo-500/30 text-indigo-100" : "bg-gray-800 text-gray-500"
            }`}>{cloudFindings.toLocaleString()}</span>
          </button>
        </div>
      </div>

      {/* Phase 29 Slice C1 — Sub-pivot inside the Code tab. Mirrors the
          FindingsPage convention: Vulnerabilities (default) shows the
          existing SAST/SCA/Secret/IaC/Container surface; Posture pivots
          to GITHUB_POSTURE findings (24 Prowler checks). The dashboard
          architecture decision is captured here in code — same domain
          (Code) split by question (vulns IN code vs hygiene OF the
          code repos). Reusable for Cloud and Identity tabs in
          subsequent slices. */}
      {tab === "code" && (
        <div className="mb-4 flex items-center gap-2 border-b border-gray-800 pb-2.5 text-sm">
          <span className="text-xs text-gray-500">View:</span>
          <button
            onClick={() => setSub("vulnerabilities")}
            className={`rounded-md px-4 py-1.5 font-medium transition-colors ${
              sub === "vulnerabilities"
                ? "bg-indigo-900/40 text-indigo-200 border border-indigo-700/50"
                : "text-gray-400 hover:text-white"
            }`}
            title="SAST / SCA / Secrets / IaC / Container — vulns in your code"
          >
            Vulnerabilities
          </button>
          <button
            onClick={() => setSub("posture")}
            className={`rounded-md px-4 py-1.5 font-medium transition-colors ${
              sub === "posture"
                ? "bg-indigo-900/40 text-indigo-200 border border-indigo-700/50"
                : "text-gray-400 hover:text-white"
            }`}
            title="GitHub posture — hygiene of your code repos (branch protection, MFA, secret scanning, etc.)"
          >
            GitHub Posture
          </button>
        </div>
      )}

      {/* Stats grid — 4 focused cards per tab.
          Lead card per tab:
            Code    → Total Code Findings (CVE counts are operator-relevant)
            Web     → Confirmed Exploits (scanner-reproduced; raw count
                       of DAST/PENTEST_FULL findings is mostly noise)
            Runtime → Confirmed Exploits (24h, sourced from /runtime/dashboard
                       — same predicate as the EXPLOIT badge)
          The "raw findings" count was demoted because operators don't
          triage by total alert volume — they triage by what's actually
          exploited. */}
      <div className="grid grid-cols-2 gap-4 lg:grid-cols-4">
        {tab === "code" && sub === "vulnerabilities" && codeStoryMetrics ? (() => {
          // Phase 29 Slice C1.5b — Story-driven Code-Vulnerabilities cards.
          //
          // Replaces the generic Posture/Critical/High/Repos quartet with
          // four narratives anchored in the actual finding mix:
          //
          //   1. Secrets in Code   — CRITICAL by nature; click → SECRET filter
          //   2. Critical Exposure — SCA + CONTAINER CRITICAL count;
          //                          known-exploits-in-deps urgency
          //   3. Easy SCA Wins     — count of SCA with fixVersion set.
          //                          On real data this is 90%+ of SCA
          //                          total — reads as "most CVEs are
          //                          one bump from fixed"
          //   4. OWASP A03         — SAST CWEs in the injection family
          //                          (78/79/89/90/91/95/502/564/917/943).
          //                          Procurement-recognisable framework.
          //
          // Each card filters /findings to its specific subset:
          //   secrets  → ?scanType=SECRET
          //   critical → ?scanType=SCA,CONTAINER&severity=CRITICAL
          //   easy SCA → ?scanType=SCA&fixAvailable=true (filter shipped same slice)
          //   OWASP    → ?owaspFamily=A03 (filter expanded to CWE list server-side)
          const m = codeStoryMetrics;
          const easyPct = m.scaTotal > 0
            ? Math.round((m.easyScaWins / m.scaTotal) * 100)
            : 0;

          return (
            <>
              <StatsCard
                label="Secrets in Code"
                value={m.secretsCount}
                valueClassName={m.secretsCount > 0 ? "text-red-400" : undefined}
                icon={<ShieldAlert className={`h-5 w-5 ${m.secretsCount > 0 ? "text-red-500/70" : "text-gray-500"}`} />}
                onClick={() => navigate(`/findings?tab=code&scanType=SECRET`)}
                hint={m.secretsCount > 0
                  ? `${m.secretsCount} credential${m.secretsCount === 1 ? "" : "s"} committed — leak path`
                  : "No secrets detected ✓"}
              />
              <StatsCard
                label="Critical Exposure"
                value={m.criticalExposure}
                valueClassName={m.criticalExposure > 0 ? "text-red-400" : undefined}
                icon={<Flame className={`h-5 w-5 ${m.criticalExposure > 0 ? "text-red-500/70" : "text-gray-500"}`} />}
                onClick={() => navigate(`/findings?tab=code&scanType=SCA,CONTAINER&severity=CRITICAL`)}
                hint={m.criticalExposure > 0
                  ? `${m.criticalExposure} known exploit${m.criticalExposure === 1 ? "" : "s"} in deps + container layers`
                  : "No critical CVEs in deps/containers ✓"}
              />
              <StatsCard
                label="Easy SCA Wins"
                value={m.easyScaWins}
                valueClassName={m.easyScaWins > 0 ? "text-emerald-300" : undefined}
                icon={<Package className={`h-5 w-5 ${m.easyScaWins > 0 ? "text-emerald-400/80" : "text-gray-500"}`} />}
                onClick={() => navigate(`/findings?tab=code&scanType=SCA&fixAvailable=true`)}
                hint={m.scaTotal > 0
                  ? `${easyPct}% of SCA findings have a fix available — bump deps`
                  : "No dependency findings yet"}
              />
              <StatsCard
                label="OWASP A03 Injection"
                value={m.owaspA03}
                valueClassName={m.owaspA03 > 0 ? "text-orange-400" : undefined}
                icon={<Target className={`h-5 w-5 ${m.owaspA03 > 0 ? "text-orange-500/70" : "text-gray-500"}`} />}
                onClick={() => navigate(`/findings?tab=code&owaspFamily=A03`)}
                hint={m.owaspA03 > 0
                  ? `${m.owaspA03} SAST finding${m.owaspA03 === 1 ? "" : "s"} — SQLi · XSS · eval · cmd injection`
                  : "No injection patterns detected ✓"}
              />
            </>
          );
        })() : tab === "code" && sub === "posture" && postureMetrics ? (() => {
          // Phase 29 Slice C1.5a — Story-driven posture cards.
          //
          // Operators don't triage by abstract counts ("you have 165
          // posture issues, 97 of them HIGH"). They triage by recognisable
          // patterns ("3 of your repos don't have branch protection on
          // main"). Each card maps to ONE concrete failing-check story
          // that the operator can act on directly:
          //
          //   1. Branch Protection — most-known control; "X repos have
          //                          no protection on main" reads like
          //                          a TODO list
          //   2. Force Push        — severe (history rewrite); separate
          //                          from #1 because it's a distinct
          //                          attack vector
          //   3. Public + Exposed  — correlation story (public AND ≥2
          //                          HIGH+ failing rules). Maximum blast
          //                          radius — what to triage FIRST.
          //   4. MFA Enforcement   — org-level binary. The single most
          //                          important toggle for credential-
          //                          theft prevention (Solorigate path).
          //                          Falls back to "Dependabot" or
          //                          "Secret scanning" when MFA isn't
          //                          on the failing list.
          //
          // Click target on each card filters /findings to the matching
          // ruleId — so "click → see exactly which 3 repos" is one hop.
          const m = postureMetrics;

          // Pick the 4th card based on what's actually broken. Priority:
          // MFA (org-level, CRITICAL severity) > Dependabot (supply-chain,
          // HIGH) > Secret Scanning (preventable cred leaks, HIGH).
          const fourthCard = m.orgLevelMfaFailing ? (
            <StatsCard
              label="MFA Enforcement"
              value="✗ Off"
              valueClassName="text-red-400"
              icon={<AlertTriangle className="h-5 w-5 text-red-500/70" />}
              onClick={() => navigate(`/findings?tab=code&sub=posture&search=organization_members_mfa_required`)}
              hint="Members can sign in without 2FA — direct credential-theft path"
            />
          ) : m.reposWithoutDependabot > 0 ? (
            <StatsCard
              label="No Dependabot"
              value={m.reposWithoutDependabot}
              valueClassName="text-amber-300"
              icon={<Package className="h-5 w-5 text-amber-400/80" />}
              onClick={() => navigate(`/findings?tab=code&sub=posture&search=repository_dependency_scanning_enabled`)}
              hint={`${m.reposWithoutDependabot} repo${m.reposWithoutDependabot === 1 ? "" : "s"} blind to known-CVE dependencies`}
            />
          ) : (
            <StatsCard
              label="No Secret Scanning"
              value={m.reposWithoutSecretScanning}
              valueClassName="text-amber-300"
              icon={<ShieldAlert className="h-5 w-5 text-amber-400/80" />}
              onClick={() => navigate(`/findings?tab=code&sub=posture&search=repository_secret_scanning_enabled`)}
              hint={`${m.reposWithoutSecretScanning} repo${m.reposWithoutSecretScanning === 1 ? "" : "s"} can leak credentials at push`}
            />
          );

          // Third card: prioritise the correlation story when present
          // ("X public repos with ≥2 HIGH+ failures"); fall back to
          // simple "Public Repos at Risk" when no correlation found.
          const thirdCard = m.publicReposExposed > 0 ? (
            <StatsCard
              label="Public + Exposed"
              value={m.publicReposExposed}
              valueClassName="text-rose-300"
              icon={<Github className="h-5 w-5 text-rose-400/80" />}
              onClick={() => navigate(`/findings?tab=code&sub=posture&severity=CRITICAL,HIGH`)}
              hint={`Public repos with ≥2 HIGH+ failures — max blast radius`}
            />
          ) : m.publicReposAtRisk > 0 ? (
            <StatsCard
              label="Public Repos at Risk"
              value={m.publicReposAtRisk}
              valueClassName="text-amber-300"
              icon={<Github className="h-5 w-5 text-amber-400/80" />}
              onClick={() => navigate(`/findings?tab=code&sub=posture&severity=CRITICAL,HIGH`)}
              hint="HIGH+ findings on publicly visible repos"
            />
          ) : (
            <StatsCard
              label="Repos at Risk"
              value={m.reposAtRisk}
              icon={<Github className="h-5 w-5 text-indigo-300" />}
              onClick={() => navigate(`/findings?tab=code&sub=posture`)}
              hint={m.orgLevelIssues > 0 ? `+${m.orgLevelIssues} org-level findings` : "Repos with failing checks"}
            />
          );

          return (
            <>
              <StatsCard
                label="Without Branch Protection"
                value={m.reposWithoutBranchProtection}
                valueClassName={m.reposWithoutBranchProtection > 0 ? "text-red-400" : undefined}
                icon={<GitBranch className={`h-5 w-5 ${m.reposWithoutBranchProtection > 0 ? "text-red-500/70" : "text-gray-500"}`} />}
                onClick={() => navigate(`/findings?tab=code&sub=posture&search=repository_default_branch_protection_enabled`)}
                hint={m.reposWithoutBranchProtection > 0
                  ? `${m.reposWithoutBranchProtection} repo${m.reposWithoutBranchProtection === 1 ? "" : "s"} unprotected on main`
                  : "All repos have branch protection ✓"}
              />
              <StatsCard
                label="Force Push Allowed"
                value={m.reposAllowingForcePush}
                valueClassName={m.reposAllowingForcePush > 0 ? "text-rose-300" : undefined}
                icon={<AlertTriangle className={`h-5 w-5 ${m.reposAllowingForcePush > 0 ? "text-rose-400/80" : "text-gray-500"}`} />}
                onClick={() => navigate(`/findings?tab=code&sub=posture&search=repository_default_branch_disallows_force_push`)}
                hint={m.reposAllowingForcePush > 0
                  ? `${m.reposAllowingForcePush} repo${m.reposAllowingForcePush === 1 ? "" : "s"} expose history-rewrite path`
                  : "Force pushes denied everywhere ✓"}
              />
              {thirdCard}
              {fourthCard}
            </>
          );
        })() : (
          <>
            {(() => {
          // The Confirmed Exploits count comes from the SAME filtered
          // dataset the Exploits widget renders — `filteredExploits`
          // applied the badge predicate (wasExploitSuccessful for
          // Code/Web, hasActiveAttack for Runtime). This guarantees
          // card-number ≡ widget-row-count, which is what the operator
          // expects when both surfaces describe "the exploits".
          if (tab === "code" && sub === "posture") {
            // Phase 29 Slice C1.5a — Posture-led stat. Posture is governance
            // hygiene, not "vulns in code" — different mental model from the
            // default Code-tab card. Lead with the open-issue count just
            // like Cloud/CSPM does (Prowler checks are deterministic).
            return (
              <StatsCard
                label="Posture Issues"
                value={totalFindings}
                icon={<ShieldAlert className="h-5 w-5 text-indigo-300" />}
                onClick={() => navigate(`/findings?tab=code&sub=posture`)}
                hint={totalFindings > 0 ? "Open misconfigurations" : "All checks passing"}
              />
            );
          }
          if (tab === "code") {
            return (
              <StatsCard
                label="Code Findings"
                value={totalFindings}
                icon={<ShieldAlert className="h-5 w-5" />}
                onClick={() => navigate(`/findings?tab=code`)}
                hint={totalFindings > 0 ? "View all" : undefined}
              />
            );
          }
          if (tab === "web") {
            return (
              <StatsCard
                label="Confirmed Exploits"
                value={filteredExploitsCount}
                valueClassName="text-red-400"
                icon={<Target className="h-5 w-5 text-red-500/70" />}
                onClick={() => navigate(`/findings?tab=web&confidence=CONFIRMED`)}
                hint={filteredExploitsCount > 0 ? "Scanner-reproduced" : "None reproduced yet"}
              />
            );
          }
          if (tab === "cloud") {
            // Cloud (CSPM) — Prowler findings are misconfigurations, not
            // exploits. Lead with total open findings; severity breakdown
            // sits in the trailing cards. Operators triage CSPM by
            // counting how much misconfig debt they're carrying, not by
            // "did the scanner reproduce it" (CSPM checks are
            // deterministic — every fail is a real misconfig).
            return (
              <StatsCard
                label="Cloud Findings"
                value={cloudFindings}
                icon={<CloudIcon className="h-5 w-5 text-indigo-300" />}
                onClick={() => navigate(`/findings?tab=cloud`)}
                hint={cloudFindings > 0 ? "Open misconfigurations" : "No findings yet"}
              />
            );
          }
          // runtime — lead card sources from stats.tagCounts so the
          // count exactly matches what /findings?tag=runtime-exploit
          // returns. No client-side predicate replication; single
          // source of truth lives in services/findingTags.ts on the
          // server.
          const runtimeExploitTotal = stats?.tagCounts?.["runtime-exploit"] ?? 0;
          return (
            <StatsCard
              label="Exploits Landed"
              value={runtimeExploitTotal}
              valueClassName="text-red-400"
              icon={<AlertTriangle className="h-5 w-5 text-red-500/70" />}
              onClick={() => navigate(`/findings?tab=runtime&tag=runtime-exploit`)}
              hint={runtimeExploitTotal > 0 ? "Attack-tagged + landed" : "No landings"}
            />
          );
        })()}
        {tab === "runtime" ? (() => {
          // Runtime cards source their counts from server-side
          // tagCounts so card-count ≡ destination-count for every tag.
          //
          // Three-card model (alongside the Lead "Exploits Landed" above
          // and the trailing "Runtime Agents" below):
          //   Active Attacks       — event-driven, runtime-attack tag
          //                           (Wazuh detected attack, no landing
          //                            signal yet)
          //   Vulnerable Packages  — STATE-driven, runtime-vulnerability
          //                           tag (Wazuh VD found a known CVE in
          //                           an installed package — what COULD
          //                           be exploited, distinct from what IS
          //                           being attacked).
          //
          // The earlier "All Attack Patterns" card (sum of attack +
          // exploit) was redundant — operators read the lead card +
          // Active Attacks and got the same signal. Vulnerable Packages
          // adds a real new dimension (state, not event) that the
          // event-only cards couldn't surface.
          const runtimeAttackTotal = stats?.tagCounts?.["runtime-attack"]        ?? 0;
          const runtimeVulnTotal   = stats?.tagCounts?.["runtime-vulnerability"] ?? 0;
          return (
            <>
              <StatsCard
                label="Active Attacks"
                value={runtimeAttackTotal}
                valueClassName="text-rose-300"
                icon={<Activity className="h-5 w-5 text-rose-400/70" />}
                onClick={() => navigate(`/findings?tab=runtime&tag=runtime-attack`)}
                hint={runtimeAttackTotal > 0 ? "Attack patterns · no landing signal" : "Quiet"}
              />
              <StatsCard
                label="Vulnerable Packages"
                value={runtimeVulnTotal}
                valueClassName="text-indigo-200"
                icon={<ShieldAlert className="h-5 w-5 text-indigo-400/70" />}
                onClick={() => navigate(`/findings?tab=runtime&tag=runtime-vulnerability`)}
                hint={runtimeVulnTotal > 0 ? "Wazuh VD · MED+ severity" : "None detected"}
              />
            </>
          );
        })() : tab === "web" ? (() => {
          // Web: mirror the Runtime model — drop severity counts in
          // favour of the confidence axis that maps to the EXPLOIT
          // workflow:
          //   Confirmed Exploits (lead) → scanner reproduced (already
          //     shown above as filteredExploitsCount)
          //   Likely Findings           → scanner has partial proof but
          //     hasn't fully reproduced (CONFIDENCE=LIKELY)
          //   Total Confirmed           → all CONFIRMED rows including
          //     ones without the url+attack evidence pair (e.g.
          //     deserialization findings where the proof shape differs)
          // Severity-based Critical/High dropped — for Web, confidence
          // (did the scanner prove it?) is the more actionable axis
          // than severity (how bad would it be if it landed?).
          const likelyCount    = (stats?.confidenceCounts ?? [])
            .find((c) => (c as { confidence?: string }).confidence === "LIKELY")?._count ?? 0;
          const confirmedCount = (stats?.confidenceCounts ?? [])
            .find((c) => (c as { confidence?: string }).confidence === "CONFIRMED")?._count ?? 0;
          // Card ordering: Confirmed Exploits (lead, card 1 above)
          // sits next to All Confirmed (card 2 here) because both
          // describe CONFIRMED-confidence findings — exploits are the
          // strict subset with reproducer evidence, All Confirmed is
          // the broader bucket. Likely Findings (card 3) goes right
          // since it's a distinct (lower) confidence tier.
          //
          // Color hierarchy mirrors urgency:
          //   Confirmed Exploits → red-400  (strongest, scanner reproduced)
          //   All Confirmed      → rose-300 (serious, partial proof category)
          //   Likely Findings    → gray-300 (lowest urgency, partial signal)
          return (
            <>
              <StatsCard
                label="All Confirmed"
                value={confirmedCount}
                valueClassName="text-rose-300"
                icon={<AlertTriangle className="h-5 w-5 text-rose-400/70" />}
                onClick={() => navigate(`/findings?tab=web&confidence=CONFIRMED`)}
                hint="Total CONFIRMED rows (incl. non-reproducer evidence)"
              />
              <StatsCard
                label="Likely Findings"
                value={likelyCount}
                valueClassName="text-gray-300"
                icon={<Activity className="h-5 w-5 text-gray-400" />}
                onClick={() => navigate(`/findings?tab=web&confidence=LIKELY`)}
                hint={likelyCount > 0 ? "Partial proof · not fully reproduced" : "Quiet"}
              />
            </>
          );
        })() : tab === "cloud" ? (() => {
          // Cloud (CSPM) — Prowler maps every failed check to multiple
          // compliance frameworks (CIS / PCI / NIST / HIPAA / MITRE
          // ATT&CK / FedRAMP / etc — 12+ per finding on Azure). The
          // operator's triage axes here are:
          //   1. Severity   — how urgent is each misconfig
          //   2. Compliance — which frameworks are at risk (audit prep)
          //   3. Scope      — how many cloud accounts have findings
          // We surface 2 cards (combined with the lead "Cloud Findings"
          // card above + the trailing "Cloud Accounts" card below = 4).

          // Critical + High count: misconfigs the operator should fix
          // FIRST. CSPM rarely produces CRITICAL (Prowler's worst tier
          // is HIGH for most checks); we sum the two so the card stays
          // useful regardless of which one populates.
          const criticalHighCount = criticalCount + highCount;
          // Resources at Risk — distinct Azure resourceIds across all
          // CLOUD findings. The right "blast radius" metric: an
          // operator triages by "how many things to fix", not "how many
          // findings I have" (a single misconfigured Storage account
          // can produce 5 findings). Replaces the Compliance Frameworks
          // card after operator feedback that the framework count was
          // a passive number — the resource count is actionable.
          //
          // Internet-Exposed — the urgency subset. Prowler tags certain
          // checks under unmapped.categories with "internet-exposed"
          // (publicly reachable storage, JIT-disabled VMs with public
          // IPs, etc). When > 0 we surface it as the card's hint so
          // the operator's eye lands on the most-urgent count without
          // a click.
          const resourceIdSet = new Set<string>();
          let internetExposedCount = 0;
          for (const f of (filteredExploits ?? [])) {
            const ev    = (f.evidence ?? {}) as Record<string, unknown>;
            const azure = (ev["azure"] ?? {}) as Record<string, unknown>;
            const rid   = azure["resourceId"];
            if (typeof rid === "string" && rid) resourceIdSet.add(rid);
            const cats  = ev["categories"];
            if (Array.isArray(cats) && cats.includes("internet-exposed")) {
              internetExposedCount++;
            }
          }
          return (
            <>
              <StatsCard
                label="Critical + High"
                value={criticalHighCount}
                valueClassName="text-orange-400"
                icon={<ShieldAlert className="h-5 w-5 text-orange-500/70" />}
                onClick={() => navigate(`/findings?tab=cloud&severity=CRITICAL,HIGH&status=OPEN`)}
                hint={criticalHighCount > 0 ? "Fix-first misconfigurations" : "No high-severity"}
              />
              <StatsCard
                label="Resources at Risk"
                value={resourceIdSet.size}
                valueClassName="text-indigo-200"
                icon={<Box className="h-5 w-5 text-indigo-400/70" />}
                onClick={() => navigate(`/findings?tab=cloud`)}
                hint={
                  internetExposedCount > 0
                    ? `${internetExposedCount} internet-exposed`
                    : (resourceIdSet.size > 0
                        ? "Distinct Azure resources affected"
                        : "No resources flagged")
                }
              />
            </>
          );
        })() : (
          // Code: severity is still the right axis (CVE counts are
          // graded by impact severity, that's what operators triage by)
          <>
            <StatsCard
              label="Critical"
              value={criticalCount}
              valueClassName="text-red-400"
              icon={<ShieldAlert className="h-5 w-5 text-red-500/70" />}
              onClick={() => navigate(`/findings?tab=code&severity=CRITICAL&status=OPEN`)}
              hint={criticalCount > 0 ? "Open & critical" : undefined}
            />
            <StatsCard
              label="High"
              value={highCount}
              valueClassName="text-orange-400"
              icon={<ShieldAlert className="h-5 w-5 text-orange-500/70" />}
              onClick={() => navigate(`/findings?tab=code&severity=HIGH&status=OPEN`)}
              hint={highCount > 0 ? "Open & high" : undefined}
            />
          </>
        )}
        {tab === "code" && sub === "posture" ? (
          // Phase 29 Slice C1.5a — Posture-specific trailing card.
          // "Public repos at risk" is the most-urgent triage axis: a
          // public repo with broken posture has maximum exposure — the
          // attack surface is anyone with internet access. Falls back to
          // "Repos at Risk" when no public repos are flagged so the card
          // still surfaces the next-most-meaningful number.
          (postureMetrics?.publicReposAtRisk ?? 0) > 0 ? (
            <StatsCard
              label="Public Repos at Risk"
              value={postureMetrics!.publicReposAtRisk}
              valueClassName="text-amber-300"
              icon={<Github className="h-5 w-5 text-amber-400/80" />}
              onClick={() => navigate(`/findings?tab=code&sub=posture&severity=CRITICAL,HIGH`)}
              hint="HIGH+ on public repos"
            />
          ) : (
            <StatsCard
              label="Repos at Risk"
              value={postureMetrics?.reposAtRisk ?? 0}
              icon={<Github className="h-5 w-5 text-indigo-300" />}
              onClick={() => navigate(`/findings?tab=code&sub=posture`)}
              hint={(postureMetrics?.orgLevelIssues ?? 0) > 0 ? `+${postureMetrics!.orgLevelIssues} org-level` : "Repos with failing checks"}
            />
          )
        ) : tab === "code" ? (
          <StatsCard
            label="Repos + Containers"
            value={(repos?.length ?? 0) + (containers?.length ?? 0)}
            icon={<GitBranch className="h-5 w-5" />}
            onClick={() => navigate((repos?.length ?? 0) >= (containers?.length ?? 0) ? "/repositories" : "/containers")}
            hint="Code scan targets"
          />
        ) : tab === "runtime" ? (
          <StatsCard
            label="Runtime Agents"
            value={runtimeFindings > 0 ? "live" : "—"}
            icon={<Activity className="h-5 w-5 text-indigo-400" />}
            onClick={() => navigate("/runtime")}
            hint="View runtime dashboard"
          />
        ) : tab === "cloud" ? (
          <StatsCard
            label="Cloud Accounts"
            value={cloudAccounts?.length ?? 0}
            icon={<CloudIcon className="h-5 w-5 text-indigo-300" />}
            onClick={() => navigate("/cloud-accounts")}
            hint="CSPM scan targets (Azure / AWS / GCP)"
          />
        ) : (
          <StatsCard
            label="Domains"
            value={domains?.length ?? 0}
            icon={<Globe className="h-5 w-5 text-gray-300" />}
            onClick={() => navigate("/domains")}
            hint="Web scan targets"
          />
        )}
          </>
        )}
      </div>

      <div className="grid grid-cols-1 gap-6 lg:grid-cols-3">
        {/* Exploits widget — unified single-card view that replaces the
            two separate "Severity bars" + "Top Risk Targets" widgets.
            Spans 2 columns. Recent Scans keeps the third column. The
            list shows the recent confirmed exploits scoped to the
            active tab; clicking any row drills into the finding drawer.
            For Runtime tab, an MITRE-tactic mini-summary stays at the
            top of this card so the operator can still see the
            distribution at a glance, but the dominant content is the
            exploits themselves — the actionable signal. */}
        <div className="lg:col-span-2 rounded-lg border border-gray-800 bg-gray-900 p-5">
          {tab === "code" && sub === "posture" ? (
            // Phase 29 Slice C1 — Code Posture sub-pivot widget. Replaces
            // the Code-default CodeCategoriesWidget with a posture-focused
            // surface (top affected repos + top failing checks). Uses the
            // same exploitsQuery dataset (scoped to GITHUB_POSTURE above).
            <GitHubPostureWidget
              findings={filteredExploits}
              isLoading={exploitsQuery.isLoading}
            />
          ) : tab === "code" ? (
            <CodeCategoriesWidget
              scanTypeCounts={stats?.scanTypeCounts}
              severityByScanType={stats?.severityByScanType}
            />
          ) : tab === "cloud" ? (
            // Phase 29 — CSPM-specific widget with Top Services +
            // Compliance Coverage + Top Failing Checks. Replaces the
            // generic ExploitsWidget for cloud tab because Prowler
            // findings are misconfigurations, not exploits — the
            // operator's triage axes are service / framework /
            // recurring check, not "did the scanner reproduce it".
            <CloudCspmWidget
              findings={filteredExploits}
              isLoading={exploitsQuery.isLoading}
            />
          ) : (
            <ExploitsWidget
              tab={tab}
              runtimeDash={runtimeDash}
              exploits={filteredExploits}
              isLoading={exploitsQuery.isLoading}
            />
          )}
        </div>

        {/* Recent scans — tab-scoped (DOMAIN scans on Web tab,
            REPO/CONTAINER on Code tab). The underlying query fetches a
            slightly larger page (20) so each tab has enough material to
            show after client-side filtering. */}
        <div className="rounded-lg border border-gray-800 bg-gray-900 p-5">
          <div className="mb-4 flex items-center justify-between">
            <h2 className="text-sm font-semibold text-white">
              Recent {
                tab === "web"     ? "Web "
                : tab === "runtime" ? "Runtime "
                : tab === "cloud"   ? "Cloud "
                : tab === "code" && sub === "posture" ? "Posture "
                :                    ""
              }Scans
            </h2>
            <Link to="/scans" className="flex items-center gap-1 text-xs text-indigo-400 hover:text-indigo-300">
              View all <ArrowRight className="h-3 w-3" />
            </Link>
          </div>
          {tabScans.length ? (
            <div className="space-y-2">
              {tabScans.map((scan) => (
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
              <p>No {tab === "web" ? "web" : "code"} scans yet.</p>
              <Link
                to={tab === "web" ? "/domains" : "/repositories"}
                className="inline-flex items-center gap-1 rounded bg-indigo-700 px-3 py-1.5 text-xs text-white hover:bg-indigo-600"
              >
                <Plus className="h-3 w-3" /> Add a {tab === "web" ? "domain" : "target"}
              </Link>
            </div>
          )}
        </div>
      </div>

      {/* Top Noisy Rules — candidates for suppression/tuning.
          Phase 29 Slice C1.5a — hidden entirely on Code-Posture sub-pivot.
          Suppression is for probabilistic detections that produce false
          positives (a noisy SAST rule, a ZAP false alarm). GitHub posture
          checks are deterministic — every FAIL is a real misconfig the
          operator should fix, not suppress. Showing this widget on the
          Posture sub-pivot would invite the wrong action. */}
      {!(tab === "code" && sub === "posture") && (
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
                // Pick the tab matching the rule's scan type so the search
                // term lands on a list that actually contains it.
                const tabParam = WEB_TYPES_SET.has(r.scanType) ? "web" : "code";
                return (
                  <Link
                    key={r.ruleId}
                    to={`/findings?tab=${tabParam}&search=${encodeURIComponent(r.ruleId)}&status=OPEN`}
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
            No critical or high {tab === "web" ? "web" : "code"} findings with a ruleId yet.
          </div>
        )}
      </div>
      )}

      {/* Recent findings — tab-scoped via the API call's scanType filter */}
      <div className="rounded-lg border border-gray-800 bg-gray-900 p-5">
        <div className="mb-4 flex items-center justify-between">
          <h2 className="text-sm font-semibold text-white">
            Recent {
              tab === "web"     ? "Web "
              : tab === "runtime" ? "Runtime "
              : tab === "cloud"   ? "Cloud "
              : tab === "code" && sub === "posture" ? "Posture "
              :                    "Code "
            }Findings
          </h2>
          <Link to={`/findings?tab=${tab}`} className="flex items-center gap-1 text-xs text-indigo-400 hover:text-indigo-300">
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
                {recentFindings?.data.map((f) => {
                  const isWeb     = WEB_TYPES_SET.has(f.scanType);
                  const isRuntime = RUNTIME_TYPES_SET.has(f.scanType);
                  const isCloud   = CLOUD_TYPES_SET.has(f.scanType);
                  const targetTab = isCloud ? "cloud" : isRuntime ? "runtime" : isWeb ? "web" : "code";
                  return (
                    <tr
                      key={f.id}
                      className="cursor-pointer border-b border-gray-800/50 hover:bg-gray-800/40 transition-colors"
                      // Land on the matching tab so back/forward and the
                      // surrounding list are coherent with the finding the
                      // user just opened.
                      onClick={() => navigate(`/findings?tab=${targetTab}&id=${f.id}`)}
                    >
                      <td className="py-2 pr-4"><SeverityBadge severity={f.severity} /></td>
                      <td className="py-2 pr-4 max-w-xs">
                        <p className="truncate text-gray-200">{f.title}</p>
                        {/* Surface URL on web findings — primary navigation aid */}
                        {isWeb && f.filePath && (
                          <p className="truncate text-[11px] text-sky-400/80 font-mono" title={f.filePath}>
                            {f.filePath}
                          </p>
                        )}
                      </td>
                      <td className="py-2 pr-4"><TargetTag finding={f} maxWidth="max-w-[140px]" /></td>
                      <td className="py-2 pr-4 text-xs text-gray-400">{f.scanType}</td>
                      <td className="py-2 text-xs text-gray-500">{formatRelative(f.firstSeen)}</td>
                    </tr>
                  );
                })}
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
