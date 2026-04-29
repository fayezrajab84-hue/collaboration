import { useQuery } from "@tanstack/react-query";
import { BarChart, Bar, XAxis, YAxis, CartesianGrid, Tooltip, ResponsiveContainer } from "recharts";
import { ShieldAlert, GitBranch, Box, Globe, ArrowRight, Flame, Plus, Target, Code2, Activity, AlertTriangle, Filter, ChevronDown, Check, Cloud as CloudIcon } from "lucide-react";
import { Link, useNavigate, useSearchParams } from "react-router-dom";
import { findingsApi, reposApi, containersApi, domainsApi, scansApi, runtimeApi, type RuntimeDashboardResponse } from "../lib/api";
import { wasExploitSuccessful, hasActiveAttack } from "../lib/findings";
import ExploitSuccessBadge from "../components/ExploitSuccessBadge";
import ActiveAttackBadge from "../components/ActiveAttackBadge";
import { SEVERITY_CHART } from "../lib/colors";

import StatsCard from "../components/StatsCard";
import SeverityBadge from "../components/SeverityBadge";
import ScanStatusBadge from "../components/ScanStatusBadge";
import TargetTag from "../components/TargetTag";
import { formatRelative } from "../lib/utils";
import type { ScanJob, Finding } from "@devsecops/types";

// Code/Web/Runtime split — mirrored from FindingsPage so the dashboard
// renders the same slice of data the user lands on after clicking through.
const CODE_SCAN_TYPES    = ["SAST", "SCA", "SECRET", "IAC", "CONTAINER"];
const WEB_SCAN_TYPES     = ["DAST", "PENTEST_FULL"];
const RUNTIME_SCAN_TYPES = ["RUNTIME"];
const CLOUD_SCAN_TYPES   = ["CLOUD"];   // Phase 29 — CSPM
const WEB_TYPES_SET      = new Set(WEB_SCAN_TYPES);
const RUNTIME_TYPES_SET  = new Set(RUNTIME_SCAN_TYPES);
const CLOUD_TYPES_SET    = new Set(CLOUD_SCAN_TYPES);

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
  const setTab = (t: "code" | "web" | "runtime" | "cloud") => {
    setSearchParams((prev) => {
      if (t === "code") prev.delete("tab"); else prev.set("tab", t);
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

  const tabScanTypes =
    tab === "web"     ? WEB_SCAN_TYPES
    : tab === "runtime" ? RUNTIME_SCAN_TYPES
    : tab === "cloud"   ? CLOUD_SCAN_TYPES
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
    queryKey: ["findings", "recent", tab, targetRaw],
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
    queryKey: ["dashboard-exploits", tab, targetRaw],
    queryFn: () => findingsApi.list(
      tab === "runtime"
        ? { scanType: "RUNTIME" as never, limit: 100, ...targetParams }
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
    if (tab !== "runtime") return wasExploitSuccessful(f);
    if (!hasActiveAttack(f)) return false;
    return f.severity === "CRITICAL" || f.severity === "HIGH" || f.severity === "MEDIUM";
  });
  const filteredExploitsCount = filteredExploits.length;

  // Per-tab slice for the noisy-rules widget.
  const noisyRules   = (noisyRulesAll ?? []).filter((r) =>
    tab === "web"     ? WEB_TYPES_SET.has(r.scanType)
    : tab === "runtime" ? RUNTIME_TYPES_SET.has(r.scanType)
    :                    !WEB_TYPES_SET.has(r.scanType) && !RUNTIME_TYPES_SET.has(r.scanType),
  ).slice(0, 5);
  const tabScans = (scans?.data ?? []).filter((s) =>
    tab === "web"     ? s.targetType === "DOMAIN"
    : tab === "runtime" ? (s.scanTypes ?? []).includes("RUNTIME")
    :                    s.targetType !== "DOMAIN",
  ).slice(0, 6);

  const severityData = (stats?.severityCounts ?? []).map((s) => ({
    name: s.severity,
    value: s._count,
    color: SEVERITY_COLORS[s.severity] ?? "#6b7280",
  }));

  const totalFindings = severityData.reduce((a, b) => a + b.value, 0);
  const criticalCount = severityData.find((s) => s.name === "CRITICAL")?.value ?? 0;
  const highCount = severityData.find((s) => s.name === "HIGH")?.value ?? 0;

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
        {(() => {
          // The Confirmed Exploits count comes from the SAME filtered
          // dataset the Exploits widget renders — `filteredExploits`
          // applied the badge predicate (wasExploitSuccessful for
          // Code/Web, hasActiveAttack for Runtime). This guarantees
          // card-number ≡ widget-row-count, which is what the operator
          // expects when both surfaces describe "the exploits".
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
        {tab === "code" ? (
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
        ) : (
          <StatsCard
            label="Domains"
            value={domains?.length ?? 0}
            icon={<Globe className="h-5 w-5 text-gray-300" />}
            onClick={() => navigate("/domains")}
            hint="Web scan targets"
          />
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
          {tab === "code" ? (
            <CodeCategoriesWidget
              scanTypeCounts={stats?.scanTypeCounts}
              severityByScanType={stats?.severityByScanType}
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
              Recent {tab === "web" ? "Web " : ""}Scans
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

      {/* Recent findings — tab-scoped via the API call's scanType filter */}
      <div className="rounded-lg border border-gray-800 bg-gray-900 p-5">
        <div className="mb-4 flex items-center justify-between">
          <h2 className="text-sm font-semibold text-white">
            Recent {tab === "web" ? "Web " : "Code "}Findings
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
                  const isWeb = WEB_TYPES_SET.has(f.scanType);
                  return (
                    <tr
                      key={f.id}
                      className="cursor-pointer border-b border-gray-800/50 hover:bg-gray-800/40 transition-colors"
                      // Land on the matching tab so back/forward and the
                      // surrounding list are coherent with the finding the
                      // user just opened.
                      onClick={() => navigate(`/findings?tab=${isWeb ? "web" : "code"}&id=${f.id}`)}
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
