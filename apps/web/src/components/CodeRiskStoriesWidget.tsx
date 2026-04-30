/**
 * Phase 29 Slice C1.5b — Code Risk Stories widget.
 *
 * Replaces / augments the generic CodeCategoriesWidget when on the
 * Code-Vulnerabilities sub-pivot. Three operator-facing sections:
 *
 *   Section A — OWASP Top 10 distribution
 *     Horizontal bar chart of finding counts by OWASP 2021 family.
 *     Procurement-recognisable framing — auditors and security teams
 *     read in OWASP terms; raw CWE numbers are technical noise to
 *     non-engineers. Click a family → /findings?owaspFamily=A0X.
 *
 *   Section B — Hot files
 *     Top file paths by finding count, scoped to file-based scan
 *     types (SAST / SECRET / IAC). Operator's "where does my work
 *     concentrate" view — refactoring db-app.tf may close 22 findings
 *     in one PR.
 *
 *   Section C — Hot packages
 *     Top packages by CVE count across SCA + CONTAINER. Supply-chain
 *     concentration — bumping `semver` may close 8 CVEs at once.
 *
 * Data comes from the extended /findings/summary/stats payload
 * (owaspCounts, hotFiles, hotPackages). All shaping is done server-
 * side so this component stays presentational.
 */
import { useNavigate } from "react-router-dom";
import { Target, FileCode, Package, ArrowRight } from "lucide-react";

// Match the shapes produced by the backend
interface OwaspFamilyMeta {
  code:        string;
  name:        string;
  description: string;
}

interface HotFileRow {
  filePath: string;
  scanType: string;
  count:    number;
}

interface HotPackageRow {
  packageName: string;
  count:       number;
}

interface Props {
  owaspCounts:   Record<string, number> | undefined;
  owaspUnmapped: number | undefined;
  hotFiles:      HotFileRow[] | undefined;
  hotPackages:   HotPackageRow[] | undefined;
}

// Display order for OWASP families. Sorted by typical operator
// triage urgency: injection + access control on top, then crypto +
// auth, then design / config / components, then SSRF / logging at
// the bottom (rarely surface in volume).
const OWASP_DISPLAY_ORDER: Array<{ code: string; name: string }> = [
  { code: "A01", name: "Broken Access Control" },
  { code: "A02", name: "Cryptographic Failures" },
  { code: "A03", name: "Injection" },
  { code: "A04", name: "Insecure Design" },
  { code: "A05", name: "Security Misconfiguration" },
  { code: "A06", name: "Vulnerable & Outdated Components" },
  { code: "A07", name: "Identification & Auth Failures" },
  { code: "A08", name: "Software & Data Integrity Failures" },
  { code: "A09", name: "Security Logging & Monitoring Failures" },
  { code: "A10", name: "Server-Side Request Forgery (SSRF)" },
];

function shortenFile(path: string): string {
  // /terraform/aws/db-app.tf  →  aws/db-app.tf
  // /apps/api/src/routes/x.ts →  …/routes/x.ts
  const parts = path.replace(/^\/+/, "").split("/");
  if (parts.length <= 2) return parts.join("/");
  return `…/${parts.slice(-2).join("/")}`;
}

export default function CodeRiskStoriesWidget({
  owaspCounts,
  owaspUnmapped,
  hotFiles,
  hotPackages,
}: Props) {
  const navigate = useNavigate();

  // Find the max OWASP count for bar-width normalisation
  const owaspMax = Math.max(1, ...Object.values(owaspCounts ?? {}));
  // Total mapped + unmapped — used for the "X% covered" caveat below.
  const owaspTotal = Object.values(owaspCounts ?? {}).reduce((a, b) => a + b, 0)
    + (owaspUnmapped ?? 0);
  const mappedPct = owaspTotal > 0
    ? Math.round(((owaspTotal - (owaspUnmapped ?? 0)) / owaspTotal) * 100)
    : 0;

  // Top 5 hot files / packages
  const topHotFiles    = (hotFiles    ?? []).slice(0, 5);
  const topHotPackages = (hotPackages ?? []).slice(0, 5);

  return (
    <div>
      <div className="mb-4 flex items-center justify-between">
        <h2 className="flex items-center gap-1.5 text-sm font-semibold text-white">
          <Target className="h-3.5 w-3.5 text-indigo-400" />
          Code Risk Stories
        </h2>
        <span className="text-[10px] uppercase tracking-wider text-gray-500">
          OWASP · concentrations
        </span>
      </div>

      {/* Section A — OWASP Top 10 distribution */}
      <div>
        <div className="mb-2 flex items-center justify-between text-[10px] uppercase tracking-wider text-gray-500">
          <span>OWASP Top 10 (2021) · this org</span>
          {owaspTotal > 0 && (owaspUnmapped ?? 0) > 0 && (
            <span title={`${owaspUnmapped} findings have no CWE that maps cleanly to an OWASP family`}>
              {mappedPct}% mapped
            </span>
          )}
        </div>
        <div className="space-y-1">
          {OWASP_DISPLAY_ORDER.map((family) => {
            const count = owaspCounts?.[family.code] ?? 0;
            const pct = Math.round((count / owaspMax) * 100);
            const inactive = count === 0;
            return (
              <button
                key={family.code}
                onClick={() => navigate(`/findings?tab=code&owaspFamily=${family.code}`)}
                disabled={inactive}
                className={`block w-full text-left transition-colors ${
                  inactive ? "opacity-40 cursor-default" : "hover:opacity-100"
                }`}
                title={inactive ? `No findings under ${family.code}` : `Filter findings to ${family.code} ${family.name}`}
              >
                <div className="mb-0.5 flex items-center justify-between gap-2 text-[11px]">
                  <span className="flex min-w-0 items-baseline gap-2">
                    <span className="shrink-0 font-mono text-[10px] text-indigo-300">{family.code}</span>
                    <span className="truncate text-gray-300">{family.name}</span>
                  </span>
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
        </div>
      </div>

      {/* Sections B + C — concentrations side-by-side */}
      <div className="mt-5 grid grid-cols-1 gap-5 lg:grid-cols-2">
        {/* Section B — Hot files */}
        <div>
          <div className="mb-2 flex items-center gap-1.5 text-[10px] uppercase tracking-wider text-gray-500">
            <FileCode className="h-3 w-3" />
            Hot files
          </div>
          <div className="space-y-1">
            {topHotFiles.map((row) => (
              <button
                key={`${row.filePath}-${row.scanType}`}
                onClick={() => navigate(`/findings?tab=code&search=${encodeURIComponent(row.filePath)}`)}
                className="flex w-full items-center justify-between gap-3 rounded border border-gray-800 bg-gray-900/40 px-3 py-1.5 text-left transition-colors hover:border-gray-700 hover:bg-gray-900/60"
                title={row.filePath}
              >
                <span className="flex min-w-0 items-center gap-2">
                  <span className="shrink-0 rounded bg-gray-800 px-1.5 py-0.5 text-[9px] font-mono text-gray-400">
                    {row.scanType}
                  </span>
                  <span className="truncate font-mono text-[11px] text-gray-200">
                    {shortenFile(row.filePath)}
                  </span>
                </span>
                <span className="tabular-nums rounded bg-gray-800 px-1.5 py-0.5 text-[10px] font-semibold text-gray-300">
                  {row.count}
                </span>
              </button>
            ))}
            {topHotFiles.length === 0 && (
              <div className="text-xs text-gray-500">—</div>
            )}
          </div>
        </div>

        {/* Section C — Hot packages */}
        <div>
          <div className="mb-2 flex items-center gap-1.5 text-[10px] uppercase tracking-wider text-gray-500">
            <Package className="h-3 w-3" />
            Hot packages
          </div>
          <div className="space-y-1">
            {topHotPackages.map((row) => (
              <button
                key={row.packageName}
                onClick={() => navigate(`/findings?tab=code&search=${encodeURIComponent(row.packageName)}`)}
                className="flex w-full items-center justify-between gap-3 rounded border border-gray-800 bg-gray-900/40 px-3 py-1.5 text-left transition-colors hover:border-gray-700 hover:bg-gray-900/60"
                title={`${row.packageName} — ${row.count} CVE${row.count === 1 ? "" : "s"}`}
              >
                <span className="flex min-w-0 items-center gap-2">
                  <span className="shrink-0 rounded bg-gray-800 px-1.5 py-0.5 text-[9px] font-mono text-gray-400">
                    PKG
                  </span>
                  <span className="truncate font-mono text-[11px] text-gray-200">
                    {row.packageName}
                  </span>
                </span>
                <span className="tabular-nums rounded bg-gray-800 px-1.5 py-0.5 text-[10px] font-semibold text-gray-300">
                  {row.count} CVE{row.count === 1 ? "" : "s"}
                </span>
              </button>
            ))}
            {topHotPackages.length === 0 && (
              <div className="text-xs text-gray-500">—</div>
            )}
          </div>
        </div>
      </div>

      {/* Footer link to full findings */}
      <div className="mt-4 flex justify-end">
        <button
          onClick={() => navigate(`/findings?tab=code`)}
          className="flex items-center gap-1 text-xs text-indigo-400 hover:text-indigo-300"
        >
          View all code findings <ArrowRight className="h-3 w-3" />
        </button>
      </div>
    </div>
  );
}
