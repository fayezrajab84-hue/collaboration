/**
 * Phase 29 Slice C1.4 — Per-repo (or per-org) GitHub posture checklist drawer.
 *
 * Renders the full catalog of Prowler GitHub checks with ✓/✗ status,
 * computed by overlaying actual FAIL findings onto the static catalog.
 *
 * The "demo moment" surface — every GitHub engineer recognizes these
 * settings (branch protection, MFA, signed commits, secret scanning).
 * Rendering them as one scanned-and-graded checklist is recognizable +
 * actionable.
 *
 * Two modes:
 *   - scope="repository": shows the 19 checks (18 repo + 1 githubactions)
 *     that apply to a single repository
 *   - scope="organization": shows the 5 org-level checks
 *
 * Click a FAILed row → navigates to the FindingDetailDrawer for that
 * specific finding (operators can then triage / accept-risk / etc.).
 */
import { useNavigate } from "react-router-dom";
import { X, CheckCircle2, XCircle, ExternalLink } from "lucide-react";
import type { Finding } from "@devsecops/types";
import { catalogForScope, type PostureCheck } from "../lib/githubPostureCatalog";
import SeverityBadge from "./SeverityBadge";

interface Props {
  open:      boolean;
  onClose:   () => void;
  /** What this drawer is for. */
  scope:     "repository" | "organization";
  /** Display label in the header — repo full name OR account login. */
  targetLabel: string;
  /** All currently-loaded GITHUB_POSTURE findings for this account.
   *  The drawer filters internally to the ones that target this specific
   *  repo / account; it doesn't make its own API call. */
  findings:  Finding[];
  /** When scope=repository, the repositoryId to filter findings by.
   *  When scope=organization, ignored (org-level findings have null
   *  repositoryId — they're scoped to GitHubAccount). */
  repositoryId?: string;
}

export default function RepoPostureDrawer({
  open,
  onClose,
  scope,
  targetLabel,
  findings,
  repositoryId,
}: Props) {
  const navigate = useNavigate();

  if (!open) return null;

  const catalog = catalogForScope(scope);

  // Filter findings to ones that apply to THIS target.
  const scoped = findings.filter((f) => {
    const fRepoId = (f as Record<string, unknown>)["repositoryId"] as string | undefined;
    if (scope === "repository") return fRepoId === repositoryId;
    return fRepoId == null; // org-level findings have no repositoryId
  });

  // Index FAIL findings by ruleId so we can mark catalog rows.
  const failByRule = new Map<string, Finding>();
  for (const f of scoped) {
    if (f.ruleId && !failByRule.has(f.ruleId)) failByRule.set(f.ruleId, f);
  }

  const passingCount = catalog.length - failByRule.size;
  const failingCount = failByRule.size;

  // Group catalog rows by scope label for readability when scope=repository
  // (mixes 18 repository + 1 githubactions).
  const groups: Array<{ label: string; checks: PostureCheck[] }> = [];
  if (scope === "repository") {
    const repoChecks = catalog.filter((c) => c.scope === "repository");
    const actionChecks = catalog.filter((c) => c.scope === "githubactions");
    groups.push({ label: "Branch protection + repo settings", checks: repoChecks });
    if (actionChecks.length > 0) {
      groups.push({ label: "GitHub Actions workflows", checks: actionChecks });
    }
  } else {
    groups.push({ label: "Organization policies", checks: catalog });
  }

  return (
    <>
      {/* Click-outside backdrop */}
      <div
        className="fixed inset-0 z-40 bg-black/40 backdrop-blur-sm"
        onClick={onClose}
      />

      {/* Drawer (right-side panel, mirrors FindingDetailDrawer's pattern) */}
      <aside className="fixed right-0 top-0 z-50 flex h-full w-full max-w-2xl flex-col overflow-hidden border-l border-gray-800 bg-gray-950 shadow-2xl">
        {/* Header */}
        <div className="border-b border-gray-800 bg-gray-900/60 px-5 py-4">
          <div className="flex items-start justify-between gap-4">
            <div className="min-w-0">
              <div className="text-[10px] uppercase tracking-wider text-gray-500">
                {scope === "repository" ? "Repository posture" : "Organization posture"}
              </div>
              <h2 className="mt-0.5 truncate text-base font-semibold text-white" title={targetLabel}>
                {targetLabel}
              </h2>
              <div className="mt-1.5 flex items-center gap-3 text-xs">
                <span className="inline-flex items-center gap-1 text-emerald-400">
                  <CheckCircle2 className="h-3.5 w-3.5" />
                  <span className="tabular-nums font-semibold">{passingCount}</span>
                  <span className="text-gray-500">passing</span>
                </span>
                <span className="inline-flex items-center gap-1 text-rose-400">
                  <XCircle className="h-3.5 w-3.5" />
                  <span className="tabular-nums font-semibold">{failingCount}</span>
                  <span className="text-gray-500">failing</span>
                </span>
                <span className="text-gray-500">
                  · {catalog.length} checks total
                </span>
              </div>
            </div>
            <button
              onClick={onClose}
              className="-mr-2 rounded-md p-1.5 text-gray-400 hover:bg-gray-800 hover:text-white"
              aria-label="Close"
            >
              <X className="h-4 w-4" />
            </button>
          </div>
        </div>

        {/* Scrollable checklist */}
        <div className="flex-1 overflow-y-auto px-5 py-4 text-sm">
          {groups.map((group, gi) => (
            <div key={gi} className={gi > 0 ? "mt-6" : ""}>
              <div className="mb-2 text-[10px] uppercase tracking-wider text-gray-500">
                {group.label}
              </div>
              <ul className="space-y-1.5">
                {group.checks.map((c) => {
                  const failed = failByRule.has(c.ruleId);
                  const finding = failByRule.get(c.ruleId);
                  return (
                    <li
                      key={c.ruleId}
                      className={`rounded border px-3 py-2 transition-colors ${
                        failed
                          ? "border-rose-900/60 bg-rose-950/20 hover:border-rose-800"
                          : "border-gray-800 bg-gray-900/40"
                      }`}
                    >
                      <button
                        onClick={() => {
                          if (finding) {
                            // Navigate to FindingDetailDrawer for the
                            // specific FAIL — operators can then triage.
                            navigate(`/findings?finding=${finding.id}`);
                            onClose();
                          }
                        }}
                        disabled={!failed}
                        className="flex w-full items-start gap-3 text-left disabled:cursor-default"
                      >
                        <span className="mt-0.5 shrink-0">
                          {failed ? (
                            <XCircle className="h-4 w-4 text-rose-400" />
                          ) : (
                            <CheckCircle2 className="h-4 w-4 text-emerald-500" />
                          )}
                        </span>
                        <span className="min-w-0 flex-1">
                          <span className="flex items-center gap-2">
                            <span className={`text-xs font-medium ${failed ? "text-gray-100" : "text-gray-300"}`}>
                              {c.title}
                            </span>
                            <SeverityBadge severity={c.severity} />
                            {failed && (
                              <ExternalLink className="h-3 w-3 text-gray-500" />
                            )}
                          </span>
                          <span className="mt-0.5 block text-[11px] leading-relaxed text-gray-500">
                            {c.rationale}
                          </span>
                          <span className="mt-0.5 block font-mono text-[10px] text-gray-600">
                            {c.ruleId}
                          </span>
                        </span>
                      </button>
                    </li>
                  );
                })}
              </ul>
            </div>
          ))}
        </div>

        {/* Footer help text */}
        <div className="border-t border-gray-800 bg-gray-900/40 px-5 py-3 text-[11px] text-gray-500">
          Failing checks link to the underlying finding. Passing checks
          are inferred from the absence of a FAIL — Prowler PASS records
          aren't persisted (re-scan to refresh).
        </div>
      </aside>
    </>
  );
}
