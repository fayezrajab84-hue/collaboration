/**
 * Phase 29 Slice C1.5a — GitHub posture finding-detail panels.
 *
 * Two stacked panels rendered in FindingDetailDrawer when a finding's
 * scanType is GITHUB_POSTURE AND evidence.github.repository is populated:
 *
 *   Panel A — Repository hygiene
 *     6-row checklist of repo-level hygiene flags (secret scanning,
 *     dependabot, SECURITY.md, CODEOWNERS, immutable releases, delete-
 *     branch-on-merge). The row that matches THIS finding's ruleId is
 *     highlighted in rose; the rest render as informational state so
 *     operators see the FULL hygiene picture without leaving the drawer.
 *
 *   Panel B — Branch protection
 *     12-row checklist of the default-branch protection state. Same
 *     highlight-the-matching-row pattern. Most actionable surface for
 *     posture findings — every GitHub engineer recognizes these
 *     settings.
 *
 * Org-level findings (5 of 24 checks) have no repository context, so
 * neither panel renders for them. The dashboard widget's per-repo
 * drawer (RepoPostureDrawer) already shows the per-repo checklist
 * cross-cut by the catalog; this component shows the SAME state but
 * scoped to the single finding the operator clicked into.
 */
import { CheckCircle2, XCircle, MinusCircle, GitBranch, ShieldCheck, Calendar, Github, Lock, Unlock, Archive } from "lucide-react";

interface Repository {
  fullName?:                 string;
  owner?:                    string;
  private?:                  boolean;
  archived?:                 boolean;
  pushedAt?:                 string | null;
  secretScanningEnabled?:    boolean | null;
  dependabotAlertsEnabled?:  boolean | null;
  securitymd?:               boolean | null;
  codeownersExists?:         boolean | null;
  immutableReleasesEnabled?: boolean | null;
  deleteBranchOnMerge?:      boolean | null;
  defaultBranch?:            DefaultBranch | null;
}

interface DefaultBranch {
  name?:                       string;
  protected?:                  boolean;
  status_checks?:              boolean;
  approval_count?:             number;
  enforce_admins?:             boolean;
  branch_deletion?:            boolean;
  allow_force_pushes?:         boolean;
  require_pull_request?:       boolean;
  dismiss_stale_reviews?:      boolean;
  require_signed_commits?:     boolean;
  conversation_resolution?:    boolean;
  required_linear_history?:    boolean;
  require_code_owner_reviews?: boolean;
}

// Maps a Prowler ruleId → the field on the repo / default_branch object
// that this check evaluates. Used to highlight the row in the checklist
// that triggered THIS finding. Some checks invert the field (e.g.
// "disallows force push" passes when allow_force_pushes is FALSE).
const RULE_TO_HYGIENE_FIELD: Record<string, keyof Repository> = {
  "repository_secret_scanning_enabled":         "secretScanningEnabled",
  "repository_dependency_scanning_enabled":     "dependabotAlertsEnabled",
  "repository_public_has_securitymd_file":      "securitymd",
  "repository_has_codeowners_file":             "codeownersExists",
  "repository_immutable_releases_enabled":      "immutableReleasesEnabled",
  "repository_branch_delete_on_merge_enabled":  "deleteBranchOnMerge",
};

const RULE_TO_BRANCH_FIELD: Record<string, keyof DefaultBranch> = {
  "repository_default_branch_protection_enabled":              "protected",
  "repository_default_branch_protection_applies_to_admins":    "enforce_admins",
  "repository_default_branch_disallows_force_push":            "allow_force_pushes",
  "repository_default_branch_dismisses_stale_reviews":         "dismiss_stale_reviews",
  "repository_default_branch_requires_codeowners_review":      "require_code_owner_reviews",
  "repository_default_branch_requires_signed_commits":         "require_signed_commits",
  "repository_default_branch_status_checks_required":          "status_checks",
  "repository_default_branch_requires_multiple_approvals":     "approval_count",
  "repository_default_branch_requires_conversation_resolution": "conversation_resolution",
  "repository_default_branch_deletion_disabled":               "branch_deletion",
  "repository_default_branch_requires_linear_history":         "required_linear_history",
};

// Fields where TRUE means PASS on the underlying GitHub setting AND on
// the Prowler check. (e.g. `protected: true` is good.)
//
// Inverted fields (where FALSE means PASS at the Prowler check level)
// — these checks succeed when the GitHub setting is OFF:
//   `allow_force_pushes` (Prowler: disallow force push) — false is good
//   `branch_deletion`    (Prowler: deletion disabled)   — false is good
const INVERTED_BRANCH_FIELDS = new Set<keyof DefaultBranch>([
  "allow_force_pushes",
  "branch_deletion",
]);

function formatPushedAt(iso: string | null | undefined): string {
  if (!iso) return "—";
  try {
    const d = new Date(iso);
    const days = Math.floor((Date.now() - d.getTime()) / (1000 * 60 * 60 * 24));
    if (days < 1)   return "today";
    if (days < 2)   return "yesterday";
    if (days < 30)  return `${days} days ago`;
    if (days < 365) return `${Math.floor(days / 30)} months ago`;
    return `${Math.floor(days / 365)} years ago`;
  } catch {
    return iso;
  }
}

function StatusIcon({ value, isHighlighted }: { value: boolean | null | undefined; isHighlighted: boolean }) {
  if (value === null || value === undefined) {
    return <MinusCircle className="h-4 w-4 text-gray-600" />;
  }
  if (value) {
    return <CheckCircle2 className={`h-4 w-4 ${isHighlighted ? "text-rose-400" : "text-emerald-500"}`} />;
  }
  return <XCircle className={`h-4 w-4 ${isHighlighted ? "text-rose-400" : "text-gray-500"}`} />;
}

interface ChecklistRow {
  label:         string;
  value:         boolean | null | undefined;
  /** True when this row is the one the current finding is about. */
  highlighted:   boolean;
  /** When true, "good" state is value=false (e.g. force pushes disabled). */
  inverted?:     boolean;
}

function ChecklistItem({ row }: { row: ChecklistRow }) {
  // For inverted fields, the displayed icon should reflect the Prowler
  // pass state, not the raw boolean. Force pushes ALLOWED = bad = X icon
  // even though the field is `true`.
  const passState = row.inverted ? !row.value : row.value;
  return (
    <li
      className={`flex items-center justify-between rounded border px-3 py-1.5 ${
        row.highlighted
          ? "border-rose-900/60 bg-rose-950/20"
          : "border-gray-800 bg-gray-900/40"
      }`}
    >
      <span className={`text-xs ${row.highlighted ? "font-semibold text-gray-100" : "text-gray-300"}`}>
        {row.label}
        {row.highlighted && (
          <span className="ml-2 rounded bg-rose-900/50 px-1.5 py-0.5 text-[10px] font-medium text-rose-200">
            this finding
          </span>
        )}
      </span>
      <StatusIcon value={passState} isHighlighted={row.highlighted} />
    </li>
  );
}

interface Props {
  ruleId:     string | null | undefined;
  repository: Repository | null | undefined;
}

export default function GitHubPosturePanels({ ruleId, repository }: Props) {
  if (!repository) return null;

  const highlightedHygiene = ruleId ? RULE_TO_HYGIENE_FIELD[ruleId] : undefined;
  const highlightedBranch  = ruleId ? RULE_TO_BRANCH_FIELD[ruleId]  : undefined;

  const hygieneRows: ChecklistRow[] = [
    { label: "Secret scanning enabled",         value: repository.secretScanningEnabled,    highlighted: highlightedHygiene === "secretScanningEnabled" },
    { label: "Dependabot alerts enabled",       value: repository.dependabotAlertsEnabled,  highlighted: highlightedHygiene === "dependabotAlertsEnabled" },
    { label: "SECURITY.md present",             value: repository.securitymd,               highlighted: highlightedHygiene === "securitymd" },
    { label: "CODEOWNERS file present",         value: repository.codeownersExists,         highlighted: highlightedHygiene === "codeownersExists" },
    { label: "Immutable releases enabled",      value: repository.immutableReleasesEnabled, highlighted: highlightedHygiene === "immutableReleasesEnabled" },
    { label: "Delete branch on merge",          value: repository.deleteBranchOnMerge,      highlighted: highlightedHygiene === "deleteBranchOnMerge" },
  ];

  const db = repository.defaultBranch ?? null;
  const branchRows: ChecklistRow[] | null = db ? [
    { label: "Branch protected",                value: db.protected,                  highlighted: highlightedBranch === "protected" },
    { label: "Protection applies to admins",    value: db.enforce_admins,             highlighted: highlightedBranch === "enforce_admins" },
    { label: "Force pushes disallowed",         value: db.allow_force_pushes,         highlighted: highlightedBranch === "allow_force_pushes", inverted: true },
    { label: "Pull request required",           value: db.require_pull_request,       highlighted: false },
    { label: "Dismiss stale reviews",           value: db.dismiss_stale_reviews,      highlighted: highlightedBranch === "dismiss_stale_reviews" },
    { label: "Require code owners",             value: db.require_code_owner_reviews, highlighted: highlightedBranch === "require_code_owner_reviews" },
    { label: "Status checks required",          value: db.status_checks,              highlighted: highlightedBranch === "status_checks" },
    { label: "Signed commits required",         value: db.require_signed_commits,     highlighted: highlightedBranch === "require_signed_commits" },
    { label: "Conversation resolution",         value: db.conversation_resolution,    highlighted: highlightedBranch === "conversation_resolution" },
    { label: "Linear history required",         value: db.required_linear_history,    highlighted: highlightedBranch === "required_linear_history" },
    { label: "Branch deletion blocked",         value: db.branch_deletion,            highlighted: highlightedBranch === "branch_deletion", inverted: true },
  ] : null;

  // Approval-count is a number, not a boolean — render separately below
  // the checklist when relevant.
  const approvalCount = db?.approval_count ?? null;
  const approvalHighlighted = highlightedBranch === "approval_count";

  return (
    <div className="space-y-3">
      {/* Repository header — name + visibility + activity */}
      <div className="rounded-lg border border-gray-800 bg-gray-900/50 px-3 py-2">
        <div className="mb-1.5 flex items-center gap-1.5">
          <Github className="h-3 w-3 text-gray-500" />
          <span className="text-[11px] font-semibold uppercase tracking-wider text-gray-400">Repository</span>
        </div>
        <div className="flex flex-wrap items-center gap-2">
          <span className="font-mono text-sm text-gray-100" title={repository.fullName ?? undefined}>
            {repository.fullName ?? "—"}
          </span>
          {repository.private != null && (
            <span className={`inline-flex items-center gap-1 rounded px-1.5 py-0.5 text-[10px] font-medium ${
              repository.private
                ? "bg-gray-800 text-gray-300"
                : "bg-amber-900/30 text-amber-300 border border-amber-800/40"
            }`}>
              {repository.private ? <Lock className="h-2.5 w-2.5" /> : <Unlock className="h-2.5 w-2.5" />}
              {repository.private ? "Private" : "Public"}
            </span>
          )}
          {repository.archived && (
            <span className="inline-flex items-center gap-1 rounded bg-gray-800 px-1.5 py-0.5 text-[10px] font-medium text-gray-400">
              <Archive className="h-2.5 w-2.5" /> Archived
            </span>
          )}
          {repository.pushedAt && (
            <span className="inline-flex items-center gap-1 text-[10px] text-gray-500" title={repository.pushedAt}>
              <Calendar className="h-2.5 w-2.5" /> last push {formatPushedAt(repository.pushedAt)}
            </span>
          )}
        </div>
      </div>

      {/* Panel A — Repository hygiene */}
      <div className="rounded-lg border border-gray-800 bg-gray-900/50 px-3 py-2">
        <div className="mb-1.5 flex items-center gap-1.5">
          <ShieldCheck className="h-3 w-3 text-gray-500" />
          <span className="text-[11px] font-semibold uppercase tracking-wider text-gray-400">Repository hygiene</span>
        </div>
        <ul className="space-y-1">
          {hygieneRows.map((row) => (
            <ChecklistItem key={row.label} row={row} />
          ))}
        </ul>
      </div>

      {/* Panel B — Branch protection (only when default_branch is captured) */}
      {branchRows && (
        <div className="rounded-lg border border-gray-800 bg-gray-900/50 px-3 py-2">
          <div className="mb-1.5 flex items-center gap-1.5">
            <GitBranch className="h-3 w-3 text-gray-500" />
            <span className="text-[11px] font-semibold uppercase tracking-wider text-gray-400">
              Branch protection {db?.name && <span className="ml-1 font-mono normal-case text-gray-500">· {db.name}</span>}
            </span>
          </div>
          <ul className="space-y-1">
            {branchRows.map((row) => (
              <ChecklistItem key={row.label} row={row} />
            ))}
            {/* Approval-count row — special-cased because it's numeric.
                Renders as "≥2 approvals" or "no approval rule" depending
                on value; highlighted when this finding is about the
                multiple-approvals check. */}
            {approvalCount !== null && (
              <li className={`flex items-center justify-between rounded border px-3 py-1.5 ${
                approvalHighlighted
                  ? "border-rose-900/60 bg-rose-950/20"
                  : "border-gray-800 bg-gray-900/40"
              }`}>
                <span className={`text-xs ${approvalHighlighted ? "font-semibold text-gray-100" : "text-gray-300"}`}>
                  Required PR approvals
                  {approvalHighlighted && (
                    <span className="ml-2 rounded bg-rose-900/50 px-1.5 py-0.5 text-[10px] font-medium text-rose-200">
                      this finding
                    </span>
                  )}
                </span>
                <span className={`tabular-nums text-xs ${
                  approvalCount >= 2 ? "text-emerald-400" : "text-gray-500"
                }`}>
                  {approvalCount === 0 ? "none" : `${approvalCount}`}
                </span>
              </li>
            )}
          </ul>
        </div>
      )}
    </div>
  );
}
