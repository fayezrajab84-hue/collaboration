/**
 * Phase 29 Slice C1.4 — Static catalog of Prowler's 24 GitHub posture checks.
 *
 * Used by the per-repo posture checklist drawer to render a complete ✓/✗
 * picture: every check Prowler ships, marked PASS by default, with FAILs
 * overlaid from the actual scan findings.
 *
 * Why static:
 *   The current normalizer filters Prowler PASS records and only emits FAIL
 *   findings. So we don't know from findings alone "did the check run +
 *   pass" vs "the scan didn't cover this." Anchoring the UI on a known
 *   catalog of all 24 checks makes the checklist deterministic — every
 *   row renders, with FAILs flagged from findings and the rest assumed
 *   passing. If the underlying check list shifts (Prowler bumps add new
 *   checks), we update this catalog; the rest of the UI is unchanged.
 *
 * Scope:
 *   `organization` — 5 org-level checks (target = GitHubAccount in DB)
 *   `repository`   — 18 repo-level checks (target = Repository in DB)
 *   `githubactions` — 1 workflow-security check (target = Repository)
 *
 * Severity reflects Prowler's defaults (verified via `prowler github
 * --list-checks` on 5.25.1 — see commit message for the dump).
 */

export type PostureCheckScope = "organization" | "repository" | "githubactions";

export interface PostureCheck {
  ruleId:     string;
  title:      string;
  scope:      PostureCheckScope;
  severity:   "CRITICAL" | "HIGH" | "MEDIUM" | "LOW";
  /** Short operator-facing rationale (1 sentence). */
  rationale:  string;
}

export const GITHUB_POSTURE_CATALOG: PostureCheck[] = [
  // ── Organization-level (5) ────────────────────────────────────────────
  {
    ruleId:    "organization_members_mfa_required",
    title:     "Members must have 2FA enabled",
    scope:     "organization",
    severity:  "CRITICAL",
    rationale: "Direct credential-theft entry point if any member can sign in without a second factor.",
  },
  {
    ruleId:    "organization_default_repository_permission_strict",
    title:     "Default repository permission is read or none",
    scope:     "organization",
    severity:  "HIGH",
    rationale: "Limits blast radius if any account is compromised — the attacker doesn't auto-inherit write on every repo.",
  },
  {
    ruleId:    "organization_repository_creation_limited",
    title:     "Repository creation limited to trusted members",
    scope:     "organization",
    severity:  "HIGH",
    rationale: "Stops random members from spinning up shadow repos that bypass policy + scanning.",
  },
  {
    ruleId:    "organization_repository_deletion_limited",
    title:     "Repository deletion / transfer restricted to owners",
    scope:     "organization",
    severity:  "HIGH",
    rationale: "Prevents accidental wipes + malicious destruction by compromised non-owner accounts.",
  },
  {
    ruleId:    "organization_verified_badge",
    title:     "Organization has a verified badge",
    scope:     "organization",
    severity:  "MEDIUM",
    rationale: "Supply-chain trust signal for downstream consumers; verified domains tie the org to a real entity.",
  },

  // ── Repository-level branch protection (8) ────────────────────────────
  {
    ruleId:    "repository_default_branch_protection_enabled",
    title:     "Default branch protection enabled",
    scope:     "repository",
    severity:  "HIGH",
    rationale: "Foundation for everything else — without protection, any of the policies below are bypassable.",
  },
  {
    ruleId:    "repository_default_branch_protection_applies_to_admins",
    title:     "Branch protection applies to admins (no admin bypass)",
    scope:     "repository",
    severity:  "HIGH",
    rationale: "Most orgs forget this — admin accounts can otherwise force-push or merge without review.",
  },
  {
    ruleId:    "repository_default_branch_disallows_force_push",
    title:     "Default branch denies force pushes",
    scope:     "repository",
    severity:  "HIGH",
    rationale: "Force-push rewrites history; an attacker can replay benign commit history while sneaking in malicious changes.",
  },
  {
    ruleId:    "repository_default_branch_dismisses_stale_reviews",
    title:     "Stale pull-request approvals dismissed on new commits",
    scope:     "repository",
    severity:  "HIGH",
    rationale: "Stops attackers from reusing an old approval after pushing additional malicious commits.",
  },
  {
    ruleId:    "repository_default_branch_requires_codeowners_review",
    title:     "Default branch requires CODEOWNERS approval",
    scope:     "repository",
    severity:  "HIGH",
    rationale: "Prevents single-person merges to critical code paths (auth, payments, infra).",
  },
  {
    ruleId:    "repository_default_branch_requires_signed_commits",
    title:     "Default branch requires signed commits",
    scope:     "repository",
    severity:  "HIGH",
    rationale: "Cryptographically binds commits to authors — supply-chain integrity at the commit level.",
  },
  {
    ruleId:    "repository_default_branch_status_checks_required",
    title:     "Default branch requires status checks",
    scope:     "repository",
    severity:  "HIGH",
    rationale: "CI bypass = unscanned merges; required checks force every change through the security pipeline.",
  },
  {
    ruleId:    "repository_default_branch_requires_multiple_approvals",
    title:     "Default branch requires ≥2 approvals",
    scope:     "repository",
    severity:  "MEDIUM",
    rationale: "Two-person rule reduces single-account-compromise blast radius for code changes.",
  },
  {
    ruleId:    "repository_default_branch_requires_conversation_resolution",
    title:     "Default branch requires conversation resolution before merge",
    scope:     "repository",
    severity:  "MEDIUM",
    rationale: "Stops merges that ignore unresolved review comments — security review concerns can't be merged-around.",
  },
  {
    ruleId:    "repository_default_branch_deletion_disabled",
    title:     "Default branch deletion disabled",
    scope:     "repository",
    severity:  "MEDIUM",
    rationale: "Prevents accidental deletion that wipes history + breaks downstream consumers.",
  },
  {
    ruleId:    "repository_default_branch_requires_linear_history",
    title:     "Default branch requires linear history",
    scope:     "repository",
    severity:  "LOW",
    rationale: "Easier audit trail; merge commits can hide intermediate commits that the review missed.",
  },

  // ── Repository-level code/release security (4) ────────────────────────
  {
    ruleId:    "repository_dependency_scanning_enabled",
    title:     "Dependabot / dependency scanning enabled",
    scope:     "repository",
    severity:  "HIGH",
    rationale: "Known-vuln blind spot — without it, CVEs in dependencies can sit for months unflagged.",
  },
  {
    ruleId:    "repository_secret_scanning_enabled",
    title:     "Secret scanning enabled",
    scope:     "repository",
    severity:  "HIGH",
    rationale: "Catches credential leaks at push time; the most-exploited attack class on public repos.",
  },
  {
    ruleId:    "repository_immutable_releases_enabled",
    title:     "Immutable releases enabled",
    scope:     "repository",
    severity:  "HIGH",
    rationale: "Stops release-tag tampering — a published v1.0.0 stays v1.0.0 even if the tag is force-pushed later.",
  },
  {
    ruleId:    "repository_branch_delete_on_merge_enabled",
    title:     "Delete branch after PR merge",
    scope:     "repository",
    severity:  "LOW",
    rationale: "Hygiene — stale feature branches accumulate access surface and confuse audit trails.",
  },

  // ── Repository-level metadata + lifecycle (3) ─────────────────────────
  {
    ruleId:    "repository_has_codeowners_file",
    title:     "Repository has a CODEOWNERS file",
    scope:     "repository",
    severity:  "MEDIUM",
    rationale: "Codifies who's accountable for which paths — pairs with the codeowners-review check above.",
  },
  {
    ruleId:    "repository_inactive_not_archived",
    title:     "Inactive repos are archived",
    scope:     "repository",
    severity:  "MEDIUM",
    rationale: "Stale repos still grant write access to legacy collaborators — archive removes the attack surface.",
  },
  {
    ruleId:    "repository_public_has_securitymd_file",
    title:     "Public repository has a SECURITY.md file",
    scope:     "repository",
    severity:  "LOW",
    rationale: "Disclosure policy — without one, finders post to Twitter/HN instead of contacting you privately.",
  },

  // ── GitHub Actions (1) ────────────────────────────────────────────────
  {
    ruleId:    "githubactions_workflow_security_scan",
    title:     "Workflow security scan (zizmor)",
    scope:     "githubactions",
    severity:  "HIGH",
    rationale: "Catches `pull_request_target` abuse, command injection in run-steps, hardcoded secrets, and other workflow-specific footguns.",
  },
];

/**
 * Filter the catalog to the checks that apply to a given target shape.
 *
 *   - `organization` scope → org-level checks (rendered when the operator
 *     opens the GitHubAccount-level checklist)
 *   - `repository` scope (with githubactions sibling) → checks that
 *     apply to a single repository
 */
export function catalogForScope(scope: "organization" | "repository"): PostureCheck[] {
  if (scope === "organization") {
    return GITHUB_POSTURE_CATALOG.filter((c) => c.scope === "organization");
  }
  // For a repository view, include both repository + githubactions checks
  // (the workflow check applies per-repo even though Prowler models it
  // under a separate service prefix).
  return GITHUB_POSTURE_CATALOG.filter(
    (c) => c.scope === "repository" || c.scope === "githubactions",
  );
}
