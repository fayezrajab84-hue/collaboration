# Phase 29 Slice C1 — GitHub posture (Prowler `--provider github`)

**Status:** scoped, not started
**Predecessor:** Phase 29 Slice A (CSPM via Prowler — same scanner container, same OCSF normaliser path). Phase 22.6 (Marketplace launch) — recommended ship-after-this so the GitHub App installation token from Marketplace is the auth path Slice C1 reuses.
**Surfaced by:** end-of-session conversation Apr 30 2026. Discovered Prowler 5.25.1 ships a GitHub provider with **24 checks across 3 services** (organization / repository / githubactions) — high-value posture coverage that Aikido and Snyk don't ship. Cheap integration (Prowler does the work) with strong demo value.

---

## Why this slice now

Three reasons:

1. **OSS gap matched to a real customer pain.** Every GitHub-using org has the same 24 misconfigurations: branch protection inconsistent across repos, members without MFA, secret scanning not enabled, force pushes allowed, no CODEOWNERS review, dependabot off. Prowler already audits these. We get 24 high-quality checks for ~50 LOC of plumbing.

2. **Differentiates against GHAS.** GitHub Advanced Security pushes branch-protection enforcement, secret scanning, CodeQL — the security FEATURES. We become the meta-tool that **audits whether GHAS is even configured correctly** across an org's repos. Different value angle, complementary moat.

3. **Reuses Phase 22.6's GitHub App.** The Marketplace App we're building gets installed at the org level with `metadata:read` + `contents:read`. Prowler's GitHub provider needs the same surface plus `administration:read` for org-level checks. **One auth flow, two value layers** — Slice C1 layered on top of an App that already exists.

---

## Dashboard architecture decision (the actual UX call)

We're at 4 tabs today (Code / Web / Runtime / Cloud). Adding a 5th GitHub tab doesn't scale — Phase 33 (NHI) wants another, AWS joins Cloud, M365 wants its own. By Q3 we'd be at 7+ tabs.

**Decision: Architecture B — sub-tabs within existing tabs.** Keep 4 top-level tabs; add sub-pivots inside.

| Top-level tab | Sub-pivots after Slice C1 |
|---|---|
| **Code** | **Vulnerabilities** (SAST/SCA/Secret/IaC) + **Posture** (GitHub Prowler) |
| **Web** | (unchanged for now) |
| **Runtime** | (unchanged) |
| **Cloud** | Will gain sub-pivots when AWS/GCP/M365 land (Slices C2-C4) |

Rationale:
- **No rename required.** "Code" stays "Code" — operators understand it
- **Maps to user mental models.** "Vulnerabilities in my code" vs. "Hygiene of my code repos" are different questions in the same domain
- **Pattern reuses** — Cloud tab gets the same treatment when AWS/GCP/M365 land
- **Reversible.** If sub-pivots feel cramped, promote any one to a top-level tab later. Going the other way (collapsing 7 tabs) is harder.

C (rename Code → Source) was considered and rejected for the comms cost vs. marginal clarity benefit.

---

## The asset graph — where GitHub findings live

Prowler's GitHub provider fires findings on three target types. Mapping to BreachLens:

| Prowler scope | BreachLens target | Notes |
|---|---|---|
| Organization-level (5 checks) | **`GitHubAccount`** (NEW resource) | Parallels `CloudAccount`. Holds the GitHub App installation token. Org-level findings attach here. |
| Repository-level (18 checks) | **`Repository`** (existing) | Just adds new `ScanType.GITHUB_POSTURE`. New `Repository.githubAccountId` FK. |
| GitHub Actions (1 check, zizmor) | **`Repository`** (existing) | Workflow files live in a repo. |

**Schema additions (~30 LOC):**

```prisma
model GitHubAccount {
  id                   String   @id @default(cuid())
  orgId                String
  installationId       Int      @unique  // GitHub App installation ID
  accountLogin         String           // "fayezrajab84-hue" or org name
  accountType          GitHubAccountType  // USER | ORGANIZATION
  encryptedCredentials Json             // App installation token (rotates) + cached metadata
  lastScannedAt        DateTime?
  createdAt            DateTime @default(now())
  repositories         Repository[]
  findings             Finding[]
  @@index([orgId, accountLogin])
}

enum GitHubAccountType { USER ORGANIZATION }

// Repository extension
model Repository {
  // ... existing fields ...
  githubAccountId String?
  githubAccount   GitHubAccount? @relation(...)
}
```

Plus:
- Add `ScanType.GITHUB_POSTURE` to the enum
- Add `TargetType.GITHUB_ACCOUNT` to the enum

---

## The 10 highest-signal findings to highlight

From the 24 Prowler checks, the subset most worth surfacing prominently in the dashboard:

| # | Check ID | Severity | Why it matters |
|---|---|---|---|
| 1 | `organization_members_mfa_required` | **CRITICAL** | Direct credential-theft entry point |
| 2 | `repository_default_branch_protection_enabled` | HIGH | Foundation for everything below |
| 3 | `repository_default_branch_protection_applies_to_admins` | HIGH | No admin-bypass — most orgs forget this |
| 4 | `repository_default_branch_disallows_force_push` | HIGH | History-rewriting attack path |
| 5 | `repository_secret_scanning_enabled` | HIGH | Preventable credential leaks |
| 6 | `repository_dependency_scanning_enabled` (Dependabot) | HIGH | Known-vuln blind spot |
| 7 | `repository_default_branch_requires_codeowners_review` | HIGH | Prevents single-person merges to critical code |
| 8 | `repository_default_branch_dismisses_stale_reviews` | HIGH | Stale approvals = bypass |
| 9 | `repository_default_branch_status_checks_required` | HIGH | CI bypass = unscanned merges |
| 10 | `githubactions_workflow_security_scan` (zizmor) | HIGH | `pull_request_target` abuse, command injection in run steps |

These 10 cover ~80% of real-world GitHub-posture risk. The remaining 14 (signed commits, immutable releases, linear history, verified badges, conversation resolution, multiple approvals, etc.) are nice-to-have and surface in the per-repo drawer but not the top-level dashboard.

---

## Slice breakdown — 5 commits, ~410 LOC, ~8 hours

| Slice | LOC | Effort | What it ships |
|---|---|---|---|
| **C1.0 — Backend integration** | ~50 | 1 hr | Prowler `--provider github` plumbing in scanner-cspm. Pydantic discriminator for GitHub auth. Reuse Phase 22.6's GitHub App installation token (or a separate PAT for pre-Marketplace dev). New `GITHUB_POSTURE` ScanType + scan worker dispatch. |
| **C1.1 — Schema** | ~30 | 30 min | `GitHubAccount` model + `Repository.githubAccountId` FK + enum additions. Zod schemas. CRUD routes for `/api/github-accounts`. |
| **C1.2 — Sub-tab UI in Code tab** | ~150 | 3 hrs | Code tab gets Vulnerabilities / Posture sub-pivots. URL state: `?tab=code&sub=posture`. Reuses `<DataTable>` + `<StatsCard>`. **This is the dashboard architecture choice in code.** Pattern reusable for Cloud tab when AWS/GCP land. |
| **C1.3 — "Top GitHub Misconfigurations" widget** | ~80 | 1.5 hrs | Dashboard widget on the Code tab Posture sub-pivot. Bar chart of the 10 highlighted checks ranked by occurrence count. New "Posture" column on the Repos table (red/yellow/green dot per repo). |
| **C1.4 — Per-repo posture drawer** | ~100 | 2 hrs | Click a repo → drawer shows all 18 repo-level checks as a ✓/✗ checklist with explanations. **The demo moment** — every GitHub engineer recognizes these settings. |

**Total: ~410 LOC, ~8 hours.**

---

## C1.2 — Sub-tab UI shape (the architecture decision in code)

Files to touch:
- `apps/web/src/pages/FindingsPage.tsx` — add sub-pivot state to existing Code tab
- `apps/web/src/pages/DashboardPage.tsx` — same
- New shared component: `apps/web/src/components/SubTabPivot.tsx` (~30 LOC, reusable for Cloud later)

URL state convention:
```
/findings?tab=code                    // defaults to vulnerabilities (back-compat)
/findings?tab=code&sub=vulnerabilities
/findings?tab=code&sub=posture
/dashboard?tab=code&sub=posture
```

Default sub-pivot = **vulnerabilities** so existing bookmarks / shared links still work.

Visual treatment:
- Sub-pivot looks like a secondary nav (smaller text, beneath the main tab row)
- Active sub-pivot uses brand-indigo underline (matches the rest of the brand colour memory)
- Empty state on Posture sub-pivot when no GitHubAccount is configured: "Connect a GitHub organization in Settings → GitHub Accounts to scan for posture issues."

---

## Auth flow — reusing Phase 22.6's GitHub App

Three paths depending on session timing:

| Scenario | Auth source |
|---|---|
| **Slice C1 ships before Phase 22.6** | Operator provides a Personal Access Token (PAT) with `read:org` + `repo` scopes per org. Stored encrypted on `GitHubAccount`. Acceptable for dev / first customer. |
| **Slice C1 ships alongside / after Phase 22.6** | Reuse the GitHub App installation token (auto-rotates, no human secret). `GitHubAccount.installationId` references the App's installation in the customer's org. |
| **Both supported simultaneously** | `GitHubAccount.encryptedCredentials` carries either `{type: "PAT", token: "..."}` or `{type: "APP_INSTALLATION", installationId: 12345}`. Scanner reads the discriminator at scan time. |

**Recommendation:** ship both auth modes from day one. The discriminator pattern is ~10 LOC additional vs. PAT-only and avoids a future migration.

---

## Verification checklist

When Slices C1.0 → C1.4 ship, verify against a real GitHub org (start with our own `fayezrajab84-hue`):

1. Schema migration applied; `npx prisma db push` clean
2. Connect `fayezrajab84-hue` GitHub account via Settings → GitHub Accounts (PAT auth for v1)
3. Trigger GITHUB_POSTURE scan → expect 24 findings within ~30s wall clock
4. Verify findings on the org map to `targetType=GITHUB_ACCOUNT`; findings on each repo map to `targetType=REPOSITORY`
5. Open Findings page → switch to Code tab → click "Posture" sub-pivot → all 24 GitHub findings render correctly
6. Open Dashboard → Code tab → Posture sub-pivot → "Top GitHub Misconfigurations" widget renders the 10 highlighted checks
7. Click a repo with multiple findings → per-repo posture drawer opens → all 18 repo-level checks render as a ✓/✗ checklist
8. Vulnerabilities sub-pivot still shows SAST/SCA/Secret/IaC findings — no regression
9. Existing `/findings?tab=code` URL still works (defaults to vulnerabilities)
10. Empty state on Posture sub-pivot renders correctly when no GitHubAccount configured

---

## Deferred to Slice C1.5

Six findings BreachLens could add ON TOP of Prowler's 24, scoped here for tracking. Not v1 — wait for customer feedback after Marketplace launch to prioritize.

| Finding | Severity | Source | Why deferred |
|---|---|---|---|
| **Long-lived Personal Access Tokens** (>1 year, no expiry, broad scopes) | HIGH | `/orgs/{org}/personal-access-tokens` | Requires PAT inventory permissions; customer may not grant initially |
| **Outdated webhook URLs** (broken endpoints, no SSL verification) | MEDIUM | `/repos/{repo}/hooks` | Adds noise on big orgs; need rate limiting |
| **Stale outside collaborators** (no activity 90+ days) | MEDIUM | `/orgs/{org}/outside_collaborators` + recent contributions API | Two API calls per collaborator; only worth it if customers ask |
| **Workflow secrets without recent rotation** | MEDIUM | `/repos/{repo}/actions/secrets` | API only exposes `updated_at`, not the value — limited diagnostic |
| **GitHub App permissions audit** (transparency) | INFO | Self-introspection | Nice-to-have, not pressing |
| **Deploy keys without expiry** | LOW | `/repos/{repo}/keys` | Niche; older pattern |

**~150 LOC additional.** Scope C1.5 only after Marketplace customer feedback lands.

---

## Risks + mitigations

| Risk | Severity | Mitigation |
|---|---|---|
| **GitHub API rate limits** for orgs with many repos (5K req/hr per token) | Medium | Pagination + retry-after handling. Default scan cadence: weekly (posture changes slowly) not daily. |
| **`administration:read` permission** is admin-only — procurement friction | Medium | Document as a one-time admin step. Provide a script to grant + verify. Make org-level checks degrade gracefully when permission missing (still surface repo-level checks). |
| **Aikido / Snyk add posture checks** within 12 months | Strategic | Speed of execution. Ship Slice C1 well before Marketplace launch so it's part of the listing's hero pitch. |
| **Sub-pivot UI feels cramped at small viewport widths** | Low | Mobile breakpoint: collapse sub-pivot into a dropdown. ~10 LOC additional. |
| **Repos without recent activity (archived) trigger noise** | Low | Filter scan target list to non-archived repos by default. |

---

## Closing thought

This is a cheap unlock with strong demo value. The integration cost is small (~50 LOC for Prowler plumbing); the bulk of the work is **dashboard UX** — and that's the moat. The "Top 10 GitHub Misconfigurations" widget + per-repo posture checklist are the kind of surfaces that screenshot well in a Marketplace listing.

The dashboard architecture decision (B: sub-tabs) is more important long-term than the Prowler integration itself. Slice C1.2 codifies that pattern; Cloud / Identity / future tabs reuse it. Get this right once and the dashboard scales to 10+ scan types without UX degradation.

**Sequencing reminder:** Slice C1 is cheaper than Slice B but Slice B is the moat-mover for Marketplace (5-act chain demo). Ship Slice B first; Slice C1 fits inline as part of Marketplace prep.
