# Phase 22.5 — GitHub Enterprise + GitHub App support

**Status:** scoped, not started
**Predecessor:** Phase 22 (RBAC + SSO + audit) — ✅ shipped
**Successor it unblocks:** Phase 17 (auto-fix PRs) — needs a GitHub App to post PRs as a bot rather than as a user

---

## Why this phase exists

A real customer told us their setup:

```
User → Entra ID → GitHub Enterprise (federated)
```

Today BreachLens has two sign-in options:

- **Continue with GitHub** — hardcoded to github.com via `passport-github2` defaults. Useless for GHES.
- **Sign in with SSO** — generic OIDC, configurable per org (Entra/Okta/Auth0/Google/Keycloak). Works for the *identity* half.

The problem is BreachLens conflates two responsibilities in the GitHub OAuth flow:

1. **Authentication** — "who is this user?" (currently the GitHub `profile.id` as `githubId`)
2. **Repo access** — "give me a token to clone repos and create webhooks" (the encrypted `User.accessToken`)

For SSO-provisioned users, the JIT path stores `encrypt("oidc-no-token")` as a placeholder — those users *cannot* trigger scans on private repos. Phase 22's existing comment acknowledges this:

> *"No real access token for SSO users — placeholder ciphertext so the NOT NULL constraint is satisfied. SSO users can't clone private repos via this account; that's a deliberate limitation until we add per-user GitHub-token linking on top of SSO."*

Phase 22.5 closes that gap, the right way: **decouple identity from repo access**, then add the two pieces an Entra-federated-GHES customer actually needs.

---

## What "the right way" looks like

| Concern | Current | Phase 22.5 target |
|---|---|---|
| Identity | GitHub OAuth OR Entra OIDC SSO | Same — Entra OIDC stays the primary path |
| Repo-access token storage | `User.accessToken` (per-user) | `Integration` (per-org) — survives user offboarding |
| Repo-access auth method | OAuth user token | **GitHub App installation token** (auto-rotates, fine-grained perms, can post PRs as a bot) |
| GHES support for sign-in | None | Optional second OAuth provider with configurable base URL |
| Scan-time token resolution | `repo.org.members[0].user.accessToken` | `org.integrations.find(t => t === GITHUB_APP).installationId → mint installation token` |

This is also the canonical pattern Snyk, Aikido, and Wiz use for GHES integrations — GitHub App at the org level, not OAuth tokens per user.

---

## Slice plan (suggested commit shape)

### Slice A — Configurable GHES OAuth login *(small, ~3h)*

**Goal:** add a "Sign in with GitHub Enterprise" path that points at the customer's GHES instance, not github.com.

**Changes:**

- `apps/api/src/config.ts` — three optional env vars:
  ```env
  GITHUB_ENTERPRISE_URL=https://github.acme.com    # base URL of GHES
  GITHUB_ENTERPRISE_CLIENT_ID=...
  GITHUB_ENTERPRISE_CLIENT_SECRET=...
  ```
  When set, BreachLens registers a *second* passport strategy alongside the existing github.com one.
- `apps/api/src/auth/passport.ts` — register a second `GitHubStrategy` with custom URLs:
  ```ts
  authorizationURL: `${GHES_URL}/login/oauth/authorize`,
  tokenURL:         `${GHES_URL}/login/oauth/access_token`,
  userProfileURL:   `${GHES_URL}/api/v3/user`,
  userEmailURL:     `${GHES_URL}/api/v3/user/emails`,
  ```
- `apps/api/src/routes/auth.ts` — `/auth/github-enterprise` + `/auth/github-enterprise/callback`. Same JIT logic as the existing GitHub flow, but the resulting `githubId` is namespaced (e.g. `ghes:<id>`) so the same person on github.com vs on GHES doesn't collide as the same User.
- `apps/web/src/pages/LoginPage.tsx` — a third button, `Continue with <ghes-domain>`, only rendered when the env var is set (falls back to nothing in dev).
- `GET /api/sso` — surface whether GHES is configured so the UI can render the button conditionally.

**Verify:**
- `passport.use("github-enterprise", ...)` only registers when env vars present
- Hitting `/auth/github-enterprise` with no env config returns 404, not 500
- End-to-end: register OAuth app on a GHES instance → click button → callback completes → JIT user lands in dashboard

**Open question:** Should the existing "Continue with GitHub" button still appear when GHES is configured, or hide? Recommendation: hide by default (most enterprise tenants don't want their devs accidentally signing in with personal github.com accounts), with an env override to keep both visible.

---

### Slice B — Schema + Integration record for GitHub App *(medium, ~4h)*

**Goal:** make space in the data model for org-level GitHub App installations *before* writing the install flow.

**Changes:**

- `apps/api/prisma/schema.prisma` — extend the existing `IntegrationType` enum:
  ```prisma
  enum IntegrationType {
    JIRA
    SLACK
    MICROSOFT_TEAMS
    GITHUB_APP            // ← new
  }
  ```
  And on the `Integration` model, the `encryptedData` JSON field already holds arbitrary payloads — for `GITHUB_APP` the shape is:
  ```ts
  {
    installationId:   number;
    accountLogin:     string;     // org/user the App is installed on
    accountType:      "Organization" | "User";
    repoSelection:    "all" | "selected";
    selectedRepoIds?: number[];   // only when repoSelection === "selected"
    githubBaseUrl:    string;     // "https://api.github.com" or GHES API URL
  }
  ```
- Make `User.accessToken` **optional** (`String?`). Migration writes a sentinel for any existing NOT NULL rows during the transition; new SSO users no longer need the placeholder ciphertext.
- New service `apps/api/src/services/githubAppService.ts`:
  - JWT signing with the App's private key (RS256) — env vars `GITHUB_APP_ID` + `GITHUB_APP_PRIVATE_KEY_PEM`
  - `getInstallationToken(installationId)` — exchanges JWT for a 1h installation token, in-memory LRU cached by installationId with a 50min TTL
  - `getRepoTokenForOrg(orgId)` — single entry point: looks up the org's `GITHUB_APP` integration, mints/returns a cached installation token

**Verify:**
- `npx prisma db push` succeeds, `\d "Integration"` unchanged structurally (just enum range expanded)
- Unit test: `getInstallationToken` correctly signs a JWT using a test keypair (use a fixture private key, don't hit GitHub)

---

### Slice C — GitHub App install flow + UI *(medium, ~5h)*

**Goal:** let an org admin install the BreachLens GitHub App and have it land as a usable `Integration` row.

**Changes:**

- `apps/api/src/routes/integrations/router.ts`:
  - `GET /api/integrations/github-app/install-url` — returns the GitHub App install URL with `state=<random+orgId-signed>` for CSRF; on github.com the URL is `https://github.com/apps/<app-slug>/installations/new`, on GHES it's `https://github.acme.com/github-apps/<app-slug>/installations/new`
  - `GET /api/integrations/github-app/callback` — receives `installation_id`, `setup_action`, `state`. Validates state, fetches the installation metadata via JWT-authed App API, persists the `Integration` row.
  - `DELETE /api/integrations/github-app` — removes the integration locally; reminds the user to also uninstall on GitHub.
- `apps/web/src/components/settings/IntegrationsTab.tsx` (or similar):
  - "Install GitHub App" button → opens install URL in a new tab
  - After install completes, status pill shows "Connected to <org>" with installation metadata + a "Disconnect" affordance
  - For GHES, an env-driven hint: "App ID `123`, install on https://github.acme.com/organizations/.../settings/installations"

**Verify:**
- Can install on a personal account, see the row appear, then uninstall — both via the app and via BreachLens
- `state` validation rejects forged callbacks
- Repo list filtered to those the App actually has access to (use `GET /installation/repositories`)

**Open question:** GitHub App definition itself. Do we ship a single Anthropic-managed app with a stable `app-slug`, or do customers create their own private App per deployment? For self-hosted BreachLens, customer-created App is the only viable path (they own the private key, never trust us). Document this in the install flow as the first step.

---

### Slice D — Migrate scan-time token resolution to org tokens *(medium, ~4h)*

**Goal:** stop reading `User.accessToken` for repo cloning when the org has a GitHub App installed.

**Changes:**

- `apps/api/src/services/sastSnippetService.ts` (and any other call site that does `org.members[0].user.accessToken` or similar) — use a new `getRepoTokenForOrg(orgId)` helper:
  - **Prefer** GitHub App installation token if the org has a `GITHUB_APP` integration
  - **Fall back** to the first OWNER's `User.accessToken` if no App installed (legacy path)
  - **Throw** with a clear "no repo access configured for this org" error when neither exists
- `triggerTestScan.ts` and equivalent migration scripts — same pattern
- `apps/scanner/main.py` — accepts the token over the existing `gitToken` field; no change needed since the source is opaque to the scanner
- Update the per-user-token storage: keep it for legacy users but stop *requiring* it — Phase 22 already added the placeholder; this just makes the placeholder permanent for SSO-only users

**Verify:**
- Org with GitHub App + SSO-only user → can trigger SAST scan, scanner clones repo using App token
- Org with no App + GitHub-OAuth user → still works (legacy fallback)
- Org with no App + SSO-only user → scan fails with the clear error message, *not* a confusing 500

**Open question:** Should we *also* support per-user GitHub Enterprise OAuth as a third tier (for audit-strict environments where each clone must be attributable)? Recommendation: **no, defer to Phase 22.6 if it ever comes up** — App-installation tokens already include the `triggered_by` user via `actions/identifying-the-installation`, so the audit trail exists at the GitHub side.

---

## Effort estimate

| Slice | Lines | Time | Risk |
|---|---|---|---|
| A — GHES OAuth login | ~80 | 3h | Low — passport-github2 supports custom URLs; well-trodden |
| B — Schema + service | ~250 | 4h | Medium — JWT signing edge cases (clock skew, key format) |
| C — Install flow + UI | ~350 | 5h | Medium — GitHub App API has quirks; CSRF state matters |
| D — Token resolution refactor | ~150 | 4h | Low — central helper, ~5 call sites |
| **Total** | **~830** | **~2 days focused** | — |

Splits cleanly into 4 commits matching the slice boundaries — same shape as Phase 22 PR 3 (Slices A/B/C).

---

## Procurement value

This phase removes **two** procurement blockers:

1. **GHES customers can't sign in** — current state literally locks them out, since the github.com button does the wrong thing and they have no SSO credentials yet
2. **GHES + Entra customers can sign in but can't scan private repos** — the Phase 22 placeholder token bites here

Both are "no" votes from regulated buyers (financial services, healthcare, defense — exactly the buyers most likely to run GHES). Closing them should be Month 2 work alongside Phase 16 (compliance dashboards) — same buyer profile.

It also unblocks **Phase 17 (auto-fix PRs)** by establishing the GitHub App pattern. PR auto-creation as a bot user is the standard play; doing it through user OAuth tokens is fragile (token expires, user leaves, PRs orphaned).

---

## Open questions to settle before starting

1. **GitHub App ownership** — does Anthropic ship a public BreachLens App that customers install (single shared `app-slug`), or do customers create their own per-deployment? *Self-hosted constraint says customer-created — confirm.*
2. **Hide github.com button when GHES configured?** — recommended yes, with env override. Confirm.
3. **Per-user GHES OAuth as a third tier** — defer to Phase 22.6, or include here? Recommend defer.
4. **Migration plan for existing User.accessToken rows** — leave them as-is and prefer App tokens when available, or proactively encourage admins to switch? Recommend leave-as-is + Settings UI nudge.

Resolve these four before we start writing Slice A.
