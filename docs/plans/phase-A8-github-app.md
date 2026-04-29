# Phase A8 — BreachLens GitHub App for full auto-discovery + PR triggers

**Status:** scoped, not built. Has a hard external dependency: the GitHub App
must be created in the operator's GitHub account before any of the backend
plumbing matters.

## What this unlocks

After A8, operators install the **BreachLens GitHub App** on their org
once → BreachLens auto-discovers every repo + watches webhooks for
`push` and `pull_request` events. No CI workflow file required to
trigger scans — though the existing Phase A7 workflow still works for
operators who want explicit control.

The end-state operator UX:

```
1. Click "Install BreachLens App on GitHub" in BreachLens Settings
2. Authorize in GitHub UI; pick which repos to grant access to
3. BreachLens auto-onboards every selected repo
4. Push to main → BreachLens scans automatically (no workflow file)
5. Open PR → BreachLens scans the PR branch + posts a Check Run
   with severity summary + click-through to the SARIF/findings
```

That's the Snyk / Aikido / Endor onboarding pattern — install the
App, everything else is automatic.

---

## Existing scaffolding (already in the codebase)

`apps/api/src/github/app.ts` (~150 LOC) already has:

- `isGitHubAppConfigured()` — env-var presence check
- `buildAppJwt()` — App-level JWT for `/app/*` endpoints
- `getInstallationToken(installationId)` — mints + caches per-install
  tokens with 60s pre-expiry refresh
- `installationClient(installationId)` — returns an Octokit-style
  Axios instance authenticated as the installation
- `listPullRequestFiles(...)` — used by PR-comment review flows

So the "talk to GitHub as the App" plumbing is done. What's missing is
the operator-facing pieces: the install flow, webhooks, and per-org
storage of installation IDs.

---

## What's required from the operator (one-time, ~30 min)

### 1. Create the GitHub App on github.com

Path: https://github.com/settings/apps/new (for personal account) OR
https://github.com/organizations/<your-org>/settings/apps/new (for org).

Required configuration:

| Field | Value |
|---|---|
| **Name** | `BreachLens` (must be globally unique on Marketplace; pick alt name if taken) |
| **Homepage URL** | `https://breachlens.fortisentinel.org` |
| **Callback URL** | `https://breachlens.fortisentinel.org/auth/github-app/callback` |
| **Setup URL** | `https://breachlens.fortisentinel.org/settings/integrations/github-app` |
| **Webhook URL** | `https://breachlens.fortisentinel.org/api/webhooks/github-app` |
| **Webhook secret** | generate via `openssl rand -hex 32`, save somewhere safe |
| **Permissions: Repository** | Contents: **Read**; Metadata: **Read**; Pull requests: **Read & Write** (to post Check Runs); Checks: **Read & Write**; Security events: **Read & Write** (to upload SARIF as the App) |
| **Permissions: Account** | Email addresses: **Read** (optional, for first-time onboarding UX) |
| **Subscribe to events** | Pull request, Push, Installation, Installation repositories, Check run |
| **Where can this be installed** | "Any account" (for Marketplace) or "Only on this account" (private install) |

After creation, on the App's settings page note:
- **App ID** (numeric, top of page)
- **Public Link** (for the install URL — `https://github.com/apps/breachlens`)

Generate a **private key** (Settings → "Generate a private key") — downloads
a `.pem` file. **This is the only time you can download it; save it securely.**

### 2. Set env vars in BreachLens `.env`

```
GITHUB_APP_ID=12345                     # the numeric ID from step 1
GITHUB_APP_PRIVATE_KEY="-----BEGIN RSA PRIVATE KEY-----
... (entire .pem contents, multiline OK with quotes) ...
-----END RSA PRIVATE KEY-----"
GITHUB_APP_WEBHOOK_SECRET=<the secret from step 1>
GITHUB_APP_INSTALL_URL=https://github.com/apps/breachlens
```

Restart the API: `docker compose restart api`. Verify with:
```bash
curl https://breachlens.fortisentinel.org/api/settings/github-app/status
# Expected: { "configured": true, "appId": 12345 }
```

### 3. (Optional) List on Marketplace

If you want other orgs to install the App:

1. App settings → "Make public" → confirm
2. App settings → "Marketplace" → fill out listing (description,
   pricing tier "Free", screenshots, ToS, privacy policy URLs)
3. Submit for GitHub review (~3-5 days)

---

## Backend pieces to ship in this phase

### Slice A — Schema + installation lifecycle (~250 LOC)

```prisma
model GitHubInstallation {
  id              String   @id @default(cuid())
  orgId           String
  // GitHub's installation ID (numeric, unique per (App, account))
  githubInstallationId Int  @unique
  // The GitHub user/org login the app is installed on
  accountLogin    String
  accountType     String   // "User" | "Organization"
  accountId       Int
  // Repository selection mode at install time. "all" = every current +
  // future repo; "selected" = only the explicit list, requires
  // installation_repositories events to track changes.
  repositorySelection String  // "all" | "selected"
  // Cached list of granted repo IDs (mirror of
  // /installation/repositories — refreshed on each webhook)
  repositoryIds   Int[]
  installedById   String?
  installedAt     DateTime @default(now())
  uninstalledAt   DateTime?
  // For status display
  lastWebhookAt   DateTime?

  org             Organization @relation(...)
  installedBy     User?        @relation(...)
  @@index([orgId])
}
```

Plus to `Repository` model: `installationId Int?` — when a Repository
is auto-onboarded via App install, store which installation it came
from (so we know which token to use for clones / Check Runs).

### Slice B — Webhook receiver (~150 LOC)

`POST /api/webhooks/github-app` — single endpoint, dispatches by event:

| Event | Handler |
|---|---|
| `installation` (action: created) | Create `GitHubInstallation` row; auto-onboard listed repos |
| `installation` (action: deleted) | Soft-delete row (set `uninstalledAt`); leave repos alone |
| `installation_repositories` (added) | Onboard newly-added repos |
| `installation_repositories` (removed) | (optional) detach repos from installation; no scan trigger |
| `push` (to default branch) | Trigger scan via `triggerScan` service |
| `pull_request` (opened/synchronize) | Trigger PR scan + create pending Check Run |
| `check_run` (rerequested) | Trigger another scan |

HMAC verification on every payload using `GITHUB_APP_WEBHOOK_SECRET`.

### Slice C — Settings UI (~200 LOC)

New tab in `/settings/integrations`: **GitHub App**.

- Status: "Not installed" | "Installed on <accountLogin>" | "Multiple installations"
- "Install BreachLens App" button → opens `GITHUB_APP_INSTALL_URL` in a new window
- After install, GitHub redirects back to the Setup URL → BreachLens
  finalises the flow (matches the installation_id query param to the
  org via the user's session) → returns to Settings showing success
- For installed orgs: list of granted repos, `lastWebhookAt`, "Open
  installation settings on GitHub" link, "Uninstall" guidance

### Slice D — Check Run integration (~100 LOC)

Replace the existing PR-comment-only flow with proper GitHub Check
Runs. When a scan finishes:

```ts
await octokit.checks.create({
  owner, repo,
  name:        "BreachLens / Security scan",
  head_sha:    commitSha,
  status:      "completed",
  conclusion:  gateFailed ? "failure" : "success",
  output: {
    title:    `${critical}C / ${high}H / ${medium}M`,
    summary:  "...",  // markdown with severity table
    text:     "..." , // detailed findings list
  },
});
```

Check Runs show on the PR's "Checks" tab + as inline status indicators.
Same shape Snyk + Aikido use.

### Slice E — Migration path from Phase A7 token-based auth (~50 LOC)

Operators who already onboarded repos via the Phase A7 auto-discovery
should be able to "upgrade" to App-based auth without losing scan
history. Logic:

1. On install, look up Repository rows in the same org by `fullName`
2. Set their `installationId` field to link them to the new install
3. Their existing scan history is preserved untouched

---

## Estimated LOC + time

| Slice | LOC | Time |
|---|---|---|
| A — Schema + lifecycle | ~250 | 2 hours |
| B — Webhook receiver | ~150 | 1.5 hours |
| C — Settings UI | ~200 | 2 hours |
| D — Check Run integration | ~100 | 1 hour |
| E — Migration | ~50 | 30 min |
| **Total** | **~750 LOC** | **~7 hours** |

Plus the operator-side ceremony (~30 min) creating the App on
github.com. Realistic shape: a focused 1-day session for the backend
+ UI, OR split into two sessions (Slice A+B+E in session 1, C+D in
session 2).

---

## Why we're NOT building A8 tonight

The hard dependency is the GitHub App itself. Without:
- A real `GITHUB_APP_ID`
- A real `GITHUB_APP_PRIVATE_KEY`
- A real webhook secret + URL pointing at a reachable BreachLens

…we can't smoke-test ANY of the slices end-to-end. Every webhook
handler, every install flow, every Check Run posting needs the App
configured to validate.

Tonight's Phase A7 work delivers ~80% of the user-facing UX win
(no `repo-id` input required; auto-discovery on first scan) at ~10%
of the engineering cost. A8 is the polish layer that adds:

- **No workflow file required** (push/PR webhooks trigger scans)
- **Proper Check Runs** (vs. the existing SARIF-only feedback loop)
- **GitHub Marketplace listing** (one-click install for any org)

All worth doing. Just not tonight.

---

## When to ship A8

Trigger conditions (any one):

1. A real procurement conversation requires "install the App, no
   workflow file" UX
2. An operator complains about needing to add the workflow file to
   every repo
3. A demo target asks for native Check Run integration (vs. the
   current SARIF/Action-summary view)
4. Marketplace listing motion starts (the App is a prerequisite)

Until then, Phase A7's auto-discovery covers the most common
operator pain point with ~10x less work.

---

## Backwards compatibility stance

When A8 ships, both modes coexist:

| Mode | When to use |
|---|---|
| **A8 — App install** | The default for new operators; minimal-config UX |
| **A7 — workflow file** | Operators who want explicit control over WHEN scans fire (CI gates, scheduled-only, etc.) |
| **Pre-A7 — explicit repo-id** | Legacy; works forever, no deprecation planned |

The action.yml stays a single binary that supports all three modes.
Operators choose by what inputs they pass.
