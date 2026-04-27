# RBAC — Roles, Permissions, and What Each Role Can Do

BreachLens uses **5 roles** scoped per organization. A user can have
different roles in different orgs (e.g. OWNER of their personal sandbox,
DEVELOPER on the company TEAM org).

```
OWNER  >  ADMIN  >  SECURITY  >  DEVELOPER  >  VIEWER
   5         4         3            2            1
```

Higher roles inherit everything lower roles can do.

> **`MEMBER` is a legacy alias** kept in the schema for migration safety.
> The RBAC layer treats it identically to `DEVELOPER` (same rank).
> New code should use `DEVELOPER` directly.

---

## Quick reference: capability matrix

✓ = can do it · ✗ = blocked

| Capability | OWNER | ADMIN | SECURITY | DEVELOPER | VIEWER |
|---|:-:|:-:|:-:|:-:|:-:|
| **Read** dashboards, findings, scans, reports | ✓ | ✓ | ✓ | ✓ | ✓ |
| **Add** repos / containers / domains | ✓ | ✓ | ✓ | ✓ | ✗ |
| **Trigger** scans on existing targets | ✓ | ✓ | ✓ | ✓ | ✗ |
| **Triage findings** (status changes, false positive, fixed) | ✓ | ✓ | ✓ | ✗ | ✗ |
| **Bulk** finding operations | ✓ | ✓ | ✓ | ✗ | ✗ |
| **Accept risk** (suppressions) | ✓ | ✓ | ✓ | ✗ | ✗ |
| **Delete** repos / containers / domains | ✓ | ✓ | ✗ | ✗ | ✗ |
| **Invite / remove / re-role members** | ✓ | ✓ | ✗ | ✗ | ✗ |
| **Edit policies** (PR-check enforcement rules) | ✓ | ✓ | ✗ | ✗ | ✗ |
| **Configure SSO** | ✓ | ✓ | ✗ | ✗ | ✗ |
| **View audit log** + export CSV | ✓ | ✓ | ✗ | ✗ | ✗ |
| **Inspect / retry / delete failed BullMQ jobs** | ✓ | ✓ | ✗ | ✗ | ✗ |
| **Last-OWNER protection** (org can't lose all owners) | ✓ | ✗ | ✗ | ✗ | ✗ |

---

## What each role can do

### OWNER

The org's ultimate authority. Identical day-to-day capabilities as ADMIN
**plus** one structural protection: an org can never lose all of its
OWNERs. Demotion / removal of the last OWNER is blocked at the API level
to prevent accidental admin lockout.

Every org auto-gets exactly one OWNER (the user who created it / accepted
the first SSO login that provisioned it). Subsequent admin elevation
should typically go to ADMIN, not OWNER.

### ADMIN

Org administration without the last-man-standing protection. Has every
read / write capability except OWNER's structural one:

- Manage members <!-- contract:change-member-role --> <!-- contract:remove-member --> — change roles, remove people, invite new GitHub users <!-- contract:list-invitations --> <!-- contract:create-invitation --> <!-- contract:revoke-invitation -->
- Configure single sign-on <!-- contract:view-sso-config --> <!-- contract:save-sso-config --> <!-- contract:delete-sso-config --> <!-- contract:test-sso-discovery -->
- Edit security policies (PR-check rules) <!-- contract:create-policy --> <!-- contract:update-policy --> <!-- contract:delete-policy -->
- Read the audit log + export it as CSV <!-- contract:view-audit-log --> <!-- contract:export-audit-csv -->
- Export per-framework compliance evidence (CSV + printable HTML for auditors) <!-- contract:export-compliance-csv --> <!-- contract:export-compliance-html -->
- Delete repos, containers, and domains (cascades all their findings) <!-- contract:delete-repo --> <!-- contract:delete-container --> <!-- contract:delete-domain -->
- Declare Phase 27 asset relations — which images each repo builds, which repo+domains a container belongs to, which containers serve a domain. Mis-declared linkage causes the correlation engine to produce incorrect attack paths. <!-- contract:update-repo-asset-links --> <!-- contract:update-container-asset-links --> <!-- contract:update-domain-asset-links -->
- Manage Phase 27.5 Application boundaries — create, edit, delete applications, and assign Repository / Container / Domain components to them. Application membership decides which findings get correlated together, so mis-assignment corrupts the chain graph for the whole org. <!-- contract:create-application --> <!-- contract:update-application --> <!-- contract:delete-application --> <!-- contract:assign-application-components -->
- Inspect the BullMQ queue, retry failed jobs, delete failed jobs <!-- contract:view-admin-queues --> <!-- contract:view-failed-jobs --> <!-- contract:retry-failed-job --> <!-- contract:delete-failed-job -->
- Plus everything SECURITY, DEVELOPER, and VIEWER can do

ADMIN is the right tier for engineering managers, security leads, or
anyone who needs full operational control without being an "owner of
the org" in a structural sense.

### SECURITY

The triage tier. Manages the lifecycle of findings — what's a real
issue, what's accepted risk, what's been fixed.

- Change a finding's status (FIXED, FALSE_POSITIVE, ACKNOWLEDGED, etc.) <!-- contract:update-finding-status --> <!-- contract:update-subfinding-status -->
- Bulk-change many findings at once <!-- contract:bulk-update-findings -->
- Bulk-create tickets from findings <!-- contract:bulk-create-tickets -->
- Accept risk on a finding (create a suppression with justification + expiry) <!-- contract:create-suppression -->
- Revoke an accepted-risk record <!-- contract:revoke-suppression -->
- Plus everything DEVELOPER and VIEWER can do

SECURITY is the right tier for the security engineer who reviews scan
output but doesn't manage org-level config.

### DEVELOPER

Adds scan targets and triggers scans. Cannot triage findings or change
their status — that's SECURITY's responsibility.

- Add a repository, container image, or domain to the org <!-- contract:add-repo --> <!-- contract:add-container -->
- Kick off a scan job on any existing target <!-- contract:trigger-repo-scan --> <!-- contract:trigger-container-scan -->
- Plus everything VIEWER can do

DEVELOPER is the default role for engineers — they can wire their
projects in and run scans, but can't accidentally accept risk on a
critical vuln.

### VIEWER

Read-only across the org. Sees the same dashboards, finding lists, scan
history, and reports as everyone else, but can't change anything.

VIEWER is the right tier for execs, auditors, and external stakeholders
who need visibility without operational responsibility.

---

## Common scenarios

| "I want to…" | Need at least |
|---|---|
| Look at the dashboard / findings / reports | VIEWER (any signed-in user) |
| Add a new GitHub repo to scan | DEVELOPER |
| Trigger a fresh scan on a repo | DEVELOPER |
| Mark a finding as a false positive | SECURITY |
| Accept risk on an OPEN finding for 90 days | SECURITY |
| Bulk-close 50 findings at once | SECURITY |
| Invite a new teammate via GitHub username | ADMIN |
| Change someone's role from DEVELOPER to SECURITY | ADMIN |
| Configure Entra ID / Okta SSO for the org | ADMIN |
| Download the audit log as CSV for compliance | ADMIN |
| Edit the policy that blocks PRs with HIGH+ findings | ADMIN |
| Delete a repo and all its findings | ADMIN |
| Demote the org's only OWNER | **Blocked** — last-OWNER protection |

---

## UI gates as of Phase 22.7

The frontend parity test originally surfaced 5 affordances visible to
all roles despite ADMIN/SECURITY API enforcement. Phase 22.7 closed
all of them via:

- **`SettingsPage` tab-level filter** — drops Audit Log, SSO, Policies
  (ADMIN-only) and Suppressions (SECURITY-only) from the sidebar nav
  for users without the role
- **Per-tab `<Can role="X">` wrappers** in AuditLogTab, SSOTab,
  PoliciesTab — defense in depth in case a tab is reached via
  deep-link
- **Per-affordance `<Can role>`** on DomainsPage delete row action and
  FindingsPage bulk toolbar
- **New `SuppressionsTab`** so accepted-risk records are auditable at
  the org level (revoke button gated by `<Can role="SECURITY">`)
- **`useRole` fixed** to read the active org's role (was reading
  `orgs[0]` and ignoring `activeOrgId`, so multi-org users got the
  role from the wrong org)

VIEWERs no longer see buttons that 403 on click.

---

## For developers

### Where the rules live

- `apps/api/prisma/schema.prisma` — `enum Role` definition (5 + MEMBER alias)
- `apps/api/src/services/rbac.ts` — `Role` type + `ROLE_RANK` map + helpers
- `apps/api/src/middleware/requireRole.ts` — Express middleware that gates routes
- `apps/web/src/hooks/useRole.ts` — React hook returning `{ role, can }`
- `apps/web/src/components/Can.tsx` — `<Can role="X">` declarative wrapper
- **`packages/types/src/roleContract.ts`** — single source of truth for which action requires which role; both api and web import this for tests + (eventually) for the gates themselves

### The contract is the canonical reference

When the table above and `roleContract.ts` disagree, **the contract
wins**. The doc is hand-written and may drift; the parity tests
(`apps/api/src/role-contract.test.ts` + `apps/web/src/role-contract.test.ts`)
verify the contract matches actual code.

A separate test (`apps/api/src/role-docs.test.ts`) verifies that every
contract entry appears in *this* doc as a `<!-- contract:<id> -->`
comment. Adding a new gated action requires a contract entry, a
`requireRole` call, a `<Can>` wrapper, and a line in this doc with the
matching contract comment.

### Adding a new role-gated route

1. Add an entry to `ROLE_CONTRACT` in `packages/types/src/roleContract.ts`
2. In the route handler: `requireRole("MIN_ROLE")`
3. In the UI: `<Can role="MIN_ROLE">…</Can>` around the affordance
4. Add a bullet under the right role in this doc with `<!-- contract:<id> -->`
5. Re-run `pnpm test` in both `apps/api` and `apps/web` — all four
   parity checks (rbac unit, requireRole matrix, backend parity,
   frontend parity, doc coverage) confirm everything agrees

### How to pick the right tier

| Question | If yes → role |
|---|---|
| Could a misuse cost money or expose data? | ADMIN |
| Does it modify auth, integrations, or membership? | ADMIN |
| Could it leave the org without an admin? | OWNER (and add last-owner check) |
| Does it change the security posture (accept risk, mark FP)? | SECURITY |
| Does it change scan targets or trigger work? | DEVELOPER (UI-gated, API allows authed) |
| Is it read-only? | VIEWER (default — no requireRole needed) |

When in doubt, gate **lower** (more permissive) on the API side and
**higher** (more restrictive) on the UI side. The API is the security
boundary; the UI is the affordance boundary. They're allowed to differ
— the parity test allows UI to be MORE strict than the contract floor.
