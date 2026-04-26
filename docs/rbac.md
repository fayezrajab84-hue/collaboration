# RBAC — Role-Based Access Control

BreachLens uses a **5-tier role hierarchy** scoped per organization. A
user can have different roles in different orgs (e.g. OWNER of their
personal sandbox, DEVELOPER of the company TEAM org).

> **You listed 4 roles but there are 5** — ADMIN sits between OWNER and
> SECURITY and is the most common elevation gate (deletes, member
> management, settings, integrations). Easy to miss because OWNER and
> ADMIN have nearly identical *day-to-day* capabilities; the OWNER
> distinction matters only for last-owner protection (see below).

---

## The 5 roles

| Role | Rank | Conceptual purpose |
|---|---|---|
| `OWNER` | 5 | Ultimate authority. Cannot be demoted to leave the org with zero OWNERs. |
| `ADMIN` | 4 | Org administration without "last man standing" protection. |
| `SECURITY` | 3 | Triage findings, manage suppressions, bulk-status changes. |
| `DEVELOPER` | 2 | Add scan targets, trigger scans, view results. |
| `VIEWER` | 1 | Read-only — dashboards, findings list, scan history. |

Plus one **legacy alias**:

| `MEMBER` | 2 | Pre-Phase-22 enum value. Treated identically to DEVELOPER by the RBAC layer. New code should use DEVELOPER directly; MEMBER stays in the schema for migration safety. |

**Canonical source:** `apps/api/src/services/rbac.ts` defines the
`Role` type + `ROLE_RANK` map. Every gating decision (route middleware
+ frontend `<Can>` checks) flows through the same rank.

---

## Capability matrix (what's actually gated, by route)

These are the explicit `requireRole(X)` middleware sites. Anything not
listed requires only `requireAuth` — i.e. any role including VIEWER can
hit it.

### ADMIN+ (rank ≥ 4) — 19 routes

| Route | Why ADMIN |
|---|---|
| `GET /api/admin/*` | BullMQ queue inspection (Bull-Board UI) |
| `GET /api/audit` + `GET /api/audit/export.csv` | Audit log read + CSV export |
| `DELETE /api/repos/:id` | Removing a target deletes all its findings — destructive |
| `DELETE /api/containers/:id` | Same |
| `DELETE /api/domains/:id` | Same |
| `PATCH /api/members/:userId` | Change another member's role |
| `DELETE /api/members/:userId` | Remove member from org |
| `GET / POST / DELETE /api/members/invitations` | Invitation CRUD |
| `POST / PUT / DELETE /api/policies` | Policy editing (PR-check enforcement rules) |
| `GET / PUT / DELETE /api/sso` + `POST /api/sso/test` | SSO config — touches authentication for the whole org |

### SECURITY+ (rank ≥ 3) — 6 routes

| Route | Why SECURITY |
|---|---|
| `POST /api/findings/bulk` | Bulk status change — accepting risk for many findings at once |
| `POST /api/findings/bulk-tickets` | Bulk ticket creation |
| `PATCH /api/findings/:id` | Single-finding status change (FIXED, FALSE_POSITIVE, etc.) |
| `PATCH /api/findings/:id/sub/:index` | Same for sub-findings (multi-instance results) |
| `POST / DELETE /api/suppressions` | Accepted-risk records (skip a finding for N days, requires justification) |

### DEVELOPER+ (rank ≥ 2) — implicit

No explicit `requireRole("DEVELOPER")` anywhere. Instead, the frontend
gates write actions with `<Can role="DEVELOPER">` (see
`apps/web/src/pages/RepositoriesPage.tsx`, `ContainersPage.tsx`):

- Add a new repo / container / domain
- Trigger a scan
- Comment on a finding

The backend allows these via `requireAuth` only — VIEWERs *can* technically
hit them, but the UI doesn't expose the buttons. That's a layered defense
choice: API-level enforcement is for the destructive / privacy-sensitive
operations only.

### VIEWER+ (rank ≥ 1) — implicit

Everything else under `requireAuth`: dashboards, finding lists, scan
history, reports, SBOM downloads.

---

## OWNER's one special power

OWNER and ADMIN are **functionally identical** at every `requireRole`
gate (both rank ≥ 4). The single difference lives in
`apps/api/src/routes/members/router.ts`:

> *"Last-owner safety: the API blocks any operation that would leave
> the org with zero OWNER members (demote, remove, role-change away
> from OWNER)."*

So OWNER is the "this person can never accidentally lose admin
privileges by being demoted" tier. Every org auto-gets exactly one
OWNER (the user who created it / accepted the first SSO login that
provisioned it); subsequent admin elevation goes to ADMIN, not OWNER.

The org has zero `OWNER` members → no one can recover it without DB
access. That's why we block the demotion.

---

## Adding a new role-gated route

### Backend (Express)

```ts
import { requireRole } from "../../middleware/requireRole.js";

router.delete("/:id", requireRole("ADMIN"), async (req, res) => {
  // req.orgId and req.orgRole are populated by requireRole as side effects —
  // downstream handlers can use them without re-resolving membership
});
```

The middleware returns:

- `401 { error: "Authentication required" }` if not signed in
- `403 { error: "No organization membership" }` if the user has no membership in their active org
- `403 { error: "Requires role X or higher (you have Y)" }` if rank insufficient

### Frontend (React)

```tsx
import { Can } from "../components/Can";

<Can role="SECURITY">
  <button onClick={handleSuppress}>Mark as accepted risk</button>
</Can>
```

`<Can>` renders children only when the user's active-org role meets the
minimum. It uses `useRole()` which reads from the cached `/auth/me`
response — no extra API call.

---

## How to pick the right role for a new gate

Reference questions to decide which tier a new route/UI control belongs to:

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
boundary; the UI is the affordance boundary. They're allowed to differ.

---

## Related files

- `apps/api/prisma/schema.prisma` — `enum Role` definition
- `apps/api/src/services/rbac.ts` — type + rank + helper functions (`roleAtLeast`, `hasAnyRole`)
- `apps/api/src/middleware/requireRole.ts` — Express middleware that gates routes + populates `req.orgRole` + `req.orgId`
- `apps/web/src/hooks/useRole.ts` — React hook returning `{ role, can }`
- `apps/web/src/components/Can.tsx` — `<Can role="X">` declarative wrapper
- `apps/web/src/components/settings/TeamTab.tsx` — UI for changing member roles + the role dropdown options
