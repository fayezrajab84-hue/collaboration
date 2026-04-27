# Phase 22.7 — Close the UI/API role-gate parity gaps

**Status:** ✅ shipped
**Predecessor:** Phase 22.6 (RBAC test scaffold) — ✅ shipped
**Surfaced by:** the `apps/web/src/role-contract.test.ts` parity test caught
real drift between the contract and live UI on first run.

## Outcome

All 5 surfaced gaps closed in a single commit cluster. Specifically:

- `SettingsPage.tsx` — tab list filtered by `useRole().can(tab.minRole)`;
  Audit Log / SSO / Policies tabs (ADMIN-only) + Suppressions tab
  (SECURITY-only) hidden from users without the role
- `AuditLogTab.tsx` / `SSOTab.tsx` / `PoliciesTab.tsx` — wrapped in
  `<Can role="ADMIN">` with explanatory fallback; defense-in-depth
  for deep-link / direct-render scenarios
- `DomainsPage.tsx` — Delete row action wrapped in `<Can role="ADMIN">`
- `FindingsPage.tsx` — bulk action toolbar wrapped in
  `<Can role="SECURITY">`
- `SuppressionsTab.tsx` — new component (was missing entirely);
  org-level list of accepted-risk records with per-row Revoke gated
  by `<Can role="SECURITY">`
- `useRole` — fixed to read the active org's role
  (`orgs.find(o => o.id === user.activeOrgId)`) instead of always
  `orgs[0]` — the underlying bug that would have made all the new
  `<Can>` wrappers useless for multi-org users

Contract entries in `roleContract.ts` had their `ui:` pointers
restored from the `// TODO Phase 22.7` placeholders. All 53 tests pass
(50 api + 3 web).

---

## What the parity test discovered

Five UI files use API endpoints that require ADMIN or SECURITY roles but
expose the affordances to **all roles** including VIEWER. Clicking them
results in a 403 from the API — works as a security boundary, but the
UX is broken (button visible, button doesn't work).

| File | Affordance | API requires |
|---|---|---|
| `apps/web/src/components/settings/AuditLogTab.tsx` | View tab + Export CSV button | ADMIN |
| `apps/web/src/components/settings/SSOTab.tsx` | View tab + Save / Remove / Test buttons | ADMIN |
| `apps/web/src/components/settings/PoliciesTab.tsx` | Create / Edit / Delete buttons | ADMIN |
| `apps/web/src/pages/DomainsPage.tsx` | Delete row action | ADMIN |
| `apps/web/src/pages/FindingsPage.tsx` | Bulk status / Bulk tickets toolbar | SECURITY |

Plus one structural gap:

- `apps/web/src/components/settings/SuppressionsTab.tsx` doesn't exist
  yet — suppression revoke lives inline in `FindingDetailDrawer` only.
  Phase 22.7 should either create this tab or update the contract to
  point at the inline location.

The contract entries in `packages/types/src/roleContract.ts` currently
have `// ui: TODO Phase 22.7 — …` placeholders for these. The parity
test passes now because there's no `ui:` claim to verify, but the
mismatch is logged for follow-up.

---

## What "done" looks like

For each file in the table above:

1. Wrap the affordance in `<Can role="X">…</Can>` matching the API gate
2. Add a fallback for non-permitted roles (either hide entirely or show
   read-only state — depends on the affordance)
3. Update the contract entry's `ui:` field to point at the file +
   describe the affordance
4. Re-run `pnpm test` in apps/web; the parity test should still pass

For the SuppressionsTab structural gap:

- **Option A**: Create `SuppressionsTab.tsx` with `<Can role="SECURITY">`
  wrapping the revoke list. Update contract `ui:` to point at it.
- **Option B**: Drop the `revoke-suppression` contract entry's `ui:`
  pointer entirely (gate stays inline in FindingDetailDrawer).

Recommend A — surfaces the suppressions list at the org level so admins
can audit accepted-risk records without drilling into each finding.

---

## Settings tab visibility — bigger pattern question

`apps/web/src/pages/SettingsPage.tsx` doesn't gate which tabs a user
sees. VIEWER can navigate to Settings → SSO and see the (empty) form,
or to Settings → Audit Log and see "loading…" forever.

Two ways to fix:

1. **Tab-level gating** (recommended) — `SettingsPage` filters its tab
   list by `useRole().can(tab.minRole)`. Tabs the user can't access
   simply don't appear. Contract entry's `ui:` then points at
   `SettingsPage.tsx` + the tab name.
2. **In-tab gating** — each tab's component shows a "you don't have
   permission" state when role is insufficient. More work, weaker UX.

Option 1 is the canonical pattern (it's what TeamTab.tsx already does
for the role dropdown). Roll it out across all settings tabs in this
phase.

---

## Effort estimate

| Slice | Lines | Time |
|---|---|---|
| A — SettingsPage tab-level gating | ~40 | 1h |
| B — Per-page <Can> wrappers (5 files) | ~80 | 2h |
| C — SuppressionsTab.tsx (new) | ~150 | 2h |
| D — Update contract entries + verify parity tests pass | ~30 | 30min |
| **Total** | **~300** | **~5–6h** |

Not the work that closes a procurement deal, but the work that prevents
"I clicked a button and it 403'd" support tickets — and the parity test
makes regressions impossible to slip past code review.
