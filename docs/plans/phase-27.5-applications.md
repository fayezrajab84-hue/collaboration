# Phase 27.5 — Application boundary for correlation

**Status:** ✅ shipped (3 commits)
**Predecessor:** Phase 27 Slices A + B + C (asset graph + correlation engine + attack-path UI)
**Surfaced by:** the Phase 27 end-to-end smoke test, which produced one 202-node mega-chain spanning DVWA + WebGoat + Juice Shop because cveBridge matched on shared base-image CVEs across unrelated apps. The data model needed an Application boundary, not just a bridge-tuning tweak.

---

## What changed

Phase 27 modeled correlation pairwise on assets: `Repository.buildsContainerImages[]`, `Container.deployedAtDomainIds[]`, `Domain.servesContainerIds[]`. The bridge engine then ran across every pair of findings in the org. Because two unrelated containers can legitimately share a base-image CVE, the union-find pass merged them into one chain — hence the 202-node mega-chain.

Phase 27.5 introduces **`Application`** as a first-class entity that owns a Repository / Container / Domain set:

```prisma
model Application {
  id          String   @id @default(cuid())
  orgId       String
  name        String
  slug        String                              // unique per org
  description String?
  environment ApplicationEnv @default(PRODUCTION) // DEV | STAGING | PROD
  criticality Criticality    @default(MEDIUM)     // CRITICAL | HIGH | MEDIUM | LOW
  owner       String?                             // free-text team / contact
  ...
}

// Each existing asset gets an optional FK
Repository.applicationId  String?
Container.applicationId   String?
Domain.applicationId      String?
```

The correlation engine now scopes its sweep **per application** — `runCorrelationForApplication(orgId, applicationId)` loads only the findings on that app's components. Findings on assets with no `applicationId` are explicitly cleared (correlationGroupId set to null) and never participate in any chain.

Result: the DVWA + WebGoat + Juice Shop mega-chain dissolves the moment each becomes its own Application. The cveBridge can't match across boundaries, even when the CVE itself is identical.

---

## Three commits

### Commit 1 — Schema + backend (`ea06356`)

- Application model + ApplicationEnv + Criticality enums
- `Repository.applicationId` / `Container.applicationId` / `Domain.applicationId` (nullable, onDelete: SetNull)
- `applicationService` with `pickSlug()` (auto-derive + uniqueness suffix), `assignComponents()` (atomic bulk membership replacement with cross-org rejection), `loadComponents` / `loadComponentCounts` / `loadFindingCounts` for the list and detail views
- Application routes (`/api/applications`): list (VIEWER+), create / update / delete / assign-components (ADMIN+), `_meta/enums`
- Correlation engine refactor: `runCorrelationForOrg` now dispatches per-application sweeps + clears unassigned findings
- New `runCorrelationForApplication(orgId, applicationId)` entry point
- Findings filter: new `?applicationId=` URL parameter resolves to "any finding whose target asset belongs to this app"
- 4 new ADMIN role-contract entries (create / update / delete / assign-components) + matching docs/rbac.md markers

### Commit 2 — Frontend (`6e7cef1`)

- ApplicationsPage with list + detail views; Components tabs (Repos / Containers / Domains) + Add modal
- ApplicationPickerPanel mounted at the top of every Repository / Container / Domain edit modal (single-select dropdown saves via the bulk components endpoint, which auto-un-assigns from any prior app)
- FindingsPage gains an "Applications" MultiSelect filter as the first filter chip
- Sidebar nav: "Applications" entry between Dashboard and Repositories (Boxes icon)
- Honest UI per `breachlens-ux-patterns.md`: empty state explains *what an Application is and why correlation needs one*; Add-components modal warns when selected asset is already in another app

### Commit 3 — Tests + docs + cleanup

- `applicationService.test.ts` — pure-function tests for `deriveSlug` boundary cases + the validation-error predicate
- Drop the two one-shot migration scripts (`smokeTestPhase27.ts`, `replaceDvwaContainer.ts`) — purpose served, would otherwise pollute the migrations dir
- This scope doc + the next snapshot in `breachlens-competitive-baseline.md`

Total: ~1700 lines net across 3 commits.

---

## Open questions for Phase 27.6+

- **Auto-suggest application from CI metadata.** Operators currently assign manually. A future `Repository.suggestedApplicationId` could be inferred from existing label conventions (e.g. `app=customer-portal` in commit messages, Dockerfile build args, k8s manifest labels). Ship as suggestion only, never auto-apply.
- **Cross-application correlation as a *separate* signal.** Today correlation is strictly within-app. Some operators may want a "cross-app pattern detector" surfaced separately — "App X and App Y share a base image with this CVE." Different surface, different priority — Phase 27.6 candidate.
- **Per-app risk score + per-app compliance dashboard.** Once apps own assets, all the existing roll-up signals (Phase 14 reachability count, Phase 16 compliance summary, AI risk score) can be rolled up per-app. Big leverage for the Application detail page.
- **Force-directed graph on the App detail page.** Phase 27 Slice C deferred this; Phase 27.5 also ships list-based UX. When operators have apps with 20+ components, the graph view becomes more useful — Phase 27.5.x candidate.

---

## Honest caveats

- **Existing assets stay `applicationId = null` until manually assigned.** No auto-migration. Operators see a hint on assignment-modal candidates — these "in another app" warnings are how they learn about it.
- **Performance characteristic shifts.** The bridge sweep is now O(n²) within an *app* instead of within an *org*. Net result: dramatically faster on orgs with many small apps; slightly slower on a single 5000-finding mega-app vs the old org sweep. The cap that matters is per-app finding count, which an operator can control by splitting apps further.
- **Bridges still work the same way.** Phase 27 Slice B's interface didn't change — same 4 plugins, same scoring. Phase 27.5 only narrowed the candidate set per sweep.
- **Slug uniqueness scoped per org.** Two orgs can each have `customer-portal` — that's intentional. Cross-org slug collisions never happen because every query already filters by orgId.
