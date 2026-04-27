# Testing — patterns + how to add tests

The api uses **vitest**. First test files landed alongside the RBAC
middleware (`apps/api/src/middleware/requireRole.test.ts`,
`apps/api/src/services/rbac.test.ts`).

## Running tests

```bash
# In the api container
docker compose exec -T -w //app/apps/api api npx vitest run

# Or via the npm script
docker compose exec -T -w //app/apps/api api pnpm test

# Watch mode (for local dev)
docker compose exec -w //app/apps/api api pnpm test:watch
```

Co-located convention: a test file lives next to the code under test.
`src/middleware/requireRole.ts` → `src/middleware/requireRole.test.ts`.
Vitest discovers `src/**/*.test.ts` automatically (see `vitest.config.ts`).

## Mocking philosophy: prefer dependency injection over `vi.mock`

`vi.mock` works under strict-ESM (`"type": "module"` + NodeNext
resolution) but the hoisting story is fragile — module-cache pollution
between tests is a real risk and the failure modes are subtle.

**The cleaner pattern**: design middleware/services to accept their
dependencies as constructor or factory arguments with sensible
defaults. Tests inject stubs directly; production code is unchanged.

`requireRole` is the canonical example:

```ts
// In production: middleware uses the real resolver via its default
router.delete("/:id", requireRole("ADMIN"), handler);

// In tests: pass a fake resolver as the second arg, no module mocking
await requireRole("ADMIN", async () => ({ orgId: "x", role: "VIEWER" }))(
  req, res, next,
);
```

The signature change is backward-compatible (default param), no caller
needs updating.

If DI isn't viable (e.g. mocking a deeply-imported leaf utility), use
`vi.hoisted` + `vi.mock` together — never bare `vi.mock` under ESM.

## Test helpers (`src/test-helpers.ts`)

Three fixtures shared across tests:

- `mockRequest({ userId, activeOrgId })` — synthetic Express Request
  that mimics the post-auth shape (no real session/passport needed)
- `mockResponse()` — returns `{ res, status, json, redirect }` where
  status/json/redirect are vi spies. Assert with
  `expect(status).toHaveBeenCalledWith(403)`.
- `fixtureMembership(role, orgId?)` — quick membership row builder
- `mockNext()` — vi.fn() with a `.lastError` getter (reads
  `next.mock.calls[0]?.[0]`) — cleaner than digging into mock.calls

> **Don't destructure getters.** Earlier `mockResponse` returned
> `{ get status() { ... } }`. Destructuring `{ status }` evaluates the
> getter once and captures the initial value — subsequent
> `res.status(403)` calls don't propagate. Returning vi spies as plain
> object properties sidesteps the trap entirely.

## What we already cover

- `src/services/rbac.test.ts` — `ROLE_RANK` ordering invariants,
  `roleAtLeast()` boundary cases, `hasAnyRole()` allowlist matching,
  MEMBER ↔ DEVELOPER legacy alias enforcement
- `src/middleware/requireRole.test.ts` — auth boundary (401, 403, error
  propagation) + the **6 × 5 capability matrix** (every actor role
  vs every required-role gate, asserting pass/reject + side effects)

The matrix table in `requireRole.test.ts` is the canonical RBAC
contract encoded as code. If you change `ROLE_RANK` or add a new role
to the enum, update the matrix in one place and every gate decision
gets re-validated.

## Role contract parity tests (UI ↔ API)

`packages/types/src/roleContract.ts` is the single source of truth for
which BreachLens action requires which role. Two parity tests verify
both sides of the codebase agree:

- **`apps/api/src/role-contract.test.ts`** — imports every router,
  walks its Express stack, and finds every handler tagged with
  `__minRole` (set by `requireRole` itself). Asserts each live gate
  has a matching contract entry with the same `minRole`, and every
  contract entry with `.api` is wired up in a real router.
- **`apps/web/src/role-contract.test.ts`** — pure source scan. Reads
  every `.tsx` file, regex-finds `<Can role="X">` wrappers, asserts
  every `<Can role>` value is documented in the contract and every
  contract `.ui` pointer corresponds to a real file with the expected
  wrapper.

Adding a new role-gated action: add a contract entry first, then the
backend `requireRole` and frontend `<Can>` will fail tests until they
match. Pattern is documented inline in `roleContract.ts`.

### Discovered UI gaps

The frontend parity test caught 5 real drift cases on first run:
Settings tabs (Audit Log, SSO, Policies), DomainsPage delete action,
and FindingsPage bulk toolbar all expose ADMIN/SECURITY-only API
endpoints to every role. The contract entries currently have `// ui:
TODO Phase 22.7 …` placeholders so the parity test passes; closing
those gaps is scoped in `docs/plans/phase-22.7-ui-role-gating.md`.

## What we don't cover yet (intentional gaps to plan against)

- **Route-level integration tests** — supertest + the actual Express
  app, hitting each `requireRole(X)`-protected route as each role.
  Catches "forgot to add `requireRole` middleware on the new endpoint"
  regressions. The current backend parity test catches "wrong role" but
  not "wired the wrong path".
- **SSO callback / OIDC flow tests** — needs a fixture IdP (Keycloak
  in docker) or extensive mocking. Phase 22.5 work.
- **End-to-end with real DB** — would need a test postgres instance.
  Defer until a real regression demands it.
- **CI integration** — vitest runs locally, no GitHub Actions yet.

## Adding a new test file

1. Create `src/<module>/<filename>.test.ts` next to the code.
2. Import vitest helpers + the SUT.
3. If the SUT calls into other services, prefer extending its factory
   signature to accept those services as args (with real defaults) —
   then pass fakes from tests.
4. Run `pnpm test` from the api container.
5. CI will run on every push once GitHub Actions is wired (TBD).
