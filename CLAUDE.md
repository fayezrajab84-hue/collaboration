# BreachLens — Claude Operating Notes

Self-hosted DevSecOps platform that orchestrates open-source security
scanners across GitHub repos, container images, and domains.

> **Scope of this file:** the things that bit us in past sessions and
> aren't obvious from the code. If a fact is enforced by the type system
> or visible in five seconds of grepping, it doesn't belong here.

---

## Project at a glance

```
apps/
  api/           Express + Prisma + BullMQ (TypeScript, Node 20)
  web/           Vite + React + Tailwind + shadcn/ui (TypeScript)
  scanner/       FastAPI + 7 scanners (Python 3.12)
packages/
  types/         Shared TS types — consumed as source, no build step
docker/          Dockerfiles + entrypoints
docker-compose.yml + docker-compose.override.yml (auto-merged in dev)
```

The platform's product name is **BreachLens**. Use that in user-facing
copy; "DevSecOps" stays for technical/internal naming.

---

## Docker workflow

### Image layering (the part that breaks first-time changes)

```
devsecops-scanner:latest         (base — bakes apps/scanner/ via COPY)
   └─ devsecops-scanner-pentest:latest  (extends base; adds nikto/sqlmap/xsstrike/dalfox)
```

**Neither image has a source bind mount in dev.** Both `COPY apps/scanner/ .`
into the image. That means:

- Editing `apps/scanner/**/*.py` does **not** affect running containers
  until you rebuild.
- `docker compose exec scanner python ...` runs against the *baked* source
  inside the container, not your host edits — useful for testing what's
  *deployed*, useless for validating what you *just wrote*.
- `scanner-pentest` extends `scanner`, so any source change requires
  **both** rebuilds in order:

  ```bash
  docker compose build scanner
  docker compose --profile pentest build scanner-pentest
  ```

  See `/scanner-rebuild` for a one-shot.

  **`build` is not `restart`.** Rebuilding the image creates a *new* image
  tag but leaves any *running container* untouched, still bound to the
  prior image ID. After `docker compose build scanner` always run

  ```bash
  docker compose --profile pentest up -d --force-recreate scanner-pentest
  ```

  to swap the live container onto the new image. We hit this in a session
  where a Round-2 parser fix didn't take effect — the rebuild succeeded
  but the running container kept emitting Round-1 log lines until forced
  to recreate. `/scanner-rebuild` does both steps; if you build manually,
  remember the second.

The `api` and `web` services *do* have bind mounts (see
`docker-compose.override.yml`), so TypeScript hot-reloads via `tsx watch`.

### Git-Bash path mangling

`docker compose exec` with an absolute path like `/app/apps/api` gets
mangled to `C:/Program Files/Git/app/apps/api` on Windows Git Bash.
Workaround:

```bash
docker compose exec -T -w //app/apps/api api node --import tsx src/migrations/triggerTestScan.ts
```

The `//app/...` prefix (note the double slash) prevents the rewrite, and
`-w` sets the working directory so the rest of the command can use
relative paths.

### Network names

Compose creates two networks: `admiring-hertz_internal` (services + DB)
and `admiring-hertz_public` (web egress). Ad-hoc one-shot containers
that need to reach `dvwa`, `api`, `postgres`, etc. must join `_internal`:

```bash
docker run --rm --network admiring-hertz_internal --entrypoint python \
  devsecops-scanner-pentest:latest -c "import httpx; print(httpx.get('http://dvwa').status_code)"
```

`admiring-hertz` is the directory name of the worktree — substitute if
you're working from a different worktree.

---

## Database access

```bash
docker compose exec -T postgres psql -U devsecops -d devsecops -c "<query>"
```

### Schema gotchas (real ones, not "look it up")

- **`ScanJob.scanTypes`** is a `String[]` array (Postgres `text[]`), not
  scalar `scanType`. Filter with `'PENTEST_FULL' = ANY("scanTypes")`.
- **`pentestDepth`** lives on `Domain`, not `ScanJob`. To run Phase 4
  (exploit), set `Domain.pentestDepth = 'AGGRESSIVE'`.
- **`Domain.authConfig`** is a *relation* through the `DomainAuthConfig`
  table. There is **no** `authConfigId` column on `Domain` — query via
  `JOIN "DomainAuthConfig" ac ON ac."domainId" = d.id` or use Prisma's
  `include: { authConfig: true }`.
- **`OrganizationMember` has no timestamps** — `(userId, orgId, role)` is
  the entire row. Don't write `orderBy: { createdAt: ... }` against it
  (Prisma will throw at runtime). Use `org: { createdAt: "asc" }` if you
  need a tiebreaker.
- **`OrgType` enum is `{ PERSONAL, TEAM }`** (not `SHARED` — easy to
  guess wrong). PERSONAL is the auto-created sandbox at first login;
  TEAM is set when an invitation is created (`routes/members/router.ts`).
- **Quoting:** Postgres folds unquoted identifiers to lowercase. Prisma
  models use camelCase, so every column with a capital letter needs
  double quotes: `SELECT "scanTypes" FROM "ScanJob"` — *not*
  `SELECT scanTypes FROM ScanJob`.

### `db push` does not survive a postgres recreate

Schema changes pushed via `prisma db push` (no migration file) live only
in the running database. When the postgres container gets recreated
(`docker compose up -d` after a long absence is the most common
trigger), the `migrate` service re-runs only what's in
`apps/api/prisma/migrations/` — anything that was `db push`-only is
gone.

This bit us this session: `SsoConfig`, `Sbom`, `SbomSigningKey`, and
`Invitation` tables disappeared after a routine `up -d`, and every
`/auth/sso/initiate` started failing with "table does not exist". The
fix is the docker-cp + prisma dance below; long-term, generate proper
migration files so the `migrate` service handles it on its own.

```bash
docker compose cp apps/api/prisma api:/app/apps/api/
docker compose exec -T -w //app/apps/api api npx prisma db push --skip-generate --accept-data-loss
docker compose exec -T -w //app/apps/api api npx prisma generate
docker compose restart api
```

`/db-push` automates this.

### Useful one-liners

```bash
# Most recent scan jobs
docker compose exec -T postgres psql -U devsecops -d devsecops -c \
  'SELECT id, status, "scanTypes", "createdAt" FROM "ScanJob" ORDER BY "createdAt" DESC LIMIT 10;'

# Findings for a scan job, grouped
docker compose exec -T postgres psql -U devsecops -d devsecops -c \
  "SELECT severity, confidence, scanner, COUNT(*) FROM \"Finding\" WHERE \"scanJobId\"='<id>' GROUP BY severity, confidence, scanner;"

# Latest recording for a domain
docker compose exec -T postgres psql -U devsecops -d devsecops -c \
  "SELECT id, status, \"urlCount\", \"zapContextName\" FROM \"RecordingSession\" WHERE \"domainId\"='<id>' ORDER BY \"startedAt\" DESC LIMIT 1;"
```

---

## Multi-tenant data scoping

Every list endpoint scopes queries by `orgId`. The mechanism that turns
"who is logged in?" into "which org are they looking at?" is
`apps/api/src/services/activeOrgService.ts`:

```ts
const member = await getActiveMembership(req);
if (!member) { res.json([]); return; }
// member.orgId is what scopes the query
```

Resolution order:

1. `req.session.activeOrgId` — set by `POST /auth/org/switch` when the
   user picks an org in the sidebar dropdown
2. Deterministic fallback — TEAM orgs over PERSONAL, then oldest
   `org.createdAt` first

**Don't write the lookup ad-hoc.** The pre-refactor pattern
`prisma.organizationMember.findFirst({ where: { userId: user.id } })`
returned a non-deterministic membership and silently dumped users with
multiple orgs into the wrong sandbox (the empty PERSONAL one usually
won the race because Postgres returned it first physically). 74 sites
across 11 files used the bad pattern before the refactor — if a new
route handler needs the user's org, use `getActiveMembership(req)`.

### PERSONAL → TEAM auto-promotion

`POST /api/members/invitations` flips the org's type from PERSONAL to
TEAM the moment an invitation is created. Without this, the
type-based ordering in `getActiveMembership` would never fire (every
auto-personal-org is born PERSONAL). If you write a new "add a member
to an org" path, mirror the `prisma.organization.updateMany({ where:
{ id: orgId, type: "PERSONAL" }, data: { type: "TEAM" } })` call.

---

## Auth & SSO

### Rate limiter scope (the wall everyone hits at request 11)

`apps/api/src/app.ts` defines two limiters:

- **`authLimiter`** — 10 req per 15 min. Applied to **only** the
  IdP-handshake routes: `/auth/github`, `/auth/sso/initiate`,
  `/auth/sso/callback`. These make outbound calls to GitHub /
  Microsoft / Okta and are unauthenticated entry points — the actual
  abuse vector.
- **`apiLimiter`** — 300 req per min. Applied to `/auth` (the rest of
  the router) and every `/api/*` route. `/auth/me` runs on every page
  load + every TanStack Query refetch + every navigation, so it MUST be
  on the loose limiter; the strict one walls users off after ~10
  navigations as `{"error":"Too many auth requests"}`.

If you add a new `/auth/*` route, decide which bucket it belongs to
**before** mounting it — the wrong choice silently breaks the app for
real users with no obvious server-side error.

### OIDC scope: send `openid` only

`apps/api/src/auth/oidcService.ts:buildAuthorizationUrl` deliberately
sends just `scope: "openid"`. Reasoning:

- **Entra rejects unknown scopes hard** — it does *not* silently drop
  them like Okta / Keycloak / Auth0. Sending `groups` causes "scope
  doesn't exist on resource" with no useful diagnostic.
- The OIDC standard scopes (`email`, `profile`) and Graph permissions
  (`User.Read`) should be driven by the IdP-side app registration
  (Entra: API permissions + Token Configuration → Optional Claims).
  Don't request them from our side — let the operator's Entra config
  decide what the userinfo endpoint returns.

### Entra-specific quirks worth knowing

- **`/userinfo` returns the photo as a Graph URL** —
  `https://graph.microsoft.com/v1.0/me/photo/$value`. That endpoint
  needs a Bearer access token; `<img src>` requests it anonymously and
  gets 401'd. `oidcService.extractPicture()` filters out
  `graph.microsoft.com` hosts so the existing initials-fallback chip
  renders instead of a broken image icon.
- **`login_hint` skips the username step.** The email the user typed
  on `/login` is threaded through to the IdP authorization URL as
  `login_hint`, which Entra honours by either pre-filling the username
  field or — under Conditional Access / passwordless — skipping it
  entirely.
- **`_claim_names` overage** — Entra returns `>150` groups via a
  `_claim_names` indirection rather than inline. We can't resolve it
  without a Graph call, so we surface a `[sso] groups overage` warn
  and fall back to `defaultRole`. Operator fix: app registration →
  Token configuration → Optional claims → `groups` → `sam_account_name`.

### Diagnostic logging on `invalid_callback`

The SSO callback handler silently redirects to
`/login?error=invalid_callback` when `code` / `state` are missing.
That's also the path Entra/Okta hit when *they* return
`?error=invalid_client / unauthorized_client / invalid_redirect_uri /
consent_required` — all real misconfigurations. The handler now
`logger.warn`s the full query so the next broken app registration
shows up in `docker compose logs api` instead of being invisible.

### Network reachability surprises

- `login.microsoftonline.com` **is** reachable from a real Chrome /
  Firefox tab on this dev box. Earlier dev-environment notes assumed
  it was DNS-blocked — that's wrong; the only real block is `github.com`
  for `git push`.
- The Claude Preview iframe still blocks top-level navigation to
  external auth endpoints. Test SSO in a real browser tab against
  `http://localhost:5173`, not in Preview.

### RBAC — 5-role hierarchy (OWNER > ADMIN > SECURITY > DEVELOPER > VIEWER)

ADMIN handles almost all elevation gates; OWNER differs only in
last-owner protection (org can't be demoted to zero OWNERs).
SECURITY gates risk-acceptance + bulk finding ops. DEVELOPER is
UI-gated only (the API accepts any authenticated user for scan-trigger
operations — layered defense). MEMBER is a legacy alias for DEVELOPER.

**Full reference:** [`docs/rbac.md`](./docs/rbac.md) — 5-role table,
per-route capability matrix (every `requireRole(X)` site), how to pick
the right gate for a new route, OWNER special-case rationale.

`apps/api/src/services/rbac.ts` is the canonical source; both backend
middleware (`requireRole`) and frontend (`<Can role="X">`) flow through
the same rank map.

---

## Pentest pipeline (`apps/scanner/scanners/pentest_full/`)

Phases (see `orchestrator.py`):

| # | Phase | Tools | Time |
|---|-------|-------|------|
| 0.5 | Crawler | Playwright OR recorded ZAP context | 30-60s |
| 1 | Recon | subfinder + httpx | <1s for one domain |
| 2 | Discovery | nmap + ffuf | 5-10s |
| 3 | Vuln | nuclei + nikto + testssl | **~25 min** (1500s nuclei wall clock) |
| 3.5 | Targeted | per-host probes | 1-5s |
| 4 | Exploit | sqlmap + xsstrike + dalfox | 10-25 min |

### Phase 4 only runs when `Domain.pentestDepth == 'AGGRESSIVE'`

Other depths skip Phase 4 entirely. To verify a depth setting:

```bash
docker compose exec -T postgres psql -U devsecops -d devsecops -c \
  "SELECT domain, \"pentestDepth\" FROM \"Domain\" WHERE id='<id>';"
```

### Phase 4 needs parameterised URLs to find anything

- xsstrike has no form-submission crawler — bare hosts produce
  `[-] No parameters to test.` and exit. We iterate the
  recorded URL list filtered to `?key=value` and run xsstrike per URL.
- Cookie freshness matters: PHPSESSID-style cookies expire during the
  ~25min nuclei phase. `exploit.py` re-authenticates at the start of
  Phase 4; if your tool produces zero findings, check the log for
  `[exploit] refreshed session cookie` — its absence means re-auth
  silently failed.
- For recordings to reach Phase 4, the trigger must pass
  `recordingContextId` + `recordingContextName` (see
  `triggerTestScan.ts` for the canonical wiring).

### Confidence levels

`POSSIBLE` < `LIKELY` < `CONFIRMED`. Only `CONFIRMED` qualifies for the
BreachLens **"Proof of Exploit"** badge in the UI; the badge requires
non-null `evidence.url` and `evidence.attack` (and ideally
`evidence.curl_command` so the user can reproduce).

### Phase 4 URL budget

`exploit.py` caps the per-target URL list:

- `EXPLOIT_URL_CAP = 30` — total URLs fed to sqlmap + dalfox per target
- `XSSTRIKE_PER_TARGET_CAP = 8` — xsstrike is run once per URL (slow), so
  it gets a tighter cap

The 30-URL cap means if your recording captured 100 URLs and the
parameterised XSS endpoint is the 31st by sort order, Phase 4 will
silently miss it. `_load_recorded_urls` puts parameterised URLs first,
which usually keeps the vuln endpoints in scope, but spot-check by:

```bash
docker compose --profile pentest exec -T scanner-pentest \
  grep -E 'xss|sqli' /tmp/scan_workspace/<workspace-id>/crawler_urls.txt
```

If the targets you care about aren't there, the recording didn't visit
them — re-record with the user clicking through those endpoints.

### Reading dalfox "(missing)" log lines

```
[exploit][dalfox] dvwa: parsed 1 item(s) by type={'(missing)': 1}
[exploit][dalfox] dvwa: dropped 1 unverified + 0 empty entr(ies); kept 0
```

This is **not** a parser bug. Dalfox always emits a trailing `{}` empty
object as a JSON terminator. When dalfox finds zero verified XSS, the
output is just `[{}]` — one object with no `type` field, which our
parser reports as `(missing)` and then correctly drops as
non-verified. It's a true negative; check the URL list before suspecting
the parser.

### xsstrike output is colourised — always strip ANSI before parsing

xsstrike has no `--no-color` flag. Its raw output is
`\x1b[92m[+]\x1b[0m Payload:` — naive `\[\+\]\s*Payload:` regexes never
match because the ANSI reset code sits between `[+]` and `Payload:`.
`exploit.py` has a module-level `_strip_ansi` helper; use it.

In **scanner mode** (which `--skip` triggers), xsstrike emits a tight
three-line block per payload tested:

```
[+] Payload: <payload>
[!] Efficiency: <0-100>
[!] Confidence: <0-10>
```

The `[+] Vulnerable webpage:` / `[+] Vector for:` lines from
*checker* mode never appear — don't gate findings on them.

---

## Triggering a test scan

`apps/api/src/migrations/triggerTestScan.ts` is **not** a Prisma migration
despite the directory. It's the canonical "kick off a real scan from
a script" helper. Run it via:

```bash
docker compose exec -T -w //app/apps/api api node --import tsx src/migrations/triggerTestScan.ts
```

(See `/trigger-pentest` slash command.)

For one-off in-container scanner experiments without going through the
queue, use a one-shot container on the internal network:

```bash
docker run --rm --network admiring-hertz_internal --entrypoint python \
  devsecops-scanner-pentest:latest -c "<your test code>"
```

`ScanRequest` (Pydantic) requires both `org_id` and `target_id` AND
`scan_job_id` — easy to forget the last one.

---

## Things that look like bugs but aren't

- **`scanner-pentest` log shows ZAP "Empty reply from server"** — ZAP
  requires `apikey` query param when `api.disablekey` isn't set. Look
  for the key in the API container's env.
- **`compose --profile pentest` is required for scanner-pentest commands**
  — the service is in the `pentest` profile so it doesn't start by
  default.
- **`tsx watch` SIGKILLs ~5s after SIGTERM** — that's why
  `server.ts` has a 8s race-timeout in shutdown. Worker locks in Redis
  may briefly look stalled after dev restarts; the orphan-reaper at
  startup handles it.

---

## Frequently useful slash commands

- `/scanner-rebuild` — rebuild base + pentest images in correct order
- `/trigger-pentest` — kick off a fresh AGGRESSIVE PENTEST_FULL with the
  latest recording context for the dvwa target
- `/scan-status <scanJobId>` — DB row + finding counts + recent log lines
- `/finding-evidence <findingId>` — pretty-print evidence + raw_output
- `/db-push` — sync the prisma schema into the running api container
  (the docker-cp + db push + generate + restart dance) — needed every
  time the postgres container gets recreated and `db push`-only tables
  get dropped

See `.claude/commands/*.md` for the prompt sources.
