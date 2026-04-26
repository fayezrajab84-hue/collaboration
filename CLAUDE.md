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
- **Quoting:** Postgres folds unquoted identifiers to lowercase. Prisma
  models use camelCase, so every column with a capital letter needs
  double quotes: `SELECT "scanTypes" FROM "ScanJob"` — *not*
  `SELECT scanTypes FROM ScanJob`.

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

See `.claude/commands/*.md` for the prompt sources.
