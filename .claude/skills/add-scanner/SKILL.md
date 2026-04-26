---
name: add-scanner
description: Walk through adding a new security scanner to BreachLens — the cross-cutting touch points across the Python scanner service, Prisma schema, BullMQ queues, shared types, and the React UI. Use when the user wants to integrate a new tool (Snyk, Bandit, Gitleaks, Grype, Wapiti, etc.), wire up a new SAST/SCA/DAST/IaC/Container/Pentest scanner, or asks "how do I add a scanner". Skip this skill if the request is to add a new tool *inside* an existing scanner phase (e.g., adding a payload tool to PENTEST_FULL Phase 4) — that's a smaller change scoped to one file.
---

# Adding a new scanner to BreachLens

Adding a scanner is **not a one-file change**. The wrong addition compiles
clean, deploys clean, and silently does nothing — typically because one
of the four-way `ScanType` definitions wasn't kept in sync, or the
container wasn't recreated after the image rebuild. Walk this checklist
top-to-bottom; every item exists because skipping it has bitten us before.

---

## 0 — Decisions to make BEFORE writing code

Ask the user:

1. **Is this a new `ScanType`, or a new tool inside an existing phase?**
   Example of "inside an existing phase": adding `wpscan` to PENTEST_FULL
   Phase 3. That's an edit to `apps/scanner/scanners/pentest_full/vuln.py`,
   not a full new scanner. Stop here, suggest the smaller change instead.
2. **What target type?** REPOSITORY, CONTAINER, or DOMAIN. Each routes
   through a different worker code path and has different payload shape.
3. **Does it need a new CLI binary inside the scanner image?** If yes,
   you also touch the Dockerfile and pay a rebuild cost on every dev
   restart until the layer caches.
4. **Does its output fit the existing `NormalizedFinding` shape?** Most
   tools do. If it produces a metadata field that doesn't (e.g., a
   chain-of-evidence list), that's a `Finding` schema migration on top of
   the scanner work — flag it explicitly so the user knows the scope is
   bigger than they probably think.

If any of these are unclear, surface them before starting. Don't guess.

---

## 1 — `ScanType` enum (FOUR places, must stay in sync)

The same `ScanType` value lives in four places and TypeScript only
catches divergence between #3 and #4. Adding to one and forgetting the
others fails at runtime.

| # | File | Format |
|---|---|---|
| 1 | `apps/scanner/models.py` (~line 12) | Python `Enum`: `MYTOOL = "MYTOOL"` |
| 2 | `apps/api/prisma/schema.prisma` (~line 30) | Prisma enum value: `MYTOOL` |
| 3 | `packages/types/src/enums.ts` (line 1) | TS union literal: `\| "MYTOOL"` |
| 4 | `apps/api/src/queues/definitions.ts:scanQueues` (~line 79) | New `Queue` entry: `MYTOOL: new Queue("scan-MYTOOL", QUEUE_OPTS)` |

After editing #2:

```bash
docker compose exec -T -w //app/apps/api api pnpm prisma migrate dev --name add_mytool_scan_type
```

After editing #4: TS will start failing to compile until #1, #3, and the
worker dispatch (next step) are added.

---

## 2 — Worker dispatch & timeout

`apps/api/src/workers/scanWorker.ts`:

- Add `MYTOOL` to the `SCAN_TYPES` array (~line 23). This drives worker
  registration via `initWorkers()`.
- Add a per-scan-type axios timeout case (~line 171) **only if the new
  scanner can run longer than 30 minutes**. The default is 30 min;
  PENTEST_FULL is 2 h, DAST is 1 h. Underestimating here causes a
  `socket hangup` at axios with no diagnostic in the scanner logs — the
  scan looks "stuck" until the timeout fires.

The worker will then automatically pick up jobs from the new queue. No
other wiring needed in the API layer.

---

## 3 — Python scanner class

Create `apps/scanner/scanners/mytool.py`:

```python
from models import NormalizedFinding, ScanRequest, ScanType, Severity
from .base import BaseScanner

class MyToolScanner(BaseScanner):
    def scan(self, request: ScanRequest, workspace: str) -> list[NormalizedFinding]:
        # 1. Use self.clone_repo() / self.run_cmd() — base helpers handle
        #    secret-safe subprocess + cache-aware git clone.
        # 2. Build NormalizedFinding objects with self.compute_fingerprint(...)
        #    — fingerprint MUST be deterministic across re-scans, otherwise
        #    findings duplicate instead of upserting.
        # 3. Return list[NormalizedFinding]. Do NOT raise on tool failure;
        #    return [] and let scan_type-level error reporting surface it.
        return []
```

Then wire it in **two** places:

- `apps/scanner/scanners/__init__.py`: add the import + `__all__` entry.
  Forgetting this is a silent ImportError swallowed by FastAPI startup
  — the scanner just won't be registered.
- `apps/scanner/main.py:SCANNER_MAP` (~line 50): map
  `ScanType.MYTOOL: MyToolScanner`.

**Fingerprint contract:** `BaseScanner.compute_fingerprint()` already
exists. Inputs are `(orgId, targetId, scanType, ruleId, filePath, line)`.
Re-using that helper keeps the dedup behaviour in step with the other
scanners — never invent your own fingerprint scheme.

---

## 4 — Image layering & container recreation

If the scanner needs a new CLI binary, edit `docker/scanner.Dockerfile`
(NOT `scanner-pentest.Dockerfile` unless this is a pentest-only tool).
Pin the version explicitly.

Then **always do all three** (this is the gotcha that wastes the most
time):

```bash
docker compose build scanner
docker compose --profile pentest build scanner-pentest    # if pentest stack also affected
docker compose --profile pentest up -d --force-recreate scanner-pentest
docker compose up -d --force-recreate scanner             # if you only changed base
```

**Build is not restart.** A successful image build leaves the running
container bound to the previous image ID; the new code is not in memory
until the container is recreated. The `/scanner-rebuild` slash command
does both base + pentest in the right order.

Verify the recreate took:

```bash
docker inspect --format '{{.Image}}' admiring-hertz-scanner-1
docker images --no-trunc --quiet devsecops-scanner:latest
# These two SHAs MUST match.
```

---

## 5 — Frontend (light touch, but don't skip)

The UI auto-renders most things off the shared `ScanType` union, but
three places need explicit additions or the new scanner shows up as
"unknown / blank chip":

- `apps/web/src/lib/colors.ts` — colour + icon mapping for the new type.
- `apps/web/src/pages/FindingsPage.tsx` — filter chip in the scan-type
  dropdown.
- `apps/web/src/pages/DashboardPage.tsx` — stats card / breakdown if the
  dashboard partitions by scan type.

Search for an existing `ScanType` (e.g., `"SAST"`) across `apps/web/src/`
and add the new value alongside every literal you find. There's no
`SCAN_TYPE_LABELS` central registry, so this is grep-driven.

---

## 6 — Smoke test before merging

Don't trust unit tests for this — the failure modes are
integration-shaped. Use the existing trigger pattern:

```bash
# Edit apps/api/src/migrations/triggerTestScan.ts to use scanTypes: ["MYTOOL"]
docker compose exec -T -w //app/apps/api api node --import tsx src/migrations/triggerTestScan.ts
```

Or use `/trigger-pentest` if MYTOOL replaces a phase the existing
trigger already covers.

Minimum acceptance signal:

1. Job moves PENDING → RUNNING → COMPLETED in the DB
2. At least one row in `Finding` for the test target has
   `scanner='mytool'`
3. Re-running the trigger upserts (same row, `lastSeen` advances) rather
   than inserting duplicates — proves fingerprint is deterministic
4. UI Findings page filter chip shows the new type and clicking it
   filters correctly

If any of these fail, do NOT merge; the scanner will silently do nothing
in production.

---

## Common failure modes (in descending frequency)

1. **Forgot to recreate the container after image build.** Container
   keeps running old code. (Step 4.)
2. **`__init__.py` not updated.** `SCANNER_MAP` import in `main.py`
   fails silently at FastAPI startup; scanner type returns 400 "Unknown
   scan type".
3. **`scanQueues` entry missing.** Worker never registers for the queue;
   jobs sit PENDING forever. Watch for this if the job never transitions
   from PENDING.
4. **Per-scan-type axios timeout not set.** Scans that exceed 30 min die
   at the API layer with `socket hangup`; scanner logs look fine.
5. **Non-deterministic fingerprint.** Re-scans produce duplicate
   findings instead of upserting. Catch this in step 6.3.
6. **ScanType missing from `packages/types/src/enums.ts`.** API+web
   builds fail; this one TS will catch.

---

## When NOT to use this skill

- **Adding a tool inside an existing scanner.** E.g., adding `wapiti` to
  PENTEST_FULL Phase 3, or a new payload generator to Phase 4 exploit.
  These are one-file edits in `apps/scanner/scanners/pentest_full/`.
- **Adding a new finding metadata field.** That's a `Finding` schema
  migration + `NormalizedFinding` shape change + UI rendering — different
  shape of work; it's a Finding-shape change, not a scanner-add.
- **Wrapping an existing scanner's output differently.** Belongs in
  `findingService.ts` or the scanner's own normalization, not a new
  scanner.
