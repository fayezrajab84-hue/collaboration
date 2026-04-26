---
name: auth-and-recording
description: Reference + diagnostic guide for BreachLens's authenticated-scan and DAST-recording subsystem — DomainAuthConfig credentials, the session-cookie refresh contract, ZAP context lifecycle, the "Promote to Full Pentest" flow, CSRF tracking, and the idle sweeper. Use when the user is touching authenticated DAST/PENTEST scans, working with FORM/HEADER/COOKIE/OAUTH2 credentials, debugging why a scan ran unauthenticated, modifying the recording flow, or asking about ZAP context lifecycle. Skip for unrelated auth (GitHub OAuth login, session middleware) — that's app-level auth, not scan auth.
---

# Auth & DAST recording

This subsystem wires user-supplied credentials into ZAP / Nuclei / sqlmap
/ xsstrike / dalfox so they can reach authenticated endpoints. It's the
gnarliest area of the codebase because it spans:

- **API**: encrypted credential storage, recording orchestration, scan dispatch
- **Scanner**: cookie acquisition, CSRF re-injection, session refresh mid-scan
- **ZAP**: stateful context that lives in shared memory, single per org
- **Time**: cookies expire mid-scan; idle recordings auto-stop; ZAP can
  briefly return zero counts under load

Walk this skill before editing any of the files listed below — the
"obviously safe" change here usually breaks two other things.

---

## 1 — Schema map

### `DomainAuthConfig` (apps/api/prisma/schema.prisma:331)

One per Domain. Stores public-ish form selectors as plain columns;
secrets in `encryptedCreds` (AES-256-GCM JSON blob, encrypted via
`apps/api/src/services/encryptionService.ts`).

| AuthType | Required plain columns | `encryptedCreds` JSON shape |
|---|---|---|
| `FORM`   | `loginUrl`, `usernameField`, `passwordField`, `loggedInPattern` | `{ username, password }` |
| `HEADER` | `headerName` (e.g. "Authorization") | `{ headerValue }` (e.g. `"Bearer eyJ..."`) |
| `COOKIE` | (none) | `{ cookieValue }` (e.g. `"PHPSESSID=...; security=low"`) |
| `OAUTH2` | `oauth2TokenUrl`, `oauth2ClientId`, `oauth2GrantType` | `{ clientSecret, username?, password? }` |

CSRF tracking columns are **orthogonal to authType** — works standalone
or layered on FORM/HEADER/OAUTH2:

- `csrfMetaSelector` — CSS selector for meta tag with token in `content`
  attr (Rails / Laravel / .NET pattern)
- `csrfCookieName` — cookie name for double-submit (Django / Express
  csurf / Angular pattern)
- `csrfHeaderName` — defaults to `X-CSRF-Token`; override per-app

### `RecordingSession` (apps/api/prisma/schema.prisma:302)

One per recording attempt. Lives in `RecordingStatus` enum:

```
ACTIVE     → user is browsing through the proxy now
SCANNING   → interactive DAST scan kicked off (recording implicitly stopped)
COMPLETED  → interactive scan finished
FAILED     → interactive scan errored
STOPPED    → user clicked stop OR idle sweeper auto-stopped
```

`zapContextId` + `zapContextName` are the two handles into ZAP's
in-memory state. `urlCount` and `alertCount` are last-polled snapshots —
authoritative number lives in ZAP. `scanJobId` (interactive replay)
and `promotedScanJobId` (Full Pentest) are tracked separately so a
session can host both.

---

## 2 — Recording lifecycle (apps/api/src/services/recordingService.ts)

```
start(orgId, domainId, userId)
  ├─ refuse if any ACTIVE/SCANNING session exists for this org (RECORDING_BUSY)
  ├─ POST scanner /dast/recording/start → creates ZAP context
  └─ insert RecordingSession status=ACTIVE

status(orgId, domainId)               (called by UI poll, every few sec)
  └─ POST scanner /dast/recording/stats → updates urlCount/alertCount/lastActivityAt

runScan(orgId, domainId)              (interactive DAST replay)
  └─ triggerScan({ scanTypes: ["DAST"], recordingContext* })
     └─ flips session.status → SCANNING

promote(orgId, domainId, depth)       (Promote to Full Pentest)
  ├─ refuse if urlCount = 0 (EMPTY_RECORDING — don't burn 25 min on nothing)
  ├─ triggerScan({ scanTypes: ["PENTEST_FULL"], recordingContext* })
  └─ session.status STAYS ACTIVE (user can keep recording while pentest runs)
     session.promotedScanJobId = result.scanJobId

stop(orgId, domainId)
  └─ POST scanner /dast/recording/stop → ZAP context removed, status=STOPPED

[idle sweeper]                       (server.ts boot + every 5 min)
  └─ ACTIVE sessions older than 60 min idle OR 4 hr hard cap → auto-STOPPED
     (never SCANNING — let active scans finish)
```

**Single-session lock per org**: ZAP is a shared singleton. Concurrent
sessions would interleave proxy traffic into each other's contexts.
`start()` enforces this; if the user complains "I can't start a new
recording", check for stuck ACTIVE/SCANNING rows from a prior crash.

**Counter monotonicity guard** (status() ~line 140): ZAP's
`core/view/urls/` and `numberOfAlerts` can briefly return empty under
load. The code treats `>0 → 0` as a read error and falls back to
persisted values. Don't "simplify" this — it eliminates a flapping UI bug.

---

## 3 — Promotion plumbing — what actually triggers Phase 0.5 to use the recording

For a scan to consume the recorded URLs (rather than run an unauth
Playwright crawl that finds nothing), the trigger payload **must**
include all four:

```ts
{
  recordingContextId,       // ZAP-assigned numeric id
  recordingContextName,     // human-readable name
  recordingTargetUrl,       // baseurl ZAP filters on
  recordingSessionId,       // for tracking back to session row
}
```

`scanWorker.ts` line ~132 forwards these to the scanner as
`recording_context_name` and `recording_target_url`. The scanner's
`pentest_full/orchestrator.py` Phase 0.5 checks
`request.recording_context_name` — if set, it pulls URLs from ZAP via
`/JSON/core/view/urls/?baseurl=...` and skips Playwright entirely. If
ANY of the four is missing, the scanner silently falls back to the
unauth crawl — which is the #1 cause of "we have a recording but the
scan still found nothing on /vulnerabilities/...".

Reference wiring: `apps/api/src/migrations/triggerTestScan.ts` is the
canonical example — copy from there when scripting test scans.

---

## 4 — Cookie-acquisition contract (apps/scanner/scanners/base.py:198)

`BaseScanner.obtain_session(auth, base_url)` is the **only** function
that mints a session cookie from a `DomainAuthConfig`. Branches by
authType:

- **FORM**: GET login URL → regex hidden inputs (CSRF tokens like
  `user_token`, `_token`) and submit buttons → POST creds + extracted
  fields → verify `loggedInPattern` in response body OR home page →
  return full cookie jar as `"k1=v1; k2=v2"` string.
- **HEADER**: returns `None` — caller uses `auth_header_dict()` instead.
- **COOKIE**: returns `header_value` directly (the user pre-supplied a
  whole cookie string).
- **OAUTH2**: not handled here — `auth_header_dict()` calls
  `obtain_oauth2_token()` lazily.

`auth_header_dict(auth, session_cookie)` priority order:

1. `session_cookie` (already obtained) → `{"Cookie": session_cookie}`
2. `HEADER` type → `{header_name: header_value}`
3. `OAUTH2` type → exchanges credentials, returns `{"Authorization": "Bearer ..."}`
4. Empty dict (unauthenticated)

**Never log credentials.** `obtain_session` errors print only the
exception type/message; never the body, never the headers, never the
extracted form fields (some apps put creds back into hidden inputs on
re-render).

---

## 5 — The Phase-4 cookie-refresh dance

Phase 3 (nuclei) runs ~25 minutes. PHPSESSID, JSESSIONID, and similar
session cookies typically expire in that window. Without refresh, all
three Phase 4 tools (sqlmap, xsstrike, dalfox) silently hit the login
page instead of the vuln endpoint and return zero findings.

`exploit.py` calls `obtain_session()` at the start of Phase 4 (look for
`refreshed session cookie` in the log). If that log line is absent, the
refresh failed silently — usually:

- `loginUrl` is wrong (404 or redirect loop)
- form selectors don't match the current login page HTML
- `loggedInPattern` doesn't match — `obtain_session` returns the cookies
  anyway with a `WARNING: pattern not found` log line, but those cookies
  may be unauthenticated session-init cookies, not real auth

When auth bugs surface, this log line is the first thing to grep for.

---

## 6 — Diagnostic flow — "auth isn't working"

Walk in order; each step rules out a class of bug.

### 6.1 — Is the DomainAuthConfig actually attached to the scan?

```bash
docker compose exec -T postgres psql -U devsecops -d devsecops -c \
  "SELECT d.id, d.domain, ac.id AS auth_id, ac.\"authType\", ac.\"loginUrl\" \
   FROM \"Domain\" d LEFT JOIN \"DomainAuthConfig\" ac ON ac.\"domainId\" = d.id \
   WHERE d.id = (SELECT \"targetId\" FROM \"ScanJob\" WHERE id='<JOB>');"
```

`auth_id = NULL` means no auth config exists — the scan ran unauth.
Tell the user to set up auth via the Domain settings UI.

### 6.2 — Did the worker pass the auth config to the scanner?

`scanWorker.ts` line ~56 builds the `authConfig` object from the
decrypted blob. If `payload.domainAuthConfigId` is missing on the
BullMQ job, the worker skips the whole block. Check the trigger code
(probably the API route) is reading `domain.authConfig?.id` and passing
it through.

### 6.3 — Did `obtain_session` succeed at start of Phase 4?

```bash
docker compose --profile pentest logs --since 2h scanner-pentest 2>&1 \
  | grep "<JOB>" -A 200 | grep -E "exploit.*refreshed session cookie|obtain_session error|pattern not found"
```

- `refreshed session cookie (N chars)` → success, downstream tools
  should be authenticated
- `obtain_session error: ...` → look at the exception (usually login
  URL or network)
- `WARNING: '<pattern>' not found — returning cookies anyway` → login
  silently failed; cookies returned are useless. Fix `loggedInPattern`
  or check the credentials work in a browser.

### 6.4 — Are findings showing up on auth'd endpoints?

If session refresh logged success but Phase 4 still returned nothing,
check the URL list (the `pentest-debugging` skill covers this). If the
URL list is right and creds refreshed, the most likely cause is **CSRF
enforcement** the form-submit didn't satisfy — set `csrfMetaSelector`
or `csrfCookieName` on the auth config.

---

## 7 — Common failure modes & their fingerprints

| Symptom | Likely cause |
|---|---|
| `RECORDING_BUSY` on start | Stale ACTIVE/SCANNING row from prior crash; query `RecordingSession WHERE status IN ('ACTIVE','SCANNING')`, manually STOP if needed |
| `EMPTY_RECORDING` on promote | User clicked Promote before browsing; tell them to do at least one navigation through the proxy first |
| Stats poll always returns same counts | ZAP context lost (likely ZAP restart). Stop and start a fresh recording — counters won't recover. |
| All scans of a domain run unauth | `triggerScan` not threading `domainAuthConfigId` from `domain.authConfig?.id`; or auth config missing |
| Phase 4 returns 0 with cookie refresh log present | URL list missing vuln endpoints (see `pentest-debugging` skill) OR CSRF protection blocked the login POST |
| Phase 4 returns 0 with NO cookie refresh log | `obtain_session` failed; check `loggedInPattern` and `loginUrl` |
| Idle sweeper auto-stopped a recording the user was actively using | They idled >60 min without page navigation. Hard cap is 4 h. Tell them to keep clicking. |
| Two users in same org can't both record | By design — ZAP is shared. Either coordinate, or self-host a separate ZAP per user (out of scope). |

---

## 8 — When NOT to use this skill

- **GitHub OAuth login flow** — that's `apps/api/src/auth/passport.ts`
  and is unrelated.
- **Session middleware / cookie config** for the BreachLens app itself
  — different layer.
- **Adding a new scanner** that doesn't need auth — see `add-scanner`
  skill.
- **Generic "the scan failed"** with no auth angle — see
  `pentest-debugging` skill.

---

## Reference: files this skill points at

```
apps/api/prisma/schema.prisma                              — DomainAuthConfig:331, RecordingSession:302
apps/api/src/services/recordingService.ts                  — full lifecycle
apps/api/src/services/encryptionService.ts                 — AES-256-GCM for creds
apps/api/src/workers/scanWorker.ts                         — line 56 decrypt, 132 forward
apps/api/src/migrations/triggerTestScan.ts                 — canonical recording-aware trigger
apps/scanner/main.py                                       — /dast/recording/{start,stats,scan,stop}
apps/scanner/scanners/base.py                              — obtain_session:198, auth_header_dict:297
apps/scanner/scanners/dast_interactive.py                  — InteractiveDASTSession class
apps/scanner/scanners/pentest_full/orchestrator.py         — Phase 0.5 recording vs Playwright fork
apps/scanner/scanners/pentest_full/exploit.py              — Phase 4 cookie refresh
```
