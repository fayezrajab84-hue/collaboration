# Phase 24.6 — Modern web app coverage (SPA + JSON API + authenticated)

**Status:** scoped, not started
**Predecessor:** Phase 24 (pentest depth — Proof of Exploit + multi-phase pentest pipeline) — 🟨 partial, in progress
**Surfaced by:** Juice Shop demo session — autonomous DAST + PENTEST against `juice-shop:3000` produced only 4 MEDIUM infrastructure-tier findings (CSP / clickjacking / CORS / session-in-URL). None of the OWASP Top 10 bugs Juice Shop is famous for (XSS, SQLi, IDOR, broken auth) fired. Good signal about real coverage gaps — modern SPAs with REST APIs + auth-gated endpoints aren't where BreachLens is strongest today.

---

## What's actually missing

The MVP autonomous scanner stack (ZAP active scan + Playwright crawler + nuclei + sqlmap + xsstrike + dalfox) catches:

- ✅ Form-based GET/POST parameter injection (DVWA-style — works great)
- ✅ Static-link discoverable endpoints
- ✅ Infrastructure misconfiguration (headers, cookies, TLS)
- ✅ Known-CVE-by-fingerprint (nuclei templates)

It does NOT catch (or catches weakly):

- ❌ JSON request-body fuzzing — ZAP's default policy emphasizes HTML form parameters; modern REST APIs need JSON-aware payload injection
- ❌ Auth-gated endpoints — recording captures URLs, ZAP replays them WITHOUT the JWT/session cookies, gets 401/403, doesn't fuzz further
- ❌ SPA-rendered routes — Playwright crawler captures initial render, but the Angular/React/Vue route tree often only materializes on user interaction
- ❌ Domain-aware target lists — Juice Shop has `/api/Challenges` listing 100+ vulnerable endpoints; scanner has no way to consume known-vulnerable-endpoint lists

These are the four sub-problems Phase 24.6 should chip at, in priority order.

---

## Slice plan (suggested commit shape)

### Slice A — Authenticated replay (highest value, ~2-3 days)

**Goal**: when a recording session has a `DomainAuthConfig` attached, propagate the captured auth state into the active-scan replay so ZAP fuzzes auth-gated endpoints with a valid session.

**The gap today**: `DomainAuthConfig` exists (Phase 20 partial), records FORM/HEADER/COOKIE/OAUTH2 credentials, and the recording flow CAN log in during capture. But the auth state isn't carried forward into the active-scan phase — ZAP forgets the JWT cookie/header by the time it starts attacking.

**Changes**:
- `apps/api/src/services/recordingService.ts` — when promoting a recording to a scan, attach the recording's session cookies + auth headers to the `ScanRequest` payload
- `apps/scanner/scanners/dast.py` — in `_setup_auth_context`, populate the ZAP context's authentication using the captured state (session cookie via `httpsessions` API, JWT via `replacer` rule) BEFORE the active scan starts
- New helper `apps/scanner/scanners/dast_auth.py` — typed handlers for cookie / bearer / OAuth2 auth modes
- Verify by re-running juice-shop DAST after a logged-in recording — should produce findings on `/api/Users/:id` (IDOR) + `/rest/basket/:id` (basket tampering)

**Why this is the highest value**: 70% of modern web app bugs live behind a login. Without this slice, BreachLens is functionally a "find vulns on public marketing pages" tool against any real customer app.

---

### Slice B — JSON body fuzzing policy (medium value, ~1-2 days)

**Goal**: when ZAP's active scanner hits a JSON-body endpoint (Content-Type: application/json), fuzz the JSON values with the same payload classes it currently throws at form parameters.

**The gap today**: ZAP's default policy assumes form-encoded bodies. JSON-body endpoints get only "passive" checks (header analysis, info leak detection) — no active payload injection.

**Changes**:
- `apps/scanner/scanners/dast.py:_setup_active_scan_policy` — enable `Content-Type: application/json` body fuzzing rules:
  - Rule 90019 (Server-Side Code Injection)
  - Rule 90020 (Remote OS Command Injection)
  - Rule 40012 (Cross Site Scripting — Reflected) with JSON-aware payload variant
  - Rule 40018 (SQL Injection) with JSON-aware payload variant
- Tune attack strength HIGH for JSON-body endpoints
- Verify via Juice Shop's `/api/Products/search?q=` — known SQL-injectable on the `q` query param + JSON-bodied `/api/Feedbacks` for stored XSS

---

### Slice C — SPA-aware crawler heuristics (medium value, ~3-4 days)

**Goal**: capture more of an SPA's route surface by waiting for client-side rendering, scraping the SPA's router config when possible, and following hash-fragment routes.

**The gap today**: Playwright crawler navigates to the entry URL, waits for `networkidle`, snapshots links. SPAs that lazy-load routes (most modern Angular/React/Next.js apps) have invisible portions ZAP never sees.

**Changes**:
- `apps/crawler/crawler/engine.py` — add SPA mode that:
  - Scrapes `window.__INITIAL_STATE__` / Redux dehydration / Next.js `__NEXT_DATA__` / Angular `Router.config` for client-side route definitions
  - Triggers click events on every visible button + interactive element with `[role=button]` / `[ng-click]` / similar SPA conventions
  - Follows hash-fragment routes (`#/admin`, `#/login`) which most static crawlers miss
- Flag per-domain: `Domain.crawlerMode = "STATIC" | "SPA"` (default STATIC)
- Verify against Juice Shop — should bump URL discovery from 132 → ~300+

---

### Slice D — Known-target ingestion (low effort, high optionality, ~1 day)

**Goal**: let operators feed BreachLens a list of "scan-these-specific-URLs" rather than relying on autonomous discovery. Juice Shop's `/api/Challenges` is the canonical example; OpenAPI specs are the broader case.

**The gap today**: there's a `Domain.apiSpec` foundation (`DomainApiSpec` table from earlier work) but it's not consumed by the DAST/PENTEST pipelines for target seeding.

**Changes**:
- `apps/scanner/scanners/dast.py` — read `request.openapi_endpoints` (already plumbed via `apiSpec`) and seed each one into ZAP as an explicit target
- New optional field on `Domain`: `targetUrls: String[]` — operator-curated list, fed to scanner alongside crawler output
- UI: "Paste known endpoints" textarea in Domain detail panel
- Composes with Slice A — the seeded URLs get the captured auth context too

---

## Effort estimate

| Slice | Lines | Time |
|---|---|---|
| A — Authenticated replay | ~400 | 2-3 days |
| B — JSON body fuzzing policy | ~150 | 1-2 days |
| C — SPA-aware crawler | ~500 | 3-4 days |
| D — Known-target ingestion | ~200 | 1 day |
| **Total Phase 24.6** | **~1250** | **~1.5-2 weeks** |

Slice A alone is the killer move — most other gaps are downstream of "no auth, no findings." Ship A first, verify the gap actually closes against Juice Shop, then evaluate whether B/C/D add enough delta to justify their cost.

---

## Open questions to settle before Slice A

1. **Auth replay strategy** — copy session cookies forward (simpler, brittle if cookies expire mid-scan) vs replay the login flow at the start of the active scan (more robust, requires storing creds plain or encrypted)? `DomainAuthConfig` already has the encryption infra; lean toward the replay approach.

2. **Per-attack auth refresh** — short-lived JWTs (e.g. 5 min) expire during a 30-min active scan. Do we re-login periodically, or accept that long scans against short-JWT apps degrade? Recommend: refresh on 401 detection in the response interceptor.

3. **Auth scope vs attack scope** — when ZAP attacks a logout endpoint, does it use the captured session (correct, will then BREAK the rest of the scan) or skip it (safer)? Recommend: ZAP context exclusion list seeded from captured logout/destroy URLs.

4. **OAuth2 / OIDC flows** — the recording can capture the redirect chain but the scanner's auth-replay needs to know how to refresh tokens. For v1, treat OAuth2 same as bearer-token (single capture, no refresh) and document the limitation.

---

## Why this is the right next pentest investment

Phase 24 (pentest depth) and the upcoming Phase 24.5 (HITL mode from the Phase 26 wishlist) both make the EXISTING capability sharper. Phase 24.6 expands the *attack surface* the scanner can reach in the first place.

Strategic position: BreachLens's pentest moat (Proof of Exploit, multi-phase pipeline) is real on simple-architecture targets like DVWA. To carry that moat into customer demos against modern SPA + REST API stacks (which is what 80%+ of customer apps actually are in 2026), the scanner has to learn modern-web tricks. Phase 24.6 is that learning curve.

Without 24.6: BreachLens looks great on demo apps + legacy PHP, weak on every customer's actual production codebase.
With 24.6: BreachLens carries its differentiator through the technologies customers actually run.
