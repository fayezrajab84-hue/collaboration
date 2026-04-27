# BreachLens Roadmap — Phases 13 to 25

> 6-month sequenced roadmap that takes BreachLens from shipped v1 to
> enterprise-class platform. **Sequenced for go-to-market unlock**, not
> for technical layering — phases are ordered by which ones remove the
> next revenue blocker, not by which ones build cleanly on prior work.
>
> **Supersedes** the original v1 plan in
> `~/.claude/plans/stateless-dreaming-journal.md`, which is now
> historical (Phases 0–12 shipped).

---

## Status & priority legend

| Symbol | Meaning |
|---|---|
| ✅ | Shipped |
| 🟨 | Partially shipped (foundation exists, gaps remain) |
| ❌ | Not started |
| **MUST-HAVE** | Strictly required for the next customer segment to consider buying |
| **HIGH-VALUE** | Demonstrable lift in retention or close-rate but not a procurement blocker |
| **DIFFERENTIATOR** | Opens a category or extends an existing moat |
| **NICE-TO-HAVE** | Marginal lift, defer until backlog is empty |
| 🚪 | Procurement gate — without this, this customer segment cannot buy |

---

## Phases — current status

### Phase 13 — Finish Phase 12 polish ✅ *(MUST-HAVE, 🚪 table stakes, 1–2 days)*

- ✅ Pin Docker image digests (`@sha256:…`) on all 5 base images — commit `b8d65c4`
- ✅ Write `ENCRYPTION_KEY` rotation runbook — commit `eb8a3ba`
- ✅ Add deep `/healthz` endpoint (DB write, Redis write, scanner reachability) — commit `868e8b2`

**Why:** blockers for any external deploy. Cost was hours, not weeks.
**Follow-up:** `apps/api/src/migrations/rotateEncryptionKey.ts` script does not yet exist; first real key rotation needs it built.

---

### Phase 22 — Multi-tenancy + enterprise auth ✅ *(MUST-HAVE, 🚪 biggest GTM unlock — SHIPPED)*

**Foundation (already in place at session start):**

- ✅ 5-tier `Role` enum (OWNER / ADMIN / SECURITY / DEVELOPER / VIEWER)
- ✅ `OrganizationMember.role` with default DEVELOPER
- ✅ `requireAuth` + `requireRole(minRole)` middleware
- ✅ `<Can role="X">` component + `useRole` hook
- ✅ RBAC enforcement on 13 sensitive routes
- ✅ `AuditEvent` model + `auditService.log()` / `listEvents()` functions
- ✅ Audit logging instrumented in 9 sites across 5 routers

**Shipped this round:**

- ✅ **PR 1 — Audit log surfacing + coverage** (commit `8327033`): `GET /api/audit` (filterable, paginated, ADMIN+) + `GET /api/audit/export.csv` (RFC 4180, 50k-row cap) + Settings → Audit Log tab + 16 new `audit.log()` call sites across integrations / AI providers / scans / recordings.
- ✅ **PR 2 — Member management + invitations** (commit `7608980`): new `Invitation` Prisma model + 6 routes (list members, change role, remove member, list/create/revoke invitations) with last-OWNER guards + `passport.ts` invitation acceptance on every login + Settings → Team tab with member table, role dropdowns, GitHub-username invite flow, "no email is sent" out-of-band notification banner.
- ✅ **PR 3 Slice A — SSO config infra** (commit `d7be957`): `SsoConfig` model (1:1 with Organization, encrypted clientSecret) + `GET / PUT / DELETE /api/sso` + `POST /api/sso/test` (validates IdP discovery doc) + Settings → SSO tab with chip-based domain editor, group → role mapping, brand-indigo styling.
- ✅ **PR 3 Slice B — OIDC login flow** (commit `d135e4a`): minimal-deps OIDC client (`oidcService.ts`, ~200 LoC, no third-party install) + `/auth/sso/initiate?email=…` + `/auth/sso/callback` + JIT user provisioning + group-claim → role mapping + LoginPage SSO toggle alongside GitHub OAuth.
- ✅ **PR 3 Slice C — Entra ID polish** (commit `686f9d7`): email fallback chain (email → preferred_username → upn → unique_name) + group overage detection (Entra ≥150 groups) + Provider preset dropdown in Settings (Generic / Entra / Okta / Auth0 / Google / Keycloak) with provider-specific setup notes.
- ✅ **Brand sweep** (commits `fb86e92` + `5de75d3` + `b88bc01`): legacy teal "Connected" indicators → indigo across Settings sidebar dots, Jira/Slack/Teams Connected pills, Repositories "Added" pill; legacy `text-sm` form font sizing → `text-xs` across all 7 Settings tabs.

**Why this unblocks revenue:** required to sell into any company with >5 engineers. Without RBAC + SSO, prospects fail the security review at procurement. Now passes.

**Verification status:**

- All routes + UI verified via API curl + browser preview during build
- OIDC initiate flow validated against real Google discovery URL (302 → standards-compliant authorization URL with `state` + `nonce`)
- OIDC callback round-trip NOT tested against a live IdP (would need real client registration); first production login is the real test
- Member invitation acceptance validated by simulating the passport callback's SQL inserts directly (test user `cmfake-invitee-probe` was provisioned and visible in Team tab)

**Slice C / future polish that's NOT in this round:**

- Per-org "require SSO" enforcement (both auth methods always work)
- Microsoft Graph API for resolving Entra group overage (currently falls back to defaultRole + warning)
- SSO logout / single-sign-out
- Real email-based invitations (deferred — depends on email infra; SSO captures email anyway)
- Audit retention policy / pg_partman integration

---

### Phase 22.7 — Close UI/API role-gate parity gaps ✅ *(SHIPPED)*

The frontend parity test from Phase 22.6 surfaced 5 places where
ADMIN/SECURITY-only API endpoints were exposed to all roles in the UI.
This phase closed every one. Plus a critical bug fix to `useRole` —
it had been reading `orgs[0].role` ignoring `activeOrgId`, so multi-org
users were getting the role from the wrong org.

Now: `SettingsPage` filters tabs by role; AuditLogTab / SSOTab /
PoliciesTab wrap their content in `<Can role="ADMIN">` with explanatory
fallbacks; DomainsPage delete + FindingsPage bulk toolbar gated;
new `SuppressionsTab` so accepted-risk records are auditable at the
org level. 53 tests still green.

Full retro: [`docs/plans/phase-22.7-ui-role-gating.md`](./phase-22.7-ui-role-gating.md).

---

### Phase 22.5 — GitHub Enterprise + GitHub App ❌ *(MUST-HAVE for GHES customers, NOT STARTED)*

Closes the Phase 22 gap that bites Entra-federated-GitHub-Enterprise customers: today they can sign in via Entra OIDC (Phase 22 PR 3), but the JIT-provisioned user has a placeholder access token (`encrypt("oidc-no-token")`) — they literally cannot scan their private GHES repos.

**Two procurement blockers, one phase:**

1. The "Continue with GitHub" button hardcodes github.com — useless for GHES tenants
2. SSO-provisioned users have no usable repo-access token — scans on private repos fail

**Solution shape:** decouple identity (Entra OIDC stays primary) from repo access (move to org-level GitHub App installations). This is the canonical pattern Snyk / Aikido / Wiz all use.

**4 slices, ~830 lines, ~2 days:**

- **A — Configurable GHES OAuth login:** second `passport-github2` strategy with custom URLs from `GITHUB_ENTERPRISE_URL` env vars; conditional "Continue with <ghes-domain>" login button
- **B — Schema + GitHub App service:** add `IntegrationType.GITHUB_APP`; new `githubAppService` with JWT signing + installation token caching
- **C — Install flow + Settings UI:** `GET /api/integrations/github-app/install-url` + callback + Settings → GitHub Integration tab
- **D — Token resolution refactor:** central `getRepoTokenForOrg(orgId)` helper; prefer App token, fall back to OWNER's user token, clear error when neither

**Also unblocks Phase 17** (auto-fix PRs) — PR creation as a bot needs an App, not user OAuth tokens.

**Full scope doc:** [`docs/plans/phase-22.5-ghes-and-github-app.md`](./phase-22.5-ghes-and-github-app.md). Four open questions to resolve before starting Slice A (App ownership model, hide-github.com toggle, per-user GHES OAuth deferral, legacy token migration).

---

### Phase 15 — SBOM generation ✅ *(MUST-HAVE, 🚪 govt/regulated procurement — SHIPPED)*

**All three slices shipped:**

- ✅ CycloneDX generation via Trivy (repos: `trivy fs`; containers: `trivy image`)
- ✅ **Slice A** (`14bedf5`) — SPDX (ISO/IEC 5962) alongside CycloneDX, audit-logged downloads, right Content-Type + filename per format
- ✅ **Slice B** (`9b71b49`) — per-scan persistence: `Sbom` model with (repo, format, generatedAt DESC) indexes; worker auto-persists CycloneDX after each SCA scan; download endpoint cache-first with `X-Sbom-Source` header; sha256 dedup against latest row prevents JSONB churn for stable repos
- ✅ **Slice C** (`00ffce2`) — cosign-compatible ECDSA P-256 SHA256 signing: instance-wide `SbomSigningKey` (lazy-init keypair, AES-256-GCM private key), worker signs after persist, download emits `X-Sbom-Signature` + `X-Sbom-Signature-Key-Id` headers, `GET /api/sbom/public-key` for verifiers
- ✅ UI: split-button group on Repositories + Containers pages — primary CycloneDX + smaller SPDX

**Verification:** stock `openssl dgst -sha256 -verify pub.pem -signature sig.bin sbom.json` returns `Verified OK` for genuine SBOMs and `Verification failure` for byte-tampered ones. Signatures are byte-for-byte compatible with `cosign verify-blob`.

**Operator workflow for procurement reviews:**
1. `curl ... /api/repos/<id>/sbom > sbom.json` (capture `X-Sbom-Signature` + `X-Sbom-Signature-Key-Id`)
2. `curl ... /api/sbom/public-key | jq -r .publicKeyPem > pub.pem`
3. `openssl dgst -sha256 -verify pub.pem -signature <decoded-sig> sbom.json` → `Verified OK`

**Deferred to follow-ups (not blockers for procurement):**
- Container SBOM auto-persistence + signing (only repo SBOMs auto-persist + auto-sign today)
- Key rotation runbook + `DELETE /api/sbom/key` endpoint
- Public key archival/export (so old signatures stay verifiable across rotations)
- Sigstore Rekor transparency log integration (keyless mode)
- SLSA provenance attestations (separate from SBOM attestation)
- Retention policy for historical `Sbom` rows
- SPDX auto-persistence on scan (cost-vs-coverage; defer until requested)

**Why:** US Executive Order 14028 + EU Cyber Resilience Act make SBOMs mandatory for selling to government and large enterprise. No SBOM = no procurement. Slice A clears the format-availability gate; Slices B+C add the historical+attested evidence procurement actually wants.
**World-class equivalent:** Snyk SBOM, Anchore.

---

### Phase 16 — Compliance framework mapping ✅ *(SHIPPED — 5 slices over one session)*

- ✅ **Slice A — Schema + seed** (commit `221f06c`): `ComplianceFramework` enum, `ComplianceControl` model, `FindingControl` join, plus 26 seeded controls (OWASP Top 10 2021 + SOC 2 CC6/7/8 + PCI DSS 4.0 Req 6/8/11) with documented CWE mappings.
- ✅ **Slice B — Mapping engine** (commit `02a6a7e`): `complianceMappingService` with CWE-based primary matching + keyword fallback. Wired into `findingService.upsertFindings` for auto-mapping; `backfillComplianceMappings.ts` for the historical backlog. 611 findings → 448 mappings on first run.
- ✅ **Slice C — Read API** (commit `7905291`): three endpoints — `/api/compliance/frameworks`, `/api/compliance/:framework/dashboard`, `/api/compliance/:framework/controls/:code/findings`. All VIEWER+, org-scoped via `getActiveMembership`.
- ✅ **Slice D — Dashboard UI** (commit `57aa64e`): `/compliance` page with framework picker tabs, control matrix grouped by category, severity histograms, inline drill-down. Sidebar nav entry between Security Report and Settings.
- ✅ **Slice E — Evidence export** (commit `37b5617`): ADMIN-gated CSV (RFC 4180) + printable HTML (auditor saves as PDF via Cmd-P). No PDF runtime dep — matches the existing `reportHtmlService` pattern. Audit-logged.

**Why this unblocks revenue:** Vanta + Drata are unicorns built primarily on this. Turns the platform from "developer tool" into "auditor tool" — 5–10× license value, opens the regulated/govt segment that requires SOC 2 + PCI evidence.

**Strategic position:** every BreachLens scan now produces evidence for *three* frameworks at once. The same SCA finding lights up OWASP A06 + SOC 2 CC7.1 + PCI Req-6.3.1 simultaneously — one scan, three audit reports. ISO 27001 / NIST CSF / HIPAA can be added by extending the `ComplianceFramework` enum + inserting new `ComplianceControl` rows; no further code changes needed.

---

### Phase 14 — Reachability for SCA ✅ *(SHIPPED — package-level MVP for JS/Python; per-language followups deferred)*

- ✅ **Slice A — Schema + scanner-side import detection** (commit `06b1c73`): `Reachability` enum + `Finding.reachability` + `reachabilityEvidence`. Scanner walks the source tree post-Trivy, builds `{packageName → [importing files]}` for JS/TS/Python.
- ✅ **Slice B — UI badge** (commit `b74d6bb`): `ReachabilityBadge` on every finding row in `/findings` and inside the compliance drill-down. Hover shows the evidence files. NOT_APPLICABLE renders nothing.
- ✅ **Language-gate fix** (commit `18f1d2b`): Java / Go / Ruby / .NET findings stay UNKNOWN instead of being falsely tagged NOT_REACHABLE — first-day bug caught before it shipped to a customer.
- ✅ **Slice C — Filter + noise-reduction stat** (commit `8983449`): reachability MultiSelect on FindingsPage; "X open findings reach actual source code · Y can be deferred (Z% noise filtered)" stat in the compliance dashboard header.

**Live numbers in dev** (OWASP/NodeGoat after Slice A scan): 6 REACHABLE / 36 NOT_REACHABLE = 86% noise reduction on SCA triage. The 6 REACHABLE packages (`underscore`, `mongodb`, `body-parser`, `marked`, `swig`, `express`) are exactly what an attacker can touch — the other 36 are deep transitives that NodeGoat's source never imports.

**Followups not in MVP:**
- Per-language full classifiers for Maven (Java), Go modules, Ruby gems, Cargo crates — currently returns UNKNOWN
- True call-graph reachability (vulnerable function actually called, not just package imported) — months of work per language; the classification framework is in place, just swap in the call-graph builder when ready
- Container SBOM reachability — harder, no source code to grep; future option is process-list / lib-load evidence from the running container

**World-class equivalent:** Endor Labs ($70M raised on this single feature), Snyk Reachability. BreachLens v1 is package-level not function-level, but the noise-reduction story matches the demo numbers customers actually see.

---

### Phase 14.5 — Container reachability ❌ *(scoped, not started, ~1 week)*

Surfaced same-day as Phase 14 by a customer adding `vulnerables/web-dvwa` and seeing 120 findings all `UNKNOWN`. Truth-in-advertising fix (sharper container tooltip) shipped same session; this phase fills the gap properly.

Container scans don't have source code to grep — Phase 14's import-detection mechanic doesn't translate. Three approaches scoped, recommendation is to ship Approach A first (~1 week):

- **A — Static entrypoint dependency closure**: trace which binaries the image's CMD/ENTRYPOINT loads, mark OS packages outside that closure as NOT_REACHABLE. Catches the "container only runs nginx, postgres-client CVE is deferrable" case.
- **B — Filesystem extraction + grep `/app`**: extracts the image, runs Phase 14's existing classifier against bundled language packages. Composes with A for full coverage.
- **C — Runtime instrumentation**: actually run the image, observe via `/proc/*/maps`. Defer until Phase 18 (CSPM) builds the sandboxed-execution layer.

Full scope: [`docs/plans/phase-14.5-container-reachability.md`](./phase-14.5-container-reachability.md). Four open questions to settle before Slice A1 (layer extraction strategy, multi-arch handling, per-scan cost ceiling, k8s/compose entrypoint-override semantics).

---

### Phase 23 — SIEM bridge + SOC workflow 🟨 *(HIGH-VALUE, easy lift, 1 week)*

- ✅ Wazuh MCP toolkit already wired in
- ❌ Wazuh connector: expose findings → Wazuh alerts
- ❌ Generic webhook → Splunk / Datadog / Sentinel
- ❌ Bidirectional alert correlation

**Why:** SOC teams want findings in their SIEM, not a separate dashboard. Easy lift, big operational value.

---

### Phase 24 — Pentest enhancements 🟨 *(DIFFERENTIATOR, extends existing moat, 2–4 weeks)*

- ❌ Exploit chaining: if Phase 3 finds SSRF, feed targets into Phase 4 RCE attempts
- ❌ Lateral movement simulation against authenticated session
- ✅ Per-finding "verified exploit" badge with reproducer payload — commit `cacd7c8` (Proof of Exploit badge shipped this session)

**Why:** doubles down on our existing differentiator. Most commercial tools don't have multi-phase pentest at all. **This is what makes BreachLens visible against the Aikido / Snyk / Wiz pile in demos.**

---

### Phase 24.6 — Modern web app coverage (SPA + JSON API + auth) ❌ *(DIFFERENTIATOR, expands attack surface, ~1.5–2 weeks)*

Surfaced by a Juice Shop demo session — autonomous DAST + PENTEST against `juice-shop:3000` produced only 4 MEDIUM infrastructure findings (CSP / clickjacking / CORS / session-in-URL). None of the OWASP Top 10 bugs Juice Shop is famous for fired. The MVP scanner stack catches form-based GET/POST + static-link discovery + nuclei templates well, but misses JSON-body fuzzing, auth-gated endpoints, and SPA-rendered routes — i.e. ~80% of modern customer apps.

Four slices, ~1250 lines, ~1.5–2 weeks total:

- **A — Authenticated replay (highest value, 2-3 days):** propagate captured `DomainAuthConfig` session into the active-scan ZAP context so it fuzzes auth-gated endpoints with a valid session. **70% of modern web app bugs live behind a login**; without this slice BreachLens is functionally a "find vulns on public marketing pages" tool.
- **B — JSON body fuzzing policy (1-2 days):** enable ZAP active-scan rules for `Content-Type: application/json` bodies (currently only form-encoded gets fuzzed).
- **C — SPA-aware crawler heuristics (3-4 days):** scrape SPA router config + trigger interactive elements + follow hash routes. Most modern Angular/React/Next.js apps are invisible to a Playwright-only crawler.
- **D — Known-target ingestion (1 day):** consume operator-supplied URL lists + `DomainApiSpec` OpenAPI specs to seed ZAP targets directly.

Slice A alone is the killer move; ship A first, verify the gap closes against Juice Shop, then evaluate B/C/D. Composes with Phase 24 (Proof of Exploit + multi-phase pipeline) — gives those existing differentiators a wider attack surface to operate on.

Full scope: [`docs/plans/phase-24.6-modern-app-coverage.md`](./phase-24.6-modern-app-coverage.md). Four open questions to settle before Slice A (auth replay strategy, per-attack token refresh, logout-endpoint exclusion, OAuth2/OIDC flow handling).

---

### Phase 17 — Auto-remediation PRs ❌ *(HIGH-VALUE, not a gate, 1–2 weeks)*

- For SCA findings with a known fix version: open a PR bumping the dep
- For Secrets: open a PR removing the secret + rotating-instructions issue
- Use the existing GitHub access token; gate behind per-repo opt-in

**Why:** the #1 unsolved problem in AppSec is "we tell devs about findings, devs don't fix them." A PR closes the loop.
**Foundation:** policy engine + PR checks already exist (commit `9e7ff07`).
**World-class equivalent:** Snyk fix PRs, Renovate, Dependabot.

---

### Phase 18 — Cloud Security Posture (CSPM) ❌ *(DIFFERENTIATOR, opens cloud buyer, 3–4 weeks)*

- AWS / GCP / Azure account onboarding via read-only IAM role
- Run Prowler / CloudQuery / steampipe against accounts
- Map findings into existing Finding schema with `targetType: CLOUD_ACCOUNT`
- CIS Benchmark dashboard

**Why:** entire missing category. Wiz hit $12B valuation primarily on this.
**Effort caveat:** can scope down to AWS-only initially.

---

### Phase 19 — Kubernetes security ❌ *(HIGH-VALUE, easy expansion, 1–2 weeks)*

- Trivy K8s for cluster manifest + running workload scans
- Kubescape for posture
- New `targetType: KUBERNETES_CLUSTER`

**Why:** Trivy already in our stack — we're 70% there. Cluster admins want this.
**World-class equivalent:** Wiz K8s, Snyk K8s, Kubescape.

---

### Phase 20 — API security 🟨 *(DIFFERENTIATOR, newer category, 2–3 weeks)*

- ✅ `DomainAuthConfig` + auth-recording subsystem (foundation for authenticated API auth)
- ❌ OpenAPI / GraphQL schema ingestion → generate test cases
- ❌ Tune DAST + Nuclei for API surface (Authorization headers, schema-driven fuzz)
- ❌ Sensitive-data exposure detector (PII patterns in responses)

**Why:** ~50% of new attacks target APIs, not web apps. Our DAST is web-app-tuned and misses most API surface.
**World-class equivalent:** Salt Security, Noname, Traceable.

---

### Phase 21 — IDE integration + pre-commit ❌ *(NICE-TO-HAVE, adoption funnel, 1–2 weeks)*

- VS Code extension: pull findings for current repo, highlight in editor
- Pre-commit hook generator: install Semgrep + secret scan locally

**Why:** "shift left" — finds problems before PR. Snyk and Semgrep have these as their #1 dev-adoption funnel. Drives renewal, not initial close.

---

### Phase 25 — Production scale ❌ *(MUST-HAVE for SaaS only, gate for multi-tenant SaaS, 2–3 weeks)*

- Redis pub/sub for SSE (multi-instance API)
- Worker autoscaling (separate worker pool per scan-type queue)
- pgbouncer for Postgres connection pooling
- Distributed scan workspace (S3-backed) instead of local `/tmp`

**Why:** current single-instance design is fine for ~50 concurrent scans; this unblocks multi-tenant SaaS deployment. Skip entirely if BreachLens stays self-host-only.

---

### Phase 26 — AI-driven novel vulnerability discovery ❌ *(RESEARCH MOAT, deferred to Month 7+, 2–3 weeks)*

- New `ScanType.AI_DISCOVERY` — runs in parallel to SAST on the same cloned repo
- New `AIServiceName.NOVEL_VULN_DISCOVERY` routed through `aiClient.ts` (multi-provider already in place)
- Per-repo opt-in (cost-sensitive — Mythos-class calls are expensive vs Trivy/Semgrep)
- Findings normalised to the existing `Finding` schema with `scanner: "ai-discovery"` so they're filterable
- Cost gating: monthly $ budget per org + per-call token cap; metrics for hit rate (false-positive vs novel-true-positive over time)
- Retrieval-augmented prompts: don't send the whole repo to the LLM — extract candidate hot paths via call-graph (the same Phase-14 reachability infra) + send only those + their dependencies. Cuts token usage 10-100x.

**Why:** Anthropic's [Mythos Preview](https://red.anthropic.com/2026/mythos-preview/) (announced 2026 via Project Glasswing) demonstrated that frontier-model reasoning over code finds vulnerabilities pattern-based scanners can't. Per the announcement: 595 severe-tier crashes vs single-digit prior generation; 181 working JavaScript exploits vs 2 prior; bugs found in heavily-audited projects (FFmpeg, OpenBSD, Linux kernel). Pattern-based scanning hits a ceiling on novel/complex bugs; LLM reasoning extends past it.

**World-class equivalents:** Mythos Preview (Anthropic, restricted preview as of 2026; no public API yet), GitHub Copilot Autofix, Snyk DeepCode AI, OpenAI's emerging code-reasoning research.

**Why deferred to Month 7+:**
- Mythos isn't GA at Anthropic (Project Glasswing is invite-only). Until a public API lands, BreachLens can use Claude Sonnet 4.5 / GPT-5 / Gemini 2.5 Pro as fallbacks — but those are demonstrably weaker on this specific task per Anthropic's own benchmarks
- Cost-per-finding is currently prohibitive without the Phase-14 reachability layer to scope what gets sent to the LLM. Phase 14 should land first
- Zero procurement urgency — no auditor / RFP / customer asks for "AI-driven novel vuln discovery" today. It's a research moat, not a procurement gate

**When the Mythos API lands** (or any frontier model with comparable code-reasoning capability): plumbing is ~hours, not weeks, because `aiClient.ts` already abstracts providers. Add a `MYTHOS` enum value to `AIProviderType`, an adapter in the service, and the new service routes through. The hard part is the *content* of the prompts + the cost-gating + the false-positive triage at scale.

**Strategic position:** Anthropic ships the pickaxe (Mythos), BreachLens ships the mine. When customers want LLM-driven discovery integrated with their existing scanner pipeline + audit trail + ticketing + RBAC, BreachLens is structurally positioned to integrate it — Mythos has no operational wrapper.

### Wishlist — adjacent AI-pentest ideas to fold in when picking up Phase 26

Surfaced from the *open-source AI pentest / red-team* survey (Apr 2026):
HexStrike AI, Shannon, PentestAgent. None are revenue-shaped on their
own; all reinforce the "decision compression" thesis Phase 26 already
sits on. Group them here so they're not lost; pick whichever lights up
once Mythos lands.

- **HITL pentest mode (PentestAgent-style Assist / Agent / Crew tiers)** —
  half-day add. Today PENTEST_FULL is fully autonomous; regulated
  buyers want supervised mode where the operator approves before each
  phase (especially Phase 4 Exploit). Schema: `Domain.pentestMode = AUTO
  | SUPERVISED`; orchestrator pauses + emits an approval event between
  phases when SUPERVISED. Cheap, differentiates against
  fire-and-forget AI pentest tools, and matches the *human keeps
  decision authority* framing customers actually trust.
- **MCP exposure of BreachLens tools (HexStrike-style)** — ~1 day.
  Expose `triggerScan`, `getFindings`, `runPentestPhase`,
  `createSuppression` etc. as MCP tools so other AI pentest frameworks
  (HexStrike, future agents) can drive BreachLens. Repositions
  BreachLens as a *substrate* for AI agents rather than just a tool.
  Low procurement value, very high strategic value if the AI-agent
  pentest pattern becomes the standard.
- **Knowledge-graph / persistent memory of org assets + past findings** —
  the pattern under all three surveyed tools. BreachLens partially
  has this (`Finding.fingerprint` dedup) but not at the "this asset
  was vulnerable last quarter, retest first" level. Fits naturally
  alongside Phase 14 reachability — both want a graph of
  asset-to-finding-to-fix-to-retest history.
- **White-box pentest mode (Shannon-style — combine SAST signal +
  live exploitation)** — feeds an AI a SAST-discovered candidate and
  has it attempt live exploitation through ZAP / sqlmap / dalfox,
  closing the loop from "this might be vulnerable" → "here's the
  working exploit" automatically. Composes well with the existing
  Proof of Exploit pattern.

When Phase 26 picks up, decide which of these belong inside it (likely
HITL + KG) vs which deserve their own follow-on (MCP exposure is its
own play, white-box mode is closer to Phase 24 than 26).

---

## GTM-optimized sequenced timeline

| Month | Focus | Phases | Why this slot |
|---|---|---|---|
| 1 | **Procurement unlock** | 13 ✅ → **22 ✅** | RBAC + SSO + audit log unblocks every >5-engineer sale. Single biggest leverage move. |
| 2 | **Auditor transformation** | 15 → 16 | SBOM + compliance dashboards turn "dev tool" into "auditor tool" — 5–10× license value, opens regulated/govt segment |
| 3 | **Noise reduction + SOC story** | 14 + 23 | Reachability cuts SCA noise (protects renewals); SIEM bridge adds operational lift cheaply |
| 4 | **Refresh the differentiator + close the fix loop** | 24 + 17 | Pentest depth keeps demos sharp; auto-PRs close the "devs don't fix" gap |
| 5 | **Category expansion** | 18 (AWS-only first cut) | Biggest single category expansion (CSPM); start with AWS to scope down |
| 6 | **Coverage + adoption** | 19 + 20 + 21 | K8s easy win; API security newer differentiator; IDE for dev adoption funnel |
| Later (SaaS-only) | **SaaS scale** | 25 | Only when going multi-tenant SaaS — defer for self-host deployments |
| Later (research moat) | **AI-driven discovery** | 26 | Waits on Mythos public API + Phase 14 reachability for cost-effective scoping. Plumbing is hours when ready. |

### Why this differs from a technical-layering sequence

The instinct is to layer technically: build the dev moat (reachability, SBOM), then the audit moat (compliance), then the cloud moat (CSPM), then the enterprise plumbing (RBAC/SSO). That's what the original sequence did — Phase 22 in Month 4.

But **every single mid-market deal blocks on RBAC + SSO**. Four months without RBAC = four months of "we love it but security says no." The technical-layering instinct loses revenue.

Two phases also got moved forward against the original sequence:

- **Phase 24 (pentest depth)** — was scheduled last (Month 6). Pentest depth is BreachLens's existing visible differentiator; if it goes 6 months without enhancement, every prospect demo flatlines because BreachLens looks like "just another scanner aggregator." Moved to Month 4.
- **Phase 14 (reachability)** — was scheduled Month 1 (the headline noise-reduction feature). It's a real moat but doesn't unblock any sale — it improves UX for already-deployed customers. Moved to Month 3.

---

## Already-shipped slices that map onto these phases

- **Multi-provider AI subsystem** (`apps/api/src/services/aiClient.ts`) — supports Phase 16 evidence-summarisation work without provider lock-in.
- **Auth-recording / `DomainAuthConfig`** — direct foundation for Phase 20 API auth + Phase 24 authenticated lateral movement.
- **Proof of Exploit badge** (commit `cacd7c8`) — Phase 24's "verified exploit" half.
- **Policy engine + PR checks** (commit `9e7ff07`) — building blocks for Phase 17 auto-PRs.
- **`pentest_full` pipeline** (`apps/scanner/scanners/pentest_full/`) — foundation for Phase 24 chaining.
- **Phase 22 (RBAC + audit + members + SSO + Entra polish)** — fully shipped (8327033 / 7608980 / d7be957 / d135e4a / 686f9d7 + brand-sweep polish in fb86e92, 5de75d3, b88bc01).
- **Wazuh MCP toolkit** — wired in, ready to expose for Phase 23.
- **`/healthz` deep endpoint** (commit `868e8b2`) — operational readiness for Phase 25 work later.
