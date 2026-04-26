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

### Phase 22 — Multi-tenancy + enterprise auth 🟨 *(MUST-HAVE, 🚪 biggest GTM unlock, ~1.5–2 weeks remaining)*

**Already shipped (foundation is ~50% done):**

- ✅ 5-tier `Role` enum (OWNER / ADMIN / SECURITY / DEVELOPER / VIEWER) — richer than the original 3-role plan
- ✅ `OrganizationMember.role` with default DEVELOPER
- ✅ `requireAuth` + `requireRole(minRole)` middleware
- ✅ `<Can role="X">` component + `useRole` hook
- ✅ RBAC enforcement on 13 sensitive routes (repos, containers, domains, findings, policies, suppressions, admin)
- ✅ `AuditEvent` model + `auditService.log()` / `listEvents()` functions
- ✅ Audit logging instrumented in 9 sites across 5 routers

**Remaining work:**

- ❌ **PR 1 — Audit log surfacing + coverage** (1–2 days): `GET /api/audit` route (filterable, paginated, CSV export) + Settings → Audit Log tab + backfill `audit.log()` calls in unaudited routers (integrations, aiProviders, recordings, scans)
- ❌ **PR 2 — Member management** (3–5 days): `GET / POST / PATCH / DELETE /api/orgs/:slug/members[/...]` + Settings → Team tab + invitation flow (GitHub-username-based until SSO lands)
- ❌ **PR 3 — OIDC SSO** (1–2 weeks): per-org `Organization.ssoConfig` (encrypted), `passport-openidconnect` strategy, JIT user provisioning, role assignment via group claims, Settings → SSO tab. SAML deferred — most modern IdPs (Okta, Azure AD, Google Workspace) speak OIDC.

**Why:** required to sell into companies with >5 engineers. Without RBAC + SSO, you can't get past procurement. **The single biggest unlock in the entire roadmap.**

---

### Phase 15 — SBOM generation ❌ *(MUST-HAVE, 🚪 govt/regulated procurement, 3–5 days)*

- Generate CycloneDX + SPDX per repo on each scan
- Store under `Repository`, expose via `GET /api/repos/:id/sbom?format=cyclonedx`
- Sign with `cosign` for attestation

**Why:** US Executive Order 14028 + EU Cyber Resilience Act make SBOMs mandatory for selling to government and large enterprise. No SBOM = no procurement.
**World-class equivalent:** Snyk SBOM, Anchore.

---

### Phase 16 — Compliance framework mapping ❌ *(HIGH-VALUE, 🚪 partial — opens auditor segment, 1–2 weeks)*

- Map every Finding → CWE + OWASP Top 10 + SOC 2 control + PCI requirement (data already in CVE/CWE metadata)
- Per-framework dashboard (e.g. "17/52 SOC 2 CC6 controls have open findings")
- Evidence export (PDF + CSV per framework) for auditors

**Why:** Vanta + Drata are unicorns built primarily on this. Turns the platform from "developer tool" into "auditor tool" — 5–10× license value.
**Trigger condition for Anthropic API Skills (`pdf` / `xlsx` / `docx`)** — that's when they become useful.

---

### Phase 14 — Reachability for SCA ❌ *(HIGH-VALUE differentiator, not a gate, 1–2 weeks)*

- Build call-graph from repo (`jdeps` for Java, `syft` + custom for JS, etc.)
- For each CVE in Trivy output, mark `reachable: true / false / unknown`
- New finding filter: "Reachable HIGH/CRITICAL only"

**Why:** Endor Labs raised $70M selling this single feature. Cuts SCA finding noise by ~80% so devs stop ignoring the queue.
**World-class equivalent:** Endor Labs, Snyk Reachability.
**Note:** does *not* block any sale — improves UX for already-deployed customers, key driver of renewal not initial close.

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

## GTM-optimized sequenced timeline

| Month | Focus | Phases | Why this slot |
|---|---|---|---|
| 1 | **Procurement unlock** | 13 ✅ → **22** | RBAC + SSO + audit log unblocks every >5-engineer sale. Single biggest leverage move. |
| 2 | **Auditor transformation** | 15 → 16 | SBOM + compliance dashboards turn "dev tool" into "auditor tool" — 5–10× license value, opens regulated/govt segment |
| 3 | **Noise reduction + SOC story** | 14 + 23 | Reachability cuts SCA noise (protects renewals); SIEM bridge adds operational lift cheaply |
| 4 | **Refresh the differentiator + close the fix loop** | 24 + 17 | Pentest depth keeps demos sharp; auto-PRs close the "devs don't fix" gap |
| 5 | **Category expansion** | 18 (AWS-only first cut) | Biggest single category expansion (CSPM); start with AWS to scope down |
| 6 | **Coverage + adoption** | 19 + 20 + 21 | K8s easy win; API security newer differentiator; IDE for dev adoption funnel |
| Later | **SaaS scale** | 25 | Only when going multi-tenant SaaS — defer for self-host deployments |

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
- **`AuditEvent` + `auditService` + RBAC middleware + `Role` enum + `<Can>` component** — ~50% of Phase 22 already in place.
- **Wazuh MCP toolkit** — wired in, ready to expose for Phase 23.
- **`/healthz` deep endpoint** (commit `868e8b2`) — operational readiness for Phase 25 work later.
