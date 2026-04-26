# BreachLens Roadmap — Phases 13 to 25

> 6-month commercial roadmap that takes BreachLens from shipped v1 to
> enterprise-class platform. Each phase is anchored to a specific
> competitor moat, procurement gate, or operational bottleneck — not a
> feature wish-list.
>
> **Supersedes** the original v1 plan in
> `~/.claude/plans/stateless-dreaming-journal.md`, which is now
> historical (Phases 0–12 shipped).

---

## Phase 13 — Finish Phase 12 polish (1–2 days)

- Pin Docker image digests (`@sha256:…`) on all 5 base images
- Write `ENCRYPTION_KEY` rotation runbook
- Add `/healthz` deeper checks (DB writes, Redis writes, scanner reachability)

**Why:** these are blockers for any external deploy; cost is hours, not weeks.

## Phase 14 — Reachability for SCA (1–2 weeks)

- Build call-graph from repo (`jdeps` for Java, `syft` + custom for JS, etc.)
- For each CVE in Trivy output, mark `reachable: true / false / unknown`
- New finding filter: "Reachable HIGH/CRITICAL only"

**Why:** Endor Labs raised $70M selling this single feature. Cuts SCA finding noise by ~80% so devs stop ignoring the queue.
**World-class equivalent:** Endor Labs, Snyk Reachability.

## Phase 15 — SBOM generation (3–5 days)

- Generate CycloneDX + SPDX per repo on each scan
- Store under `Repository`, expose via `GET /api/repos/:id/sbom?format=cyclonedx`
- Sign with `cosign` for attestation

**Why:** US Executive Order 14028 + EU Cyber Resilience Act make SBOMs mandatory for selling to government and large enterprise. No SBOM = no procurement.
**World-class equivalent:** Snyk SBOM, Anchore.

## Phase 16 — Compliance framework mapping (1–2 weeks)

- Map every Finding → CWE + OWASP Top 10 + SOC 2 control + PCI requirement (data already in CVE/CWE metadata)
- New page: per-framework dashboard (e.g. "17/52 SOC 2 CC6 controls have open findings")
- Evidence export (PDF + CSV per framework) for auditors

**Why:** Vanta + Drata are unicorns built primarily on this. Turns the platform from "developer tool" into "auditor tool" — 5–10× license value.
**Trigger condition for Anthropic API Skills (`pdf` / `xlsx` / `docx`)** — that's when they become useful.

## Phase 17 — Auto-remediation PRs (1–2 weeks)

- For SCA findings with a known fix version: open a PR bumping the dep
- For Secrets: open a PR removing the secret + rotating-instructions issue
- Use the existing GitHub access token; gate behind per-repo opt-in

**Why:** the #1 unsolved problem in AppSec is "we tell devs about findings, devs don't fix them." A PR closes the loop.
**World-class equivalent:** Snyk fix PRs, Renovate, Dependabot.

## Phase 18 — Cloud Security Posture (CSPM) (3–4 weeks)

- AWS / GCP / Azure account onboarding via read-only IAM role
- Run Prowler / CloudQuery / steampipe against accounts
- Map findings into existing Finding schema with `targetType: CLOUD_ACCOUNT`
- CIS Benchmark dashboard

**Why:** entire missing category. Wiz hit $12B valuation primarily on this. Even a basic implementation captures the "we have an AWS account, what's misconfigured" use case.
**Effort caveat:** can scope down to AWS-only initially.

## Phase 19 — Kubernetes security (1–2 weeks)

- Trivy K8s for cluster manifest + running workload scans
- Kubescape for posture
- New `targetType: KUBERNETES_CLUSTER`

**Why:** Trivy already in our stack — we're 70% there. Cluster admins want this.
**World-class equivalent:** Wiz K8s, Snyk K8s, Kubescape.

## Phase 20 — API security (2–3 weeks)

- OpenAPI / GraphQL schema ingestion → generate test cases
- Tune DAST + Nuclei for API surface (Authorization headers, schema-driven fuzz)
- Sensitive-data exposure detector (PII patterns in responses)

**Why:** ~50% of new attacks target APIs, not web apps. Our DAST is web-app-tuned and misses most API surface.
**World-class equivalent:** Salt Security, Noname, Traceable.
**Builds on:** the existing `DomainAuthConfig` + auth-recording subsystem.

## Phase 21 — IDE integration + pre-commit (1–2 weeks)

- VS Code extension: pull findings for current repo, highlight in editor
- Pre-commit hook generator: install Semgrep + secret scan locally

**Why:** "shift left" — finds problems before PR. Snyk and Semgrep have these as their #1 dev-adoption funnel.

## Phase 22 — Multi-tenancy + enterprise auth (2–3 weeks)

- RBAC (currently single-org-per-user; add roles: Admin / Engineer / Viewer)
- SAML / OIDC SSO (beyond GitHub OAuth)
- Audit log for every state change

**Why:** required to sell into companies with >50 engineers. Without RBAC + SSO, you can't get past procurement.

## Phase 23 — SIEM bridge + SOC workflow (1 week)

- Wazuh connector (the MCP toolkit is already wired in, just expose findings → Wazuh alerts)
- Generic webhook → Splunk / Datadog / Sentinel
- Bidirectional alert correlation

**Why:** SOC teams want findings in their SIEM, not a separate dashboard. Easy lift, big operational value.

## Phase 24 — Pentest enhancements (2–4 weeks)

- Exploit chaining: if Phase 3 finds SSRF, feed targets into Phase 4 RCE attempts
- Lateral movement simulation against authenticated session
- Per-finding "verified exploit" badge with reproducer payload  *(partially shipped — see commit `cacd7c8`)*

**Why:** doubles down on our existing differentiator. Most commercial tools don't have multi-phase pentest at all.

## Phase 25 — Production scale (2–3 weeks)

- Redis pub/sub for SSE (multi-instance API)
- Worker autoscaling (separate worker pool per scan-type queue)
- pgbouncer for Postgres connection pooling
- Distributed scan workspace (S3-backed) instead of local `/tmp`

**Why:** current single-instance design is fine for ~50 concurrent scans; this unblocks multi-tenant SaaS deployment.

---

## Sequenced timeline

| Month | Focus | Phases |
|---|---|---|
| 1 | Polish + dev-experience moat | 13 → 14 → 15 |
| 2 | Audit-tool transformation + remediation loop | 16 → 17 |
| 3 | Easy operational wins | 19 → 23 |
| 4 | Enterprise procurement unlock | 22 |
| 5 | Cloud category | 18 |
| 6 | API security + pentest depth | 20 → 24 |

Phases 21 (IDE + pre-commit) and 25 (production scale) sit outside the
strict month sequence — pull in when dev-adoption or SaaS-deployment
becomes the bottleneck.

---

## Already-shipped slices that map onto these phases

- **Multi-provider AI subsystem** (`apps/api/src/services/aiClient.ts`) —
  supports Phase 16 evidence-summarisation work without provider lock-in.
- **Auth-recording / `DomainAuthConfig`** — direct foundation for Phase
  20 API auth + Phase 24 authenticated lateral movement.
- **Proof of Exploit badge** (commit `cacd7c8`) — Phase 24's "verified
  exploit" half.
- **Policy engine + PR checks** (commit `9e7ff07`) — building blocks for
  Phase 17 auto-PRs.
- **`pentest_full` pipeline** (`apps/scanner/scanners/pentest_full/`) —
  foundation for Phase 24 chaining.
