# Phase 22.6 — GitHub Marketplace launch

**Status:** scoped, not started
**Predecessor:** Phase 22.5 (GitHub App + GHES support — ❌ scoped, not started). This phase REUSES Phase 22.5's GitHub App primitive but adds Marketplace-specific surface area on top.
**Hard prerequisite:** Phase 29 Slice B (cross-tier cloud bridges, ~200 LOC). The Marketplace listing should not go live until the **5-act demo** (source → image → pen-test → runtime → cloud) is end-to-end demoable on a real target. Otherwise the listing under-sells the moat.
**Surfaced by:** end-of-session conversation Apr 30 about distribution / GTM. Marketplace listing is the highest-leverage GTM move available in the next 2 months — moves Scale C → B-, opens dev-funnel parity with Snyk/Aikido/Endor, restructures positioning from *"credible alternative"* to *"Marketplace baseline with the only cross-tier correlation moat."*

---

## Why this phase, why now

Three convergent reasons:

1. **The install-friction gap is the largest moveable axis.** Today: 5-7 days from interest to first scan. Post-Marketplace: <5 minutes. Aikido's entire growth model is built on this funnel; we currently lose every "evaluate three tools" bake-off because step 1 is "install all three" and we can't be installed in 30 seconds.
2. **The 5-act demo gives us a story Aikido / Snyk can't tell.** Phase 29 Slice A (Apr 30) put the cloud tier on screen. Slice B (the next ~200 LOC commit) chains it. With the chain live, the Marketplace listing's hero moment is a real PR Check Run that links source → image → pen-test → runtime → cloud — something **no other Marketplace App can show**.
3. **GitHub App primitive is already scoped (Phase 22.5).** We're not building from zero. Phase 22.5 was scoped for GHES procurement-unlock; Phase 22.6 reuses that primitive for Marketplace distribution. ~80% of the GitHub App engineering is shared.

---

## What "Marketplace launch" actually means (specific scope)

GitHub Marketplace has two listing types. Phase 22.6 ships the App, defers the Action.

| Type | Scope | Status in this phase |
|---|---|---|
| **GitHub App** | Installed by an org admin; integrates with PRs / issues / Check Runs / deployments via webhooks + the Apps API | ✅ Primary scope |
| **GitHub Action** | Published as a reusable workflow step; users add it to their `.github/workflows/*.yml` | 🟡 Deferred to Phase 22.7 — runs in their CI, doesn't pull our platform value; ship after the App is established |

The App scope below assumes the platform stays the value surface. Action scope (post-22.6) is "headless scanner runs in customer CI; results POST back to platform for chain analysis."

---

## Slice plan (suggested commit shape)

| Slice | Commits | LOC | Effort | What it ships |
|---|---|---|---|---|
| **A** | 4-6 | ~600 | 2 days | Phase 22.5 (GitHub App + GHES) — also unblocks non-Marketplace customers |
| **B** | 3-4 | ~500 | 3 days | PR Check Run integration with diff-line annotations |
| **C** | 5-7 | ~1,200 | 1 week | Hosted SaaS deployment (multi-tenant, single-region, with proper org isolation) |
| **D** | 3-4 | ~400 | 2 days | Marketplace billing API integration (handle webhooks for plan upgrades/downgrades) |
| **E** | — | — | 1 week | Listing assets + ToS / privacy policy / support page / pricing page / demo video |
| **F** | — | — | 2-4 weeks **wait** | GitHub Marketplace security review (their pace, depends on permissions requested) |

**Total realistic timeline:** 6-8 weeks of focused work + 2-4 weeks of GitHub review wait time = **~10-12 weeks from kickoff to public listing**.

---

### Slice A — Phase 22.5 (GitHub App + GHES support)

This is **literally** the existing Phase 22.5 plan; see [`phase-22.5-ghes-and-github-app.md`](./phase-22.5-ghes-and-github-app.md) for the full spec. Shipped here as Slice A because every subsequent slice depends on the App primitive.

Recap of what 22.5 ships:

- New `Integration.type = GITHUB_APP` with `installationId` per-org
- `services/github/githubAppService.ts` — installation token minter (mints short-lived JWT → exchanges for installation token, caches with TTL)
- Update `services/github/githubClient.ts` — resolve repo-access token via the cascade: per-repo Integration override → per-org GITHUB_APP integration → per-user OAuth token (legacy fallback)
- Optional second OAuth provider for GHES sign-in (configurable base URL)
- Update `routes/integrations/router.ts` — `PUT/DELETE /api/integrations/github-app` for the org-admin install/uninstall webhooks

Verification (from the existing 22.5 doc): `pnpm test` green; manual test against a real GitHub App installation; verify scan triggers from a webhook use the installation token, not the legacy user token.

### Slice B — PR Check Run integration with diff-line annotations

**Why it's a separate slice from 22.5:** the App primitive is generic; Check Runs are the GTM hero feature.

**What ships:**

- `services/github/checkRunService.ts` — creates / updates Check Runs on PR-triggered scans
- New BullMQ queue: `github-check-runs` (separate from scan queue so check delivery is independent of scan duration)
- Diff-line annotations: for each finding on a file in the PR diff, post an annotation at `(filePath, lineStart)` with severity-keyed icon + title + summary + link to BreachLens drawer
- Aggregate Check Run conclusion: `success` (no findings on changed lines) / `neutral` (findings exist but no policy violation) / `failure` (policy violation)
- Policy gate scaffold (full policy engine is Phase 17-ish): default-allow with a "block on CRITICAL+EXPLOIT_CONFIRMED" toggle per org

**Files to touch:**
- `apps/api/src/services/github/checkRunService.ts` (new, ~200 LOC)
- `apps/api/src/workers/checkRunWorker.ts` (new, ~150 LOC)
- `apps/api/src/routes/webhooks/github.ts` (extend — listen for `pull_request.opened` / `synchronize` / `reopened`)
- `apps/api/src/queues/definitions.ts` (extend — add the new queue)
- `packages/types/src/api.ts` (extend — `CheckRunPayload`, `CheckRunPolicy`)

**Verification:**
- Open a PR on a connected test repo with a known-vulnerable commit; verify the Check Run appears within ~30s of push
- Annotation lands on the right line of the right file
- Re-push to the PR → Check Run updates (not a duplicate)
- Policy violation → conclusion = `failure`; clean PR → conclusion = `success`
- Admin toggles policy off → next PR is `neutral` not `failure`

**Why this is the demo moment:** every screenshot for the Marketplace listing comes from this slice. The "BreachLens vs. Aikido" comparison post is built on side-by-side Check Run screenshots. **Don't ship Slice E without Slice B working.**

### Slice C — Hosted SaaS deployment

**This is the slice with the highest variance in effort.** The platform was designed single-tenant self-host; Marketplace requires multi-tenant SaaS. The org-isolation work matters more here than anywhere else in the codebase.

**Audit checklist (must do BEFORE Slice C ships):**

1. **Every list endpoint scopes by `orgId`** — ✅ already enforced via `getActiveMembership(req)` per `breachlens-sso-and-orgs.md` memory. Re-verify with parity test.
2. **Every cross-org bridge edge stops at the Application boundary** — ✅ already enforced per Phase 27.5 (`runCorrelationForApplication(orgId, appId)`). Re-verify the boundary holds for runtime + cloud bridges added since.
3. **AES-256-GCM encryption per-org for integration credentials** — ✅ already in `encryptionService.ts`. Verify `ENCRYPTION_KEY` is scoped per-deployment, NOT shared across customer tenants in any code path.
4. **Postgres RLS** — currently NOT enforced; we rely on application-level scoping. Decide: add Postgres RLS as defense-in-depth (~3 days), or accept app-level-only (faster, more risk). **Recommendation: add RLS** — multi-tenant SaaS without DB-level isolation is one bug from a cross-tenant data leak.
5. **BullMQ queue isolation** — jobs carry `orgId`; verify worker can't accidentally cross-pollute when error-handling.
6. **Audit log per-org** — already exists; verify access controls (admin of org X can't read org Y audit log).

**Infra surface to ship:**

- Single-region deployment (us-east or eu-west — pick one, expand later)
- Managed Postgres (RDS or Cloud SQL)
- Managed Redis
- Object storage for SBOM artifacts + scan workspaces (S3 or equivalent)
- Container orchestration (ECS / Cloud Run / Fly.io — pick the cheapest that runs Docker and handles auto-scale; **avoid Kubernetes for v1** — operational cost is wrong shape for a 1-2 person team)
- Status page (statuspage.io or equivalent)
- Monitoring: Datadog / Honeycomb / Grafana Cloud

**Pricing to expect:** ~$500-1,500/month for first 100 customers on Fly.io / Cloud Run; ~$2-3K/month at 1K customers.

### Slice D — Marketplace billing API integration

**What ships:**

- `routes/webhooks/marketplace.ts` — handles `marketplace_purchase.purchased / changed / cancelled / pending_change` events
- `services/billing/marketplaceService.ts` — maps GitHub Marketplace plans to BreachLens internal tiers (Free/Team/Business)
- Tier-gating in feature checks: `requireTier("BUSINESS")` middleware for AI verdict / correlation / etc.
- Grace period handling: cancelled customer keeps access for 30 days (their deactivation flow)

**Files to touch:**
- `apps/api/src/routes/webhooks/marketplace.ts` (new, ~150 LOC)
- `apps/api/src/services/billing/marketplaceService.ts` (new, ~150 LOC)
- `apps/api/src/middleware/requireTier.ts` (new, ~50 LOC)
- `apps/api/prisma/schema.prisma` — add `Organization.tier` enum + `marketplaceListingId` + `subscriptionStatus`
- `packages/types/src/api.ts` — `BillingTier` enum

**Verification:**
- Use GitHub's Marketplace simulator (`https://github.com/marketplace/<app>/test_purchase`) to fire fake purchase events
- Verify org tier flips correctly across all 4 lifecycle events
- Verify `requireTier` blocks Free-tier orgs from AI verdict endpoint with 402 Payment Required + clear upgrade message
- Cancellation → 30-day grace window → access cuts cleanly

### Slice E — Listing assets

Marketing work, not engineering. But it gates the listing.

**Required by GitHub Marketplace:**

| Asset | What good looks like |
|---|---|
| **Listing description** | 200 chars elevator + 1500 chars detail. Lead with "5-tier correlation chain." |
| **Hero screenshot** | The DVWA chain page with the AI verdict pill visible — operator-recognisable at a glance |
| **Feature screenshots (4-6)** | (1) PR Check Run with annotation, (2) Findings table, (3) Attack-path drawer, (4) CSPM dashboard, (5) RBAC settings, (6) SBOM download |
| **Demo video (60-120s)** | The 5-act chain narrative end-to-end. Voiceover + captions. Hosted on YouTube + embedded. |
| **Logo** | We have one. Verify renders cleanly at 24px / 40px / 96px sizes. |
| **Privacy policy URL** | New page on docs site. Cover GDPR + CCPA. |
| **Terms of service URL** | New page. Standard SaaS ToS adapted for security tool. |
| **Support page** | Email + GitHub Discussions + (eventually) an SLA matrix per tier. |
| **Pricing page** | Tier comparison table, FAQ, "contact for Enterprise" CTA. |
| **Documentation** | Polish `docs/` to operator-grade. Quickstart in <5 mins must actually work. |

**Recommended:** hire a freelance technical writer + designer for ~2 weeks ($5-8K) to do the writing + screenshot polish + video production. Engineering team's time is better spent on Slices A-D.

### Slice F — Security review

GitHub's review process. Out of our hands once submitted; their cadence is 2-4 weeks.

**What they check** (based on documented + observed-from-other-apps patterns):

- App permissions are minimised (don't ask for `admin` if you need `read`)
- App handles uninstallation cleanly (data deletion or grace-period archival)
- Privacy policy + ToS link to real pages, not placeholders
- App description is accurate (no overclaim)
- App screenshots are real product, not mockups

**Permissions we need (minimised):**

| Permission | Scope | Why |
|---|---|---|
| `metadata` | Read | List repos in installation |
| `contents` | Read | Clone repos for scanning |
| `pull_requests` | Read & write | Create/update Check Runs + post annotations |
| `checks` | Read & write | Same |
| `webhooks` | Read | List existing webhooks (avoid duplicate registration) |
| `members` | Read | Map GitHub teams → BreachLens RBAC roles (optional, can defer) |

**Do NOT request** `admin:org`, `repo` (broad), `delete_repo`, or any write that we don't actually use. GitHub's reviewers look for over-permissioning specifically.

---

## Pricing tier shape (recommended, derived from competitors)

Pulled from actual Marketplace listings of comparable security tools:

| Tier | Price | Limit | What's included |
|---|---|---|---|
| **Free** | $0 | Public repos + ≤3 private repos | SAST + SCA + Secrets only; community support; no PR Check Run annotations on private repos (just summary conclusion); 14-day finding history |
| **Team** | $99/month flat | Up to 25 private repos | All 8 scan types; PR Check Runs + annotations; Slack/Teams alerts; standard support; 90-day finding history |
| **Business** | $499/month flat | Unlimited repos | **Correlation engine + attack paths + AI verdict** (the moat); SSO; 24h response support; 1-year finding history; SBOM signing |
| **Enterprise** | Contact sales | Unlimited | Self-host option; on-premises deployment; SOC2 audit assist; dedicated success manager; custom SLA; HIPAA/FedRAMP attestations |

**Key gating decision:** **correlation engine is paid-only.** That's the moat — gating it behind Business tier is what converts free users to paid. SAST/SCA/Secrets on free tier is the loss-leader.

**Comparison to direct competitors** (rough, from public listings):
- Aikido: Free + Team $300/mo + Business $1,500/mo + Enterprise sales
- Snyk: Free + Team $25/dev/mo + Business $52/dev/mo + Enterprise sales
- Endor: Free + Pro $1,000/mo + Enterprise sales
- Apiiro: Enterprise sales only (no Marketplace tier listed)

Our flat-rate (vs per-seat) is a deliberate differentiator — most security teams hate per-seat because it disincentivizes adding more developers to the security tool.

---

## Pre-launch checklist (specific to Marketplace, different from OSS)

| # | Thing | Why it has to be done before submitting |
|---|---|---|
| 1 | **GitHub App installation flow works perfectly** | First impression — broken install = uninstalled in 5 min |
| 2 | **PR Check Run renders correctly on default-branch and feature-branch PRs** | Most demoable feature; broken Check Runs = #1 reason apps get uninstalled |
| 3 | **Sub-30-second first scan from install** | If they wait 5 min, they leave. Trim initial scan scope to a single-language SAST sweep first; full scan runs in background |
| 4 | **Demo video on listing page** | GitHub's listing page asks for it; without one, no installs |
| 5 | **Privacy policy + terms of service hosted on real URLs** | GitHub mandates these for ANY listing |
| 6 | **Support email + status page live** | Marketplace listings without support contact get rejected |
| 7 | **GDPR / DPA documentation** | EU customers will ask within 24 hours of listing going live |
| 8 | **Free-tier rate limits enforced** | Otherwise free tier becomes infinite-cost. Cap at: 100 scans/day per org, 30 min/day total scan duration |
| 9 | **App permissions documented + minimised** | Asking for `admin:org` when you need `metadata:read` = security review failure |
| 10 | **Cancellation / uninstall flow doesn't lose data** | Customer reinstalls 2 weeks later expecting their findings to be there. Implement 30-day archival, then hard-delete |
| 11 | **5-act chain demoable on a public test repo** (DVWA fork) | Listing screenshots come from here. **Hard prerequisite — if Slice B (Phase 29 Slice B) hasn't shipped, the listing under-sells.** |
| 12 | **Hosted SaaS handles 100 concurrent scans without OOM** | Run a load test before submitting. Marketplace launches typically peak in the first 48 hours. |

---

## Architecture decisions worth preserving

### Hosted SaaS vs Marketplace-pointing-to-self-host

**Decision:** Run a hosted SaaS. The self-host option remains available for Enterprise tier customers.

**Why not Marketplace-points-to-self-host:**
- Defeats the install-friction win — customer still has to deploy infra
- Aikido / Snyk / Endor all run hosted; Marketplace customers expect SaaS
- Self-host as Enterprise tier (paid) keeps the upgrade path clean

### Why correlation is paid-only (Business tier)

The bridge engine + Application boundary + AI verdict is the moat. Gating it behind a tier:

1. **Justifies the subscription** — Free tier has SAST/SCA which competitors give away too. Without a paid-tier hook, conversion is impossible.
2. **Preserves the demo moment** — when a Free user upgrades to Business, the chain "appears" in their existing data. Powerful UX.
3. **Maps to actual cost structure** — running correlation across an org's full finding history is meaningfully more compute than running individual scanners.

### Why we keep self-host even with hosted SaaS

Self-host stays as the Enterprise tier value-add for two buyer segments:

1. **Regulated industries** (defense, healthcare, finance) — where data-residency rules forbid SaaS
2. **Privacy-paranoid mid-market** — where "we never see your data" is the wedge

These segments are NOT going to install our Marketplace App. The Marketplace listing is for the dev-led adoption funnel; self-host is for the enterprise-led adoption funnel. **Both motions exist in parallel.**

### Why we don't ship the Action in 22.6

GitHub Action vs GitHub App for security tools is a recurring debate. Tradeoffs:

| Axis | App | Action |
|---|---|---|
| Where compute runs | Our infra | Customer's CI runners |
| What they pay for | Our Marketplace tier | Their CI minutes (free for OSS, $$$ at scale) |
| Where data flows | Customer → us | Stays in their CI |
| Trust signal | "We see your code" | "Your code never leaves" |

**Action ships in Phase 22.7** as a complement: Action runs scanners in customer CI, POSTs normalised findings back to platform for chain analysis. That decouples scanner-compute from platform-value, but it's net-additional engineering, not a substitute. **Defer to 22.7 to avoid scope creep.**

---

## Risk mitigations

### Risk: Security review fails or stalls indefinitely

**Mitigation:**
- Keep permissions minimised (above table) — no `admin:*` scopes
- Have privacy policy + ToS reviewed by a lawyer (~$500-1K) before submission
- Submit during weekday daytime PST so reviewers see it in their morning queue
- Have a backup plan: if GitHub stalls, list on Atlassian Marketplace (Bitbucket) or GitLab Marketplace as alternative dev funnels

### Risk: First-day load takes the hosted SaaS down

**Mitigation:**
- Pre-launch load test at 5x expected first-day install rate
- Start with conservative free-tier rate limits (can loosen later)
- Have on-call coverage for first 7 days post-launch
- Status page live BEFORE launch so customers have a place to check during incidents

### Risk: Reputation damage from a security vulnerability in BreachLens itself

**Mitigation:**
- Run BreachLens against itself before launch (eat-our-own-dogfood)
- Public `SECURITY.md` with disclosure policy + 90-day coordinated disclosure
- Bug bounty program via HackerOne ($500 + per-bug, scaling with severity)
- Pre-launch external pen-test (~$5-10K) — non-optional for a security tool

### Risk: Free tier becomes a cost sink

**Mitigation:**
- Hard rate limits at the BullMQ-queue level (not just API level) — caps actual compute
- Auto-archive inactive Free orgs after 90 days of no scans
- Stripe-backed payment failure handling: 3 attempts → grace period → archive

### Risk: Aikido or Snyk responds with a comparable feature within 6 months

**Mitigation:**
- The correlation engine + Application boundary took us 4 weeks of focused work; it would take Aikido / Snyk 6+ months because they'd need to refactor their findings tables and scan workers (which assume single-tier independence)
- The OSS-scanner stack underneath us is a structural cost advantage — Aikido / Snyk pay for proprietary scanner R&D
- Speed of execution is the response: ship Marketplace + Phase 29 Slice B + AWS support before they can react

---

## Post-launch metrics to track

| Metric | Target at 30 days | Target at 90 days |
|---|---|---|
| Free tier installs | 50 | 500 |
| Active scans / day (any tier) | 200 | 2,000 |
| Free → Team conversion rate | 2% | 5% |
| Team → Business conversion rate | 10% | 15% |
| Median time from install to first scan | <60s | <30s |
| PR Check Run failure rate | <2% | <0.5% |
| GitHub support / issue volume | <5 / week | <20 / week |
| Net Promoter Score (in-product survey) | n/a (insufficient sample) | >40 |

**The single number that matters for Snapshot 10:** Free tier install count. If it's >500 at 90 days, the launch worked. If it's <100, something's broken (probably listing copy or first-scan UX) and a v2 launch is warranted.

---

## Verification checklist for the launch itself

When the listing goes live, verify against a fresh GitHub org (not our test ones):

1. Sign out of all BreachLens browser sessions.
2. Visit Marketplace listing as anonymous user — copy reads correctly, screenshots load, demo video plays.
3. Click "Install" — OAuth flow completes in <30 seconds.
4. App lands on a "pick repos" screen — clear copy, no GitHub-jargon-only language.
5. After picking repos, app redirects to BreachLens dashboard with the org auto-created and tier auto-set.
6. First scan auto-triggers on the first selected repo within 60 seconds.
7. Open a PR on that repo with a known finding — Check Run appears within 30 seconds, with annotation on the right line.
8. Hit upgrade-tier flow — Stripe checkout via GitHub Marketplace billing — confirm the tier change reflects in BreachLens within 60 seconds of payment confirmation.
9. Cancel via GitHub Marketplace — confirm 30-day grace period kicks in.
10. Reinstall after cancellation — confirm finding history is preserved within the grace window.

If any of those fail, fix BEFORE running paid acquisition (HN post / blog post / Twitter announcement). The listing page itself can stay live; just don't push traffic to it until the broken step is fixed.

---

## Closing thought

This is the first Phase that's primarily **distribution** rather than **capability**. Engineering effort is real (~6-8 weeks of Slices A-D) but the bigger risk surface is non-engineering: pricing, support, GDPR, security disclosure, marketing copy, GitHub review timing.

**The single decision that determines everything else:** budget for ~$10-15K of non-engineering spend (lawyer, freelance writer/designer, pen-test, monitoring) in addition to the engineering time. Trying to do this on the engineering team alone produces a sub-grade launch.

If that budget isn't available, defer Marketplace to after Phase 29 Slice C (AWS support) lands and revenue is in. **A great launch needs the supporting cast; a rushed launch wastes the launch window.**
