# Phase 29 — Cloud Security Posture Management (CSPM)

**Status:** Slice A ✅ shipped Apr 30 2026 (Azure-only, single subscription end-to-end)
**Predecessor:** Phase 27 (Application boundary + bridge engine — Slice B will reuse). Phase 16 (compliance framework mapping — Prowler ships 12 frameworks per finding for free)

> **Note on phase numbering:** Phase 29 was originally scoped as
> "AI/LLM application security" in
> [`phase-29-ai-llm-application-security.md`](./phase-29-ai-llm-application-security.md).
> The user has redefined Phase 29 = CSPM as of Apr 30 2026; the
> AI/LLM scope still exists but should be renumbered (Phase 32?) in
> a follow-up. **All commits and post-Slice-A planning use "Phase 29
> Slice A/B/..." for CSPM.** This doc is the CSPM plan; the
> AI/LLM doc is historical.

---

## Why CSPM is the right next phase

Three structural reasons:

1. **Closes the only "F" cell on the grade-card.** Snapshot 8's grade-card had Cloud security at F — the single biggest gap vs Wiz, Prisma Cloud, and Aikido (Aikido has a basic CSPM tab). Every other dimension was at C or above. Closing F → D in one phase is the highest-leverage cell-move available.
2. **Compliance-framework moat compounds.** Prowler ships 12 framework mappings per finding (NIS2, FedRAMP, HIPAA, SOC2, PCI-4.0, ISO27001:2022, MITRE ATT&CK, CSA CCM, CCC, RBI, SecNumCloud, C5, CIS-Azure). The frameworks expand BreachLens's procurement story for EU/India/France/Germany customers without writing any compliance-mapping code.
3. **Architecture composes cleanly.** The bridge engine (Phase 27) accepts a new tier without engine changes — Slice B is just two new bridge plugins (Container ↔ CloudAccount + Domain ↔ CloudAccount) implementing the existing `Bridge` interface. The Application boundary (Phase 27.5) keeps cross-app contamination out for free.

---

## Slice breakdown

### ✅ Slice A — Azure CSPM via Prowler (SHIPPED Apr 30 2026)

**Commits:** `03fae3a` → `7385095` (14 commits, ~1,800 LOC).

**What landed:**

- **Dedicated `scanner-cspm` Docker image** — layered FROM `prowlercloud/prowler:5.25.1`. Three earlier install approaches blew up on pydantic 1.10 vs 2.x conflicts before this one landed. The Poetry venv inside the official image keeps Prowler's deps isolated from the FastAPI surface we layer on top. (See `breachlens-cspm.md` memory for the full story.)
- **`CloudAccount` schema** — new model with `provider: CloudProvider` (AZURE | AWS | GCP), `encryptedCredentials: Json` (AES-256-GCM via `encryptionService`), `subscriptionId / accountName / tenantId`. FK on `ScanJob` and `Finding`.
- **Azure SP auth flow** (`apps/api/src/services/cloud/azureAuth.ts`) — OAuth client-credentials against `login.microsoftonline.com` + ARM `/subscriptions/:id` verification. Test-connection endpoint surfaces actionable errors before a scan kicks off.
- **Prowler→OCSF→BreachLens normalizer** (`apps/scanner/scanners/cloud_azure/normalizer.py`) — extracts `risk_details` for description (impact prose, NOT check criterion); strips resource_name + subscription_name from titles via `_derive_title()`; combines `remediation.desc` + `unmapped.notes` for full remediation; surfaces 12 compliance frameworks per finding. Five iterations on operator feedback before it was acceptable.
- **CRUD routes** for CloudAccount + scan trigger + Cloud Accounts settings page UI.
- **Cloud-specific dashboard tab** with 4 stats cards (Cloud Findings / Critical+High / Resources at Risk / Cloud Accounts) + `CloudCspmWidget` (Top Affected Services bar chart + Compliance Coverage bars + Top Failing Checks with human-readable titles + ruleId subtitle).
- **Cloud-specific findings page** with cloud-shaped columns (Resource / Resource Type / Account replacing FilePath / Confidence) + cloud-only filter set (Service / Compliance / Category — replacing Confidence / Reachability / AI Suppression which don't apply to deterministic-scanner output).
- **Inline markdown renderer** (`apps/web/src/lib/inlineMarkdown.tsx`, ~30 LOC, no new deps) for Prowler's `**bold**` / `` `code` `` prose. Wired into FindingDetailDrawer at 3 sites. No-op for plain-text scanners.

**Verified end-to-end:**

- Real Azure subscription "Infrastructure Subscription" scanned in **1m21s**.
- **55 findings** (31 HIGH / 22 MEDIUM / 2 LOW) across 180 Prowler checks in 20 services.
- **12 compliance frameworks per finding** for free, including 6 NEW frameworks BreachLens didn't have before (HIPAA, FedRAMP, NIS2, CSA CCM, RBI, SecNumCloud, C5, CIS Azure Benchmark).

**Real bugs surfaced + fixed during Slice A integration** (see `breachlens-cspm.md` memory for the full list):

1. Pydantic 1.10 vs 2.x conflict killed three install approaches → solved by layering FROM official image.
2. `cloudAccountId` NULL on findings after upsert → `findingService.upsertFindings` didn't auto-handle new FK fields → fix shipped + SQL backfill on the existing 55 findings.
3. Title used OCSF `message` verbatim → operator feedback drove `_derive_title()` regex stripping resource_name + "(from\|in) subscription <NAME>" clause.
4. Description was check criterion not impact → switched to `risk_details` first.
5. Top Failing Checks click went nowhere → `ruleId` added to backend search OR clause.

---

### 🚧 Slice B.0 — Private container registry auth (ACR token + scope map)

**Status:** scoped, not started.
**Estimated effort:** ~180 LOC + ~3 hours.
**Why this ships BEFORE Slice B's bridges:** the demo end-state is "DVWA in ACR scans cleanly + chains via Slice B." Verify the **scan** works first (no bridges yet) so when Slice B's bridges fire, you know any issue is bridge logic, not registry auth. Bisects faster.

**Auth method picked: token + scope map.** Best practice for our use case:

| Method | Why we picked / didn't |
|---|---|
| **Anonymous pull** | Only works for public repos. Doesn't fit the demo. |
| **Admin user** | Single shared credential per registry; audit-trail collapses to "the registry did it." |
| **Service Principal** | Couples to AD; over-permissioning easy ("Reader on subscription" = read all registries). |
| **Token + scope map** ✅ | Repository-scoped (`repositories/dvwa/content/read`), per-token password, rotate independently, named identity in Azure. **Compromise = attacker only gets the specific repos in the scope map.** Requires ACR Standard tier (~$20/mo vs Basic $5/mo); $15 delta is worth the audit story. |

**Trivy native support:** Trivy reads `TRIVY_USERNAME` + `TRIVY_PASSWORD` env vars. No custom auth code needed — just decrypt the stored token and pass through to the scanner subprocess.

**Schema additions:**

```prisma
model ContainerRegistry {
  id                   String   @id @default(cuid())
  orgId                String
  type                 RegistryType
  hostname             String           // myregistry.azurecr.io
  authMethod           RegistryAuthMethod
  encryptedCredentials Json             // AES-256-GCM via encryptionService
  createdAt            DateTime @default(now())
  containers           Container[]
  @@unique([orgId, hostname])
}

enum RegistryType       { ACR ECR GCR DOCKERHUB GHCR GENERIC }
enum RegistryAuthMethod { ANONYMOUS TOKEN SP ADMIN }
```

For ACR + token auth, `encryptedCredentials` stores:
```json
{ "tokenName": "breachlens-pull", "password": "<generated token>" }
```

**Container model gets a new optional FK:** `Container.registryId` → `ContainerRegistry`. Nullable — public images (Docker Hub, ghcr.io public) don't need a registry record.

**Files to touch:**

| File | LOC | What |
|---|---|---|
| `apps/api/prisma/schema.prisma` | ~20 | New model + FK + enums |
| `apps/api/src/routes/containerRegistries/router.ts` (new) | ~60 | CRUD routes + Zod validators (POST/GET/PATCH/DELETE) |
| `apps/api/src/services/containerRegistryService.ts` (new) | ~30 | Decrypt creds for the scan worker |
| `apps/api/src/workers/scanWorker.ts` (extend) | ~20 | Pass `TRIVY_USERNAME` / `TRIVY_PASSWORD` to scanner request when registryId set |
| `apps/scanner/scanners/container.py` (extend) | ~10 | Read env vars from request; pass through to trivy invocation |
| `apps/web/src/pages/SettingsPage.tsx` (extend) | ~50 | New "Container Registries" tab |
| `apps/web/src/pages/ContainersPage.tsx` (extend) | ~30 | Registry dropdown in Add/Edit modal |
| `packages/types/src/api.ts` + `models.ts` (extend) | ~20 | `ContainerRegistry` interface + `RegistryType` / `RegistryAuthMethod` enums |
| **Total** | **~180** | |

**Operator flow (UI):**

1. Azure portal: ACR → Repository permissions → **Scope maps** → create `breachlens-pull` with scopes like `repositories/dvwa/content/read`
2. Azure portal: ACR → Repository permissions → **Tokens** → create `breachlens-token` bound to that scope map → generate password 1 → copy
3. BreachLens: Settings → Container Registries → Add → type=ACR, hostname=`<reg>.azurecr.io`, auth=TOKEN, name=`breachlens-token`, password=`<paste>` → encrypts via `encryptionService` + persists
4. BreachLens: Container resource → select Registry from dropdown → enter `imageRef = dvwa:latest`
5. Scan triggers → scan worker decrypts creds → scanner-cspm container receives `TRIVY_USERNAME` + `TRIVY_PASSWORD` → Trivy pulls + scans normally

**Verification:**

1. Schema migration applied; `npx prisma db push` clean
2. Add a `ContainerRegistry` for an ACR with a working scope-map token
3. Add a Container pointing at `<reg>.azurecr.io/dvwa:latest` referencing that registry
4. Trigger CONTAINER scan → expect Trivy CVE findings within ~60 seconds
5. Rotate the token in Azure → verify scan FAILS with auth error (proves we're actually using the token, not falling back to anonymous)
6. Update the password in BreachLens → verify scan PASSES again
7. Audit log shows `breachlens-token` as the puller in ACR → identity is preserved

**Why we ship multi-registry-type even though we only need ACR for the demo:** the schema + UI cost is ~30 LOC additional per type vs. shipping ACR-only and migrating later. Cheaper to do all five (`ECR`, `GCR`, `DOCKERHUB`, `GHCR`, `GENERIC`) at once. The auth-method enum stays open for future per-type quirks (e.g., ECR uses STS short-lived creds, not static tokens — would need separate handling, but the schema accommodates it).

---

### 🚧 Slice B — Cross-tier bridges (Container/Domain ↔ CloudAccount)

**Status:** scoped, not started.
**Estimated effort:** ~200 LOC + ~6-8 hours. Single highest-leverage remaining play.

**What it unlocks:**

The **five-act demo narrative** end-to-end:

1. Source code (SAST flagged unsanitised input on `login.php:42`)
2. Image (Trivy flagged CVE-2026-31789 in openssl on the same container)
3. Pen-test confirmation (DAST flagged the SQLi endpoint with reproducer payload)
4. Runtime confirmation (Wazuh detected the SQL injection attack 4 minutes ago on dvwa)
5. **NEW: Cloud posture** — Prowler flagged "Storage account has shared key access enabled" on the subscription hosting the workload, AND "Network Security Group allows 0.0.0.0/0 inbound on 443" on the VNet the container is deployed to → **chains into the same `correlationGroupId` as the runtime exploit.**

**Two bridge plugins:**

| Plugin | Match key | Confidence policy |
|---|---|---|
| `containerCloudBridge` | `Container.deployedAtCloudAccountId` declared on the asset graph (Phase 27 Slice A pattern) | LIKELY when CONTAINER finding is HIGH+ AND CLOUD finding is HIGH+ on the same account; POSSIBLE otherwise |
| `domainCloudBridge` | `Domain.servesFromCloudAccountId` declared on the asset graph | Same severity gate as containerCloudBridge |

**Why severity-gated**: the `containerExposureBridge` learning from Phase 27.5.x — ungated CVE-shared bridges produced 4658 edges → 142-node mega-chain on DVWA. Severity gating both sides kept it sane. CSPM bridges should default to the same gate.

**Implementation steps:**

1. Add `Container.deployedAtCloudAccountId` + `Domain.servesFromCloudAccountId` FK fields to schema.
2. Extend `AssetLinksPanel` UI (Phase 27 Slice A) with a "Hosted in cloud account" picker on Container + Domain edit modals.
3. Implement `containerCloudBridge.ts` + `domainCloudBridge.ts` mirroring `containerExposureBridge.ts` shape.
4. Register both in `correlationService.ts`.
5. Verify on DVWA: assign the dvwa container to the Azure CloudAccount → next scan should produce a chain spanning SAST + CONTAINER + DAST + RUNTIME + CLOUD.

---

### 🚧 Slice C — Multi-cloud (AWS + GCP)

**Status:** scoped, not started.
**Estimated effort:** ~50 LOC each (AWS, GCP) + credential plumbing.

Prowler supports AWS via `--provider aws` and GCP via `--provider gcp` natively. The work is:

1. Add `AwsCredentials` + `GcpCredentials` Pydantic discriminators to `ScanRequest.cloud_credentials`.
2. Add an analogous `awsAuth.ts` / `gcpAuth.ts` to verify credentials before scan (AWS: STS GetCallerIdentity; GCP: IAM permissions on resource).
3. Plumb the credentials through to the scanner-cspm container as env vars (same pattern as `AZURE_TENANT_ID/CLIENT_ID/CLIENT_SECRET`).
4. UI: Cloud Accounts settings page already takes a `provider` discriminator; AWS/GCP forms render the right fields.
5. Normalizer reuse: Prowler's OCSF schema is identical across providers, so `normalizer.py` works as-is. Only the `evidence.cloud.*` shape needs minor tweaks (e.g. `evidence.aws.region`, `evidence.aws.accountId`, `evidence.aws.arn`).

**Sequencing rationale:** ship multi-cloud (Slice C) **before** Slice B if any sales conversations are happening with multi-cloud customers. Most CSPM buyers run multi-cloud — Azure-only is a hard gate in real bake-offs against Wiz / Prisma. Slice B (correlation chain) is more architecturally interesting; Slice C is more commercially urgent.

---

### 🚧 Slice D — Continuous monitoring (event-driven)

**Status:** scoped, not started.
**Estimated effort:** Phase 28.5-ish scope, 1-2 days.

Prowler is point-in-time. The 15-min interval scan via the existing BullMQ recurring-job infrastructure is **competitive with commercial CSPMs' actual cadence** (most operate at 5-15 min polling intervals behind their "continuous" marketing language).

**True event-driven** would need:
- Azure Activity Log → EventGrid subscription for `Microsoft.Authorization/roleAssignments/write` events
- A new `cloud-events` ingest endpoint on the API
- Targeted re-scan trigger (run only the IAM checkset, not all 180) on event arrival

Defer to Phase 28.5 unless a specific customer asks for it — interval scanning satisfies the "continuous" use case for the vast majority of IAM-monitoring scenarios.

---

### 🚧 Slice E+ — CWPP / KSPM / CIEM

**Status:** unscoped.

These are different scan-types **within** the cloud tier. Each would need:

- **CWPP** (Cloud Workload Protection) — agent-based runtime introspection. BreachLens's Wazuh tier (Phase 28) is conceptually similar; CWPP would extend it to cloud-managed workloads. Probably belongs in Phase 28.x rather than 29.
- **KSPM** (Kubernetes Security Posture) — Trivy already scans K8s manifests via `--scanners config`; we'd need to wire it through as a separate scan-type with its own normalizer. Probably ~400 LOC.
- **CIEM** (Cloud Infrastructure Entitlement Management) — already partially covered by Prowler's Entra checks (16 dedicated identity-access checks for Azure). For full CIEM (cross-account permission analysis, blast-radius mapping), would need a dedicated tool like CloudKnox or AccessAnalyzer. Probably ~600 LOC if the tool exists; unscoped if it doesn't.

These are NOT on the immediate roadmap. Slices B + C are the leverage moves; D is on demand; E+ is competitive parity work for full Wiz feature-match.

---

## Architectural decisions worth preserving

### Why a dedicated container, not a shared scanner

Three reasons (covered in `breachlens-cspm.md`):

1. **Pydantic version conflict** — Prowler's pinned 2.12.5 conflicts with the FastAPI surface's 2.7.x. Poetry venv isolation is the cleanest fix.
2. **Operational surface area** — CSPM scans take 1-2 min; bundling into the main scanner would block other scans during that window. Dedicated container = independent scaling.
3. **Image size** — `prowlercloud/prowler:5.25.1` is ~1.5GB. Bundling into the main scanner image would inflate every other scanner's deploy footprint.

**Pattern for future tools with heavy/conflicting deps**: layer FROM the upstream official image, install the FastAPI shim into system Python via `--break-system-packages`, shim the CLI via a small wrapper. Don't merge environments.

### Why the asset graph instead of CSPM-internal correlation

Prowler emits independent findings per resource with no relationship between them — "Storage account X has shared key" and "Storage account X has public blob access" are separate findings. **All cross-finding correlation goes through Phase 27's bridge engine**, not Prowler's output. This means:

- Slice B bridges (Container ↔ CloudAccount) operate on the **declared asset graph**, NOT on Prowler's resource UIDs.
- The operator declares "this dvwa container is deployed in subscription X" via the AssetLinksPanel UI; the bridge then fires on every CONTAINER ↔ CLOUD finding pair within the same Application boundary.
- This composes cleanly with the existing `containerExposureBridge` pattern.

**Lesson**: don't reinvent correlation per scan-type. Every new tier adds a new bridge plugin to the existing engine.

### Why we extract `risk_details` not `finding_info.desc`

These two OCSF fields are **completely different prose**:

- `risk_details` — "Allowing Shared Key undermines confidentiality. A leaked key grants broad read/write/delete access to every blob."
- `finding_info.desc` — "Storage accounts are evaluated for whether Shared Key authorization is disabled at the management plane."

The first is what an operator (and the AI analyst) wants to read. The second is the check criterion — useful as fallback but generates AI confusion when status=FAIL means the OPPOSITE of what the description literally says (operator feedback: "It is bad description confused AI" on a JIT finding).

**Pattern**: when a tool ships multiple description-shaped fields, default to the **business-impact** field. Use the check criterion only as fallback.

---

## Verification checklist for Slice B

When Slice B ships, verify against DVWA + Azure:

1. Apply schema migration: `Container.deployedAtCloudAccountId`, `Domain.servesFromCloudAccountId`.
2. Use the AssetLinksPanel UI to declare: dvwa container is deployed in the Azure subscription that's been scanned.
3. Trigger scans: SAST (already scanned) + Trivy CONTAINER + DAST + Wazuh RUNTIME + Prowler CLOUD.
4. Hit `/attack-paths` — top chain should now span 5 tier types (was 5 in Snapshot 8 too: SAST + DAST + PENTEST + CONTAINER + RUNTIME), but the chain should now ALSO contain CLOUD findings linked via `containerCloudBridge` edges.
5. Inspect `correlationGroupId` on a CLOUD finding — should equal the chain's union-find root.
6. AI summary should auto-mention the cloud leg: "Storage account exposure compounds the SQL injection risk by..." (test on the DVWA application with `?regenerate=true` to refresh the summary).

If any of those don't fire, the bridge plugin's match key or severity gate is wrong. Iterate.

---

## Closing thought

Slice A was **larger than scoped** (~1,800 LOC vs. estimated ~600). The bulk of the overrun was the 5-iteration normalizer pattern + cloud-specific UI shape (different columns + filters + stats cards from any other scan type). **Budget the same overrun** for Slice C if you ship AWS + GCP — each provider has its own OCSF mappings and quirks, and the normalizer will need iteration even though Prowler's OCSF schema is "identical" across providers.

Slice B is genuinely small (~200 LOC) because the bridge engine is mature. Don't over-budget it.
