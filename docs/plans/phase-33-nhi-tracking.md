# Phase 33 — Non-Human Identity (NHI) tracking

**Status:** scoped, not started
**Predecessor:** Phase 29 Slice A (CSPM with Azure SP credentials in `encryptionService`) — auth scaffolding reused. Phase 22.6 (Marketplace launch) — recommended ship-after-this so customer feedback informs scope.
**Surfaced by:** end-of-session strategic conversation Apr 30 2026 about whether tracking Azure Service Principals / App Registrations is worth doing. Concluded yes — it's the **highest-leverage NEW asset class** BreachLens isn't covering, in a hot procurement category with a real OSS gap.

---

## Why NHI tracking, why this phase

The non-human-identity attack surface is the **fastest-growing breach vector in 2024–2026**:

| Real breach | What was compromised |
|---|---|
| SolarWinds / Solorigate (2020) | Compromised SP with consented Graph permissions → mass mailbox access |
| Microsoft Storm-0558 (2023) | Stolen signing key, abused via SPs to access government tenants |
| Microsoft Midnight Blizzard (2024) | Test SP with elevated perms + no MFA → exec mailbox access |
| Cloudflare Okta breach (2023) | Stolen SAML SP creds → deep platform access |

The pattern: in modern enterprises, **NHIs outnumber humans 10:1**, but IAM/IGA tools were designed for humans. Service Principals sit in a governance blind spot.

## Why BreachLens specifically should ship this

1. **Composable with what already shipped.** Phase 29 Slice A added CSPM with Azure SP credentials stored in `encryptionService`. The Microsoft Graph auth flow already exists. Adding `/servicePrincipals` enumeration reuses ~80% of the credential plumbing.

2. **Maps cleanly to the asset graph.** Phase 27 + 27.5's architecture wants assets that link to Applications and chain to findings. SP fits: SP belongs to an Application, has findings (expiring secret), bridges to CloudAccount findings (the SP's permissions amplify cloud blast radius).

3. **Attack-chain story gets richer (6-act).** Today: SAST → Container → DAST → Runtime → Cloud. With Phase 33: add `ServicePrincipal "aks-deploy-sp" has Owner on subscription + secret expires in 12 days + admin-consented Files.ReadWrite.All` → if attacker pivots from workload to this SP, blast radius expands from "this app" to "every blob in every storage account in this subscription." **SP-as-pivot-point is the most plausible escalation step in real cloud breaches.**

4. **Differentiates against the right competitors:**

   | Tier | Players | Position |
   |---|---|---|
   | **Established CIEM** (broad) | Wiz, Microsoft Entra Permissions Management (CloudKnox), Sonrai, Saviynt | Cover SPs as part of bigger CIEM. Enterprise-priced ($75K+/yr) |
   | **NHI specialists (well-funded)** | Astrix, Valence, Oasis Security, Token Security, Aembit, Permiso, Reco, Grip | Each raised $20–100M+ in 2024–2025. Pure-play SaaS, no self-host |
   | **OSS** | None mature. `roadrecon` exists for offensive recon only | **Genuine OSS gap** — mid-market self-hosted is unaddressed |

   Mid-market self-hosted with NHI tracking = a wedge the commercial players can't easily close.

---

## The 9 finding types

| Finding type | Severity rule | Why it's exploitable |
|---|---|---|
| **Expiring secret** | CRITICAL <30d, HIGH <90d | Operations break + emergency rotation invites mistakes |
| **Long-lived secret** (age > 1 year) | HIGH | Attacker dwell time; many orgs rotate but don't revoke old secrets |
| **Stale SP** (not used 90+ / 365+ days) | MEDIUM / HIGH | Owner forgot it exists; still has full perms |
| **Orphaned SP** (owner deleted) | HIGH | No accountability; common cleanup miss |
| **Over-permissioned SP** (Owner / Contributor on subscription) | CRITICAL | Compromise = total subscription takeover |
| **Admin-consented high-risk Graph perms** (Mail.ReadWrite.All, Directory.ReadWrite.All, Files.ReadWrite.All, etc.) | CRITICAL | Persistent tenant access; the Solorigate path |
| **No federated credentials configured** (uses secrets when OIDC fed-creds available) | LOW | Best-practice nudge to migrate from secrets |
| **Public client flow enabled** | HIGH | OAuth phishing path |
| **Multi-tenant + low publisher verification** | MEDIUM | Cross-tenant attack vector |

Every one of these is a finding that exists in production tenants today.

---

## Slice breakdown

| Slice | LOC | Effort | What it ships |
|---|---|---|---|
| **A** | ~150 | 4 hours | Schema (ServicePrincipal + secrets + permissions models) + new ScanType.NHI_AUDIT + auth reuse from CloudAccount |
| **B** | ~250 | 1 day | Microsoft Graph enumerator — paginates `/servicePrincipals`, `/applications`, `/appRoleAssignments`, `/passwordCredentials`, `/auditLogs/signIns` |
| **C** | ~200 | 4 hours | 9 risk-scoring rules from the table above; output as `NormalizedFinding` |
| **D** | ~300 | 1 day | UI: new "Identities" tab; per-SP drawer with permissions matrix + secrets timeline + risk score; filter by tenant/Application/risk |
| **E** | ~80 | 2 hours | Bridge plugin: ServicePrincipal ↔ CloudAccount (SP perms amplify cloud blast radius) |

**Total: ~980 LOC across ~3 focused days of work.**

### Slice A — Schema design

```prisma
model ServicePrincipal {
  id                String   @id @default(cuid())
  orgId             String
  cloudAccountId    String
  applicationId     String?  // nullable — operator declares which Application owns this SP
  tenantId          String   // Azure tenant GUID
  appId             String   // SP's appId / clientId
  displayName       String
  ownerObjectId     String?
  ownerDisplayName  String?
  ownerDeleted      Boolean  @default(false)
  createdAt         DateTime
  lastUsedAt        DateTime?  // from signInActivity (requires Entra ID P1)
  hasFederatedCreds Boolean  @default(false)
  scanJobId         String?
  cloudAccount      CloudAccount @relation(...)
  application       Application? @relation(...)
  secrets           ServicePrincipalSecret[]
  permissions       ServicePrincipalPermission[]
  findings          Finding[]
  @@unique([cloudAccountId, appId])
  @@index([orgId, applicationId])
}

model ServicePrincipalSecret {
  id          String   @id @default(cuid())
  spId        String
  hint        String        // Azure shows last 3 chars only
  startsAt    DateTime
  endsAt      DateTime      // expiry
  isActive    Boolean
  servicePrincipal ServicePrincipal @relation(...)
}

model ServicePrincipalPermission {
  id           String   @id @default(cuid())
  spId         String
  resourceId   String   // API the perm targets (e.g. Microsoft Graph)
  resourceName String   // "Microsoft Graph"
  scope        String   // "Mail.ReadWrite.All"
  type         PermissionType  // APPLICATION | DELEGATED
  consentedAt  DateTime?
  consentedBy  String?
  servicePrincipal ServicePrincipal @relation(...)
}

enum PermissionType { APPLICATION DELEGATED }
```

### Slice B — Graph API endpoints used

| Endpoint | Purpose |
|---|---|
| `GET /servicePrincipals` | List all SPs in tenant (paginate via `@odata.nextLink`) |
| `GET /applications` | List app registrations (separate from SPs — SPs are tenant-scoped instances of apps) |
| `GET /servicePrincipals/{id}/appRoleAssignments` | Application-typed Graph permissions granted to SP |
| `GET /servicePrincipals/{id}/oauth2PermissionGrants` | Delegated permissions |
| `GET /servicePrincipals/{id}/getMemberObjects` | Group memberships (for permission inheritance) |
| `GET /auditLogs/signIns?$filter=appId eq '<appId>'` | Last-used signal (requires Entra ID P1) |
| `GET /applications/{id}/passwordCredentials` | Secret expiry + creation date |
| `GET /applications/{id}/keyCredentials` | Certificate expiry |
| `GET /applications/{id}/federatedIdentityCredentials` | OIDC federation config |

**Permissions required:** `Application.Read.All` on Microsoft Graph (admin-consent only). For sign-in activity: also `AuditLog.Read.All`.

### Slice E — Bridge logic

`servicePrincipalCloudBridge`:

```typescript
// Pair: SP with high-risk findings + CLOUD finding on same subscription
// Match condition:
//   - sp.cloudAccountId === cloud.cloudAccountId
//   - sp finding severity >= HIGH (over-permissioned, expiring secret, admin-consented)
//   - cloud finding severity >= HIGH
// Confidence: LIKELY
// Reason: "SP <name> has <permission> on this cloud account; SP compromise
//          amplifies workload exploit blast radius across the subscription"
```

---

## Open design decisions

| # | Decision | Default for v1 |
|---|---|---|
| 1 | Single-tenant or multi-tenant SP coverage | **Single-tenant only**. Multi-tenant SPs (apps registered in one tenant, consented in another) → defer to Phase 33.5 |
| 2 | High-risk Graph permissions list source | **Static JSON in codebase** (~200 perms across 4 risk tiers); review quarterly. Pulling dynamically from Microsoft docs is brittle |
| 3 | Detection cadence | **24h sweep** via existing recurring BullMQ infrastructure. Faster (1h) optional via env flag. Real-time via Azure Activity Log events → Phase 33.5 |
| 4 | Behavior on 10K+ SP tenants | Paginate + worker concurrency. Not a blocker for v1; document operational expectation |
| 5 | Federated credential coverage | **YES in v1** — it's a high-value finding ("SP has secret AND no fed-cred"). +50 LOC |
| 6 | AWS / GCP NHI tracking | **Defer to Phase 33.2 / 33.3.** AWS IAM Roles + GCP Service Accounts have analogous risks but different APIs |

---

## Risks + mitigations

| Risk | Severity | Mitigation |
|---|---|---|
| **Microsoft Graph rate limits** on big tenants (10K+ SPs) | Medium | Pagination + retry-after handling + worker concurrency cap |
| **`Application.Read.All` is admin-consent only** — procurement friction | Medium | Document as a one-time tenant-admin step in onboarding; provide PowerShell script to grant + verify |
| **Hot category — Astrix/Valence might ship self-host** within 12 months | Strategic | Speed of execution; ship Phase 33 before they pivot; emphasize OSS-stack transparency they can't match |
| **Graph permissions database goes stale** | Medium | Quarterly review process; static JSON pinned by date in repo |
| **Sign-in activity requires Entra ID P1 license** (not all customers have) | Low | Graceful degradation: if P1 unavailable, surface "lastUsed unknown" instead of failing the scan |
| **False positives on "stale SP"** for legitimate disaster-recovery / break-glass identities | Medium | Allow operator to tag SPs as "intentionally idle" via `applicationId = null` + an `isBreakGlass: boolean` field. Phase 33.1 |

---

## Verification checklist

When Slice A through E ship, verify against a real tenant:

1. Schema migration applied; `npx prisma db push` clean
2. Service principal credentials set on a CloudAccount; trigger NHI_AUDIT scan
3. Verify ≥10 SPs ingested (every Azure tenant has at least this many — Microsoft Graph + first-party apps)
4. Verify each of the 9 finding types fires on a known-bad fixture SP (could create one in a test tenant)
5. Verify "expiring secret" finding fires for an SP with a secret expiring in <30 days; severity = CRITICAL
6. Open Identities tab → SP list renders + filterable
7. Open per-SP drawer → permissions matrix + secrets timeline visible
8. After Phase 27 correlation refresh: chain spanning CONTAINER + DAST + CLOUD + **SERVICE_PRINCIPAL** materializes
9. AI summary regenerates and mentions the SP leg (e.g., "SP overpermissioning amplifies the SQLi blast radius")
10. Daily recurring scan picks up new SPs (verify by manually creating a fresh SP and waiting 25 hours)

---

## Sequence with other phases

| Order | Phase | Why this order |
|---|---|---|
| 1 | Phase 29 Slice B (cloud bridges) | 5-act chain unlocks Marketplace listing |
| 2 | Phase 29 Slice C1 (GitHub Prowler provider) | Cheapest GitHub posture win |
| 3 | Phase 22.6 (Marketplace launch) | Distribution multiplier |
| 4 | **Phase 33 (NHI tracking)** | First major post-Marketplace differentiator |
| 5 | Phase 29 Slice C2 (AWS) | Multi-cloud breadth |
| 6 | Phase 33.2 (AWS NHI) | Extends Phase 33 to AWS IAM Roles |

Phase 33 sequenced after Marketplace because:
- Marketplace gives you a customer base
- Customer feedback within weeks will sharpen scope (which finding types matter most, which UI shape works)
- ~980 LOC is too much to bundle with Slice B without compromising both

---

## What to do NOW (cheap, prevents future rework)

If you want to future-proof the schema **without** building Phase 33 yet, ~5 minutes of work:

1. Add empty `ServicePrincipal` model placeholder to `apps/api/prisma/schema.prisma` (just the table, no relations yet)
2. Add stub `ServicePrincipal` interface to `packages/types/src/`
3. Add `ScanType.NHI_AUDIT` to the enum

That's it. When Phase 33 ships, the migration is non-breaking — just adds columns + relations to the existing table.

---

## Closing thought

This is the **next moat-mover after Marketplace launch**. Customer feedback from Marketplace will sharpen scope, but the data model + risk rules are stable enough to scope now. The strategic argument is strong: real procurement-relevant pain, rapid commercial growth in adjacent specialists, genuine OSS gap, composes with existing architecture, doesn't require new infrastructure.

The honest cost: ~980 LOC across ~3 focused days. Probably 4-6 weeks calendar time accounting for review + iteration + documentation. Worth it.
