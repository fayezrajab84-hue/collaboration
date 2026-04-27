# Phase 31 — Low-code / no-code platform security

**Status:** scoped, not started
**Predecessor:** Phase 27 (asset graph — `LowCodeFlow` is a new asset type) + Phase 16 (compliance framework — Slice E adds OWASP LCNC Top 10) + Phase 28 (Wazuh ingestion — Slice D ingests Power Platform audit logs).
**Surfaced by:** customer environment reality. Logic Apps + Power Automate + Power Apps are running in the wild; **none of the existing roadmap covers any of this**. SAST doesn't apply (workflows aren't tracked in Git). Container scan doesn't apply (no container). DAST doesn't apply (no public surface). Phase 31 is a genuinely new category, not an extension of anything we've shipped.

---

## Why low-code is fundamentally different from everything else in the roadmap

Phase 14 through Phase 30 all assume one of two things: (a) the security artifact lives in Git as code, or (b) the security artifact runs as an OS-level workload. Low-code platforms violate both:

- **Logic App definitions** are JSON workflow templates stored in Azure, **not in Git** unless the team explicitly chose Azure Resource Manager / Bicep export
- **Power Automate flows** live in the Power Platform tenant; only visible via Power Platform admin APIs
- **Power Apps** are XML/YAML (msapp format) inside the tenant; same access pattern
- **Power BI dataflows** are model definitions; same pattern
- **Salesforce Flows / ServiceNow Workflows / Workato recipes** all follow the same pattern: tenant-resident, admin-API-accessible, not Git-tracked

**Citizen developers** — the people building these — are usually NOT in IT or Security. The HR team, the Finance team, the Marketing team build flows. They have legitimate business reasons. They just operate completely outside the SDLC governance that Phases 13-30 assume. Microsoft estimates 60% of new business apps in 2026 will be built on low-code platforms; the security organisation has **no visibility into 60% of new apps being built in the company**.

The connector ecosystem is the security surface:
- Power Platform has **1,000+ connectors** (Office 365, SharePoint, Dataverse, SQL, Salesforce, Twilio, custom HTTP, custom Azure Functions, …)
- Each connector has its own scope (often configurable, often not configured tightly)
- Flows compose multiple connectors — a single flow might read from SharePoint, transform via Office 365 AI Builder, write to Dataverse, send via Outlook
- **The flow runs as the creator's identity** by default — the creator's permissions, the creator's blast radius — even when triggered by anyone else

**Common attack patterns specific to low-code:**

| Pattern | Example | Why it's hard to catch |
|---|---|---|
| **Over-permissive connector scope** | `Office 365 Users: User.ReadWrite.All` granted when flow only needs `User.Read` | Connector scopes aren't visible in flow definitions; require Graph API enumeration |
| **Missing approval gates** | "Delete user" action with no approval step in front | Workflow logic — needs static analysis of the JSON definition |
| **Hardcoded secrets in flow definitions** | API key in a "Compose" action's JSON | Secrets scanning needs to walk the flow's JSON for hardcoded values |
| **Exposed HTTP triggers** | Logic App with public HTTP trigger and no auth | Tenant-wide configuration check |
| **Citizen-built data exfil** | Flow reads SharePoint daily, sends CSV to Gmail | Looks like normal flow activity unless you compare destination to allowlist |
| **Malicious template adoption** | Pre-built Power Automate template with backdoor connectors | Supply chain — needs allowlist/denylist of templates |
| **Privilege escalation via service principal** | Flow uses application-level (not user-level) Office 365 connector with admin scope | Common misconfiguration; invisible without tenant-wide enumeration |
| **DLP policy evasion** | Flow chains "trusted" + "untrusted" connectors to bypass single-connector DLP rule | Microsoft's own DLP works per-connector; cross-connector flow analysis is harder |

**Where the existing market sits:**
- **Zenity** — direct competitor, raised $38M Series B in 2024 specifically for low-code security. Strong on Power Platform; expanding to Salesforce + ServiceNow
- **Microsoft Defender for Cloud Apps + Power Platform Center of Excellence** — Microsoft's own answer; technically capable but most customers find the deployment + admin overhead too high
- **Salesforce Shield** — Salesforce's first-party answer for Salesforce Flows; doesn't extend across platforms
- **No DevSecOps platform covers this today** — Snyk, Wiz, Aikido, Aqua all silent

---

## The killshot demo Phase 31 unlocks

```
[Static finding, 4 months ago]
   Power Automate flow "HR-onboarding-automation" (created by Sarah J., HR team)
   ├─ Connector 1: Office 365 Users (scope: User.ReadWrite.All — over-permissive,
   │              flow only needs User.Read.All)
   ├─ Connector 2: SharePoint (scope: Sites.FullControl.All — over-permissive)
   ├─ Connector 3: Outlook (scope: Mail.Send)
   └─ Trigger: HTTP request (public URL, NO authentication)

[Phase 27 graph shows]
   This flow's connectors reach:
   - Microsoft 365 tenant user directory (~12,000 users)
   - SharePoint site "HR-Confidential" (contains 47,000 employee records)
   - All Outlook mailboxes in tenant

[Runtime audit log, this morning at 09:14]
   Flow triggered by external IP 185.x.x.x (URLhaus MALICIOUS, NRD 4 days)
   Flow runs as Sarah J.'s identity
   Reads 47,000 records from "HR-Confidential" SharePoint site
   Sends via Outlook to: external-attacker-gmail@gmail.com
   Total exfil: 14 MB

🔴 ATTACK PATH CONFIRMED:
   Citizen-developer flow + over-permissive connectors + exposed HTTP trigger
   = mass HR data exfil via Microsoft's own infrastructure.
   Sarah didn't write the malicious flow — she wrote a legitimate flow with
   over-broad scopes. The attacker hit the public trigger and rode her permissions.
   Recommended: disable the flow immediately; rotate Sarah's MFA; investigate
   whether 185.x.x.x discovered the trigger URL by enumeration or insider leak.
```

That story is invisible to every other security tool the customer owns. The CISO's first awareness is when 47,000 employee records show up on a paste site. Phase 31 catches the flow + its over-permissive connectors **months before** the attacker finds it.

---

## Slice plan

### Slice A — Power Platform tenant connection + asset enumeration (~3-4 days)

**Goal**: connect to a customer's Microsoft 365 tenant; enumerate all Logic Apps, Power Automate flows, Power Apps, and Power BI dataflows; build the foundational `LowCodeFlow` asset inventory.

**Changes**:
- `apps/api/prisma/schema.prisma`:
  ```prisma
  model LowCodeFlow {
    id                String         @id @default(cuid())
    orgId             String
    platform          LowCodePlatform
    flowType          FlowType
    externalId        String         // Power Platform flow ID / Logic App resource ID
    name              String
    creatorIdentity   String         // user UPN or service principal
    creatorIsCitizen  Boolean        @default(true)  // true if creator NOT in IT/Security AAD groups
    triggerType       TriggerType
    triggerExposure   TriggerExposure
    state             FlowState
    connectorRefs     Json           // [{name, scope, classification, riskScore}]
    blastRadiusScore  Int
    blastRadiusSummary String
    discoveredAt      DateTime       @default(now())
  }
  enum LowCodePlatform { POWER_AUTOMATE  AZURE_LOGIC_APPS  POWER_APPS  POWER_BI  SALESFORCE_FLOW  SERVICENOW_WORKFLOW  WORKATO  ZAPIER  CUSTOM }
  enum FlowType         { CLOUD_FLOW  DESKTOP_FLOW  BUSINESS_PROCESS  CANVAS_APP  MODEL_DRIVEN_APP  DATAFLOW }
  enum TriggerType      { MANUAL  SCHEDULED  HTTP_REQUEST  EVENT_GRID  WEBHOOK  RECORD_CREATED  RECORD_UPDATED  CUSTOM }
  enum TriggerExposure  { TENANT_ONLY  AUTHENTICATED  PUBLIC  UNKNOWN }
  enum FlowState        { ENABLED  DISABLED  SUSPENDED  ORPHANED }
  ```
- New `IntegrationType.POWER_PLATFORM` for the tenant auth credential storage (extends the AES-256-GCM encrypted `Integration` table from Phase 9)
- `apps/scanner/scanners/lowcode/power_platform.py` — new scanner using Microsoft Graph + Power Platform Admin APIs:
  - `GET /admin/environments` — enumerate Power Platform environments
  - Per environment: enumerate flows, apps, connectors via Power Platform Admin REST + Power Platform CLI APIs
  - For Logic Apps specifically: Azure Resource Manager `Microsoft.Logic/workflows` enumeration (extends Phase 18 CSPM patterns)
  - Map each flow's creator to the AAD user; classify creator-is-citizen via AAD group membership (configurable: by default, anyone NOT in IT/Security/Engineering AAD groups is "citizen")
- Read-only auth scope: `Microsoft Graph: User.Read.All`, `Power Platform: PowerAppFlow.Read.All`, `Azure Resource Manager: read on Logic App resource group`. No write scopes — BreachLens never modifies a flow

**Verify**: connect a Power Platform tenant → BreachLens enumerates all flows + apps within 5 minutes; UI shows flow inventory with creator + trigger + state per row.

---

### Slice B — Connector permission analysis + blast-radius scoring (~4-5 days)

**Goal**: for each enumerated flow, parse the connector list; classify scope per connector; quantify blast radius; flag over-permissive flows. Same conceptual pattern as Phase 29 Slice D's agent permission analysis — but for low-code connectors instead of AI agent tools.

**Changes**:
- `apps/scanner/scanners/lowcode/connector_classifier.py` — connector scope classification per major connector type:
  - **Office 365 Users**: `User.Read` (low) → `User.ReadBasic.All` (medium) → `User.Read.All` (high) → `User.ReadWrite.All` (CRITICAL)
  - **SharePoint**: `Sites.Read.All` → `Sites.ReadWrite.All` → `Sites.Manage.All` → `Sites.FullControl.All`
  - **Outlook**: `Mail.Read` → `Mail.Send` → `Mail.ReadWrite` → `Mail.ReadWrite.Shared`
  - **Dataverse**: per-table read/write/delete + system administrator role check
  - **HTTP**: per-target-URL classification (allowlist of trusted endpoints; flag if target is external + unrestricted)
  - **SQL Server / Azure SQL**: read-only connection string vs read-write vs db_owner
  - Custom connector: parse OpenAPI definition; classify per-operation scope
- Blast-radius scoring algorithm:
  ```
  flowBlastRadius = max(connectorRiskScore for each connector) +
                    log(N affected entities)              # users / files / records reachable
                    × triggerExposureMultiplier           # public HTTP trigger = 3.0
                    × creatorIsCitizenMultiplier          # citizen-dev = 1.5
                    × (orphaned ? 2.0 : 1.0)              # orphaned flows are higher risk
  ```
- New `Finding` subtypes:
  - `lowcode.connector.over-permissive` — connector scope exceeds inferred flow needs (heuristic; ships at LIKELY confidence)
  - `lowcode.flow.public-trigger-no-auth` — exposed HTTP trigger without auth (deterministic; CONFIRMED confidence)
  - `lowcode.flow.citizen-developer-high-blast-radius` — citizen-built flow reaching > N sensitive entities
  - `lowcode.flow.orphaned-still-enabled` — flow's creator left the company; flow still runs (uses their service principal)
- Phase 27 graph integration: `LowCodeFlow` becomes a new asset node; edges to Office 365 entities (users / sites / mailboxes), Dataverse tables, Salesforce objects, etc.

**Verify**: a flow with `Office 365 Users: User.ReadWrite.All` + 12,000 users reachable + public HTTP trigger → `lowcode.flow.citizen-developer-high-blast-radius` at HIGH severity with blastRadius "can read+modify all 12,000 user records".

---

### Slice C — Flow definition static analysis (~4-5 days)

**Goal**: parse Logic App JSON / Power Automate definition exports / Power Apps msapp packages; detect security antipatterns *inside* the flow logic, not just at the connector boundary.

**Changes**:
- `apps/scanner/scanners/lowcode/flow_definition_analyzer.py` — parses each platform's flow definition format:
  - Logic Apps: standard ARM `definition` JSON — actions, triggers, parameters
  - Power Automate: same JSON schema (Logic Apps and Power Automate share the engine)
  - Power Apps: msapp ZIP → YAML controls + formulas
  - Salesforce Flow: XML metadata
- Detection rules:
  - **Hardcoded secrets**: API keys / connection strings / OAuth tokens embedded in `Compose` actions or Power Apps formulas (uses TruffleHog regex packs we already ship)
  - **Missing approval gate before destructive action**: actions tagged `Delete*` / `Remove*` / `Send*` (mass mail) without an `Approval_Wait` step preceding
  - **Output passed to dynamic content without sanitization**: HTTP response → SharePoint write without escape; common XSS-via-flow pattern
  - **Cross-connector data flow without DLP label**: data read from "Confidential" SharePoint flowing to "Personal" Outlook violates Microsoft's per-connector DLP policy class (these classes ship in Power Platform; we cross-reference flow data path against them)
  - **Run-as-creator with admin connector**: flow uses application-level connector (admin scope) but runs as the creator's user identity — privilege escalation pattern
  - **Tight loop without throttle**: flow with `Apply_to_each` over large dataset can ramp up cost-DOS; pattern caught + flagged
- New `ScanType.LOW_CODE` value
- Findings tagged with CWE mappings so Phase 16 + Slice E's OWASP LCNC framework auto-routes them

**Verify**: a Power Automate flow with hardcoded `Authorization: Bearer eyJ...` in a `Compose` action → finding `lowcode.secret.hardcoded-bearer-token` mapped to OWASP LCNC LCNC-04 Authentication & Secure Communication Failures.

---

### Slice D — Runtime audit log ingestion + anomaly detection (~3-4 days)

**Goal**: ingest Power Platform + Logic Apps runtime audit logs into Wazuh; detect anomalous flow runs (unusual triggers, unusual destinations, unusual volumes).

**Changes**:
- `apps/scanner/decoders/lowcode/` — Wazuh decoder XML for:
  - Power Platform audit logs (Microsoft 365 Unified Audit Log filtered to `Workload=PowerPlatform`)
  - Azure Logic Apps run history (Azure Monitor Activity Logs)
  - Power Apps usage telemetry
- `apps/api/src/services/runtime/lowCodeIngestService.ts` — pulls audit data on a 5-minute cadence; transforms to Wazuh-event format
- Anomaly rules:
  - **Trigger from new IP**: HTTP-triggered flow invoked from an IP not seen in last 30 days for this flow
  - **Trigger from TI-listed IP**: integrates Phase 28.6 `tiService` — flow trigger from URLhaus/AbuseIPDB-listed source = HIGH severity finding
  - **Volume spike**: flow ran 50× more than rolling-7-day-median in last hour
  - **Outbound destination not in baseline**: flow sending to email/HTTP destination it never used before
  - **Citizen-developer flow ran outside business hours**: contextual signal — citizen-built flows usually run 9am-6pm; off-hours runs warrant investigation
  - **Flow modified by non-creator**: flow definition changed by a user other than the original creator (insider-threat pattern; could be legitimate handoff or attacker pivoting)
- New Phase 27 bridge: `flowDataAccessBridge` — links a runtime flow-run finding to the flow's static finding (over-permissive connector flagged 4 months ago + flow ran today touching 47k records = chain confirmed)
- Phase 27 attack-path scoring: paths involving citizen-developer flows with high blast-radius get `proofMultiplier × 2.0` (matches Phase 28's runtime weight; high-confidence "this is the kind of attack we predicted")

**Verify**: a flow that normally runs 5×/day suddenly runs 200×/hour from a new IP → finding `lowcode.runtime.volume-spike-with-new-source` within 5 minutes.

---

### Slice E — OWASP LCNC Top 10 + CSA No/Low-Code Top 10 compliance frameworks (~1-2 days)

**Goal**: extend Phase 16's compliance system with the two low-code-specific frameworks. Procurement-RFP-ready answer the day it ships.

**Changes**:
- `apps/api/prisma/schema.prisma` — extend `ComplianceFramework` enum:
  ```prisma
  enum ComplianceFramework {
    SOC2  OWASP_TOP_10  PCI_DSS  OWASP_LLM_TOP_10  MITRE_ATLAS  // existing through Phase 29
    OWASP_LCNC_TOP_10  CSA_NLC_TOP_10  // new
  }
  ```
- Seed `apps/api/prisma/seeds/owaspLcncTop10.ts` — 10 controls mapping to OWASP Low-Code/No-Code Top 10 (LCNC-01 Account Impersonation, LCNC-02 Authorization Misuse, LCNC-03 Data Leakage and Unexpected Consequences, LCNC-04 Authentication & Secure Communication Failures, LCNC-05 Security Misconfiguration, LCNC-06 Injection Handling Failures, LCNC-07 Vulnerable & Untrusted Components, LCNC-08 Data and Secret Handling Failures, LCNC-09 Asset Management Failures, LCNC-10 Security Logging & Monitoring Failures)
- Seed `apps/api/prisma/seeds/csaNlcTop10.ts` — Cloud Security Alliance's parallel framework (slightly different categorisation; useful for customers using CSA standards)
- All findings from Slices B/C/D auto-route to the right controls via Phase 16's CWE mapping engine — no UI code change needed

**Verify**: existing Slice B findings (over-permissive connector) auto-map to LCNC-02 Authorization Misuse on the compliance dashboard with no manual operator action.

---

### Slice F — Multi-platform expansion (DEFERRED to 31.x)

Same pattern as Phase 28 Slice D / Phase 29 Slice F: built when customer asks. Order of priority:
- Salesforce Flow (next biggest install base after Power Platform)
- ServiceNow Workflow
- Workato
- Zapier (smaller business workflows; less enterprise relevance)

Each adapter is ~400-600 lines (Slices A-D need to be re-implemented per platform's specific API and definition format).

---

## Effort estimate

| Slice | Lines | Time |
|---|---|---|
| A — Power Platform tenant connection + asset enumeration (Power Automate / Logic Apps / Power Apps / Power BI) | ~600 | 3-4 days |
| B — Connector permission analysis + blast-radius scoring + Phase 27 graph integration | ~700 | 4-5 days |
| C — Flow definition static analysis (5 detection rule classes across 4 platform formats) | ~700 | 4-5 days |
| D — Runtime audit log ingestion + 6 anomaly rule classes + flowDataAccessBridge | ~600 | 3-4 days |
| E — OWASP LCNC Top 10 + CSA NLC Top 10 compliance frameworks | ~250 | 1-2 days |
| F — Salesforce / ServiceNow / Workato adapters (DEFERRED to 31.x; documented for future picker) | n/a | n/a |
| **Total Phase 31 v1 (A-E, Microsoft Power Platform only)** | **~2850** | **~3-4 weeks** |

**Recommend ship order: A → E → B → C → D.** A unlocks the inventory (the "we can see your flows" credibility). E (compliance framework — same pattern as Phase 29 Slice B) gives the procurement-RFP answer. B + C ship the static findings. D adds runtime detection last.

---

## Open questions to settle before Slice A

1. **Power Platform admin consent vs delegated permissions** — tenant connection via OAuth is straightforward but requires admin consent for the read scopes we need. Some tenants restrict who can grant admin consent. **Recommend**: ship with admin-consent OAuth flow primary; document the consent scopes in plain English so admins can review before approving; offer a fallback "manual API key" workflow for tenants where admin consent is impossible.

2. **Citizen-developer classification** — defaulting to "anyone not in IT/Security AAD groups = citizen" requires the operator to configure which AAD groups count as IT/Security. **Recommend**: ship Settings UI for "Define IT/Security groups" with sensible defaults (`Security Administrators`, `Global Administrators`, `Application Administrators`); operator can override.

3. **Connector scope inference** — saying "this flow only NEEDS User.Read but has User.ReadWrite.All" requires inferring the flow's actual usage. Static parsing of the definition catches obvious cases but heuristics won't catch every one. **Recommend**: Slice B ships at LIKELY confidence for the obvious cases; LIKELY ones get one-click suppress to "this is intentional" workflow; build the heuristic catalogue from operator suppression patterns over time.

4. **Cost of audit log ingestion** — Microsoft 365 Unified Audit Log retention costs money beyond the default 90 days; querying via Office 365 Management API has rate limits. **Recommend**: 5-minute polling interval (matches D's anomaly responsiveness); document retention costs honestly; offer "high-frequency mode" (60s polling) as opt-in for security-sensitive customers.

5. **DLP policy cross-reference** — Microsoft's own Power Platform DLP policies are configured per-environment. Slice C's "cross-connector data flow without DLP label" rule is most useful when paired with the customer's existing DLP policy. **Recommend**: Slice C ships standalone first; Slice C.1 adds DLP-policy import (read-only) as a follow-up so we can flag flows that violate the customer's OWN policies, not just generic best practices.

6. **Citizen-developer notification ethics** — when we surface "Sarah's flow is over-permissive," do we notify Sarah directly, or only IT/Security? Politically sensitive — citizen developers can feel surveilled. **Recommend**: notification routing is operator-configurable per-finding-class; ship with conservative default (notify IT/Security only; let them decide whether to escalate to the citizen developer with context).

---

## Strategic position

**Coverage matrix update (post-31):**

| Tool | Citizen-developer flow inventory | Connector permission analysis | Flow runtime monitoring | Phase 27 graph integration | Multi-platform |
|---|---|---|---|---|---|
| Snyk | ❌ | ❌ | ❌ | ❌ | ❌ |
| Wiz | ❌ | ❌ | ❌ | ❌ | ❌ |
| Microsoft Defender for Cloud Apps | partial | partial | partial | ❌ | M365 only |
| Power Platform CoE Starter Kit | ✅ inventory | ❌ | partial | ❌ | M365 only |
| **Zenity** | ✅ best-in-class | ✅ best-in-class | ✅ | ❌ | Power Platform + Salesforce + ServiceNow |
| Salesforce Shield | ❌ | ❌ | partial | ❌ | Salesforce only |
| **BreachLens (post-31)** | ✅ | ✅ | ✅ | **✅ via integration** | Power Platform v1, F deferred |

**The strategic insight:** Zenity is the best-in-class specialist (raised $38M for this category specifically) — we won't beat them on raw low-code feature depth in v1. **BreachLens's unique angle is the integration moat** — same as Phase 29 vs Lakera. Zenity reports "Sarah's flow has over-permissive connectors"; BreachLens reports "Sarah's flow has over-permissive connectors AND those connectors reach the same SharePoint site that contains the customer-data finding from Phase 16, AND the trigger IP that hit it this morning is on a TI list (Phase 28.6), AND that constitutes a data-breach pattern under SOC 2 CC7.1."

That cross-tier story closes the deal. Zenity sees flows; BreachLens sees flows-as-part-of-a-larger-attack-surface.

**The CISO conversation post-31:** "How many low-code apps are running in your tenant?" → most CISOs don't know. Phase 31 Slice A alone gives the inventory answer. Slice B gives the risk score per app. Slice E gives the compliance answer. **Slices A + E in 4-6 days each give the CISO their first credible answer to questions they can't answer today** — that's the GTM wedge.

**Composes with Phase 29 (AI agents):** Power Automate + AI Builder integrations are growing rapidly (Microsoft is pushing AI-powered low-code hard). A Power Automate flow that calls a Power Platform AI Builder model is BOTH a low-code flow (Phase 31) AND an AI agent (Phase 29). The asset graph supports both representations; bridges between them via the same `agentToolBridge` + `flowDataAccessBridge` pattern.

**Honest caveats:**
- Multi-platform expansion (Salesforce, ServiceNow, Workato) is real work — Slice F is hand-wave for v1
- Microsoft Power Platform admin consent process can take weeks at large enterprises (security review of the BreachLens app registration); document the operational lead time honestly
- Connector scope inference is heuristic — over-permissive flagging will false-positive; ship at LIKELY confidence with one-click suppress
- Citizen-developer notification ethics is a real political consideration — operator controls
- This phase is genuinely a new product surface, not an extension; the team will learn things during Slice A that change Slices B-D. Budget time for that learning
