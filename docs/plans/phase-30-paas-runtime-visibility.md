# Phase 30 — PaaS-native runtime visibility

**Status:** scoped, not started
**Predecessor:** Phase 28.5 (network/DB tier ingestion patterns) + Phase 28.6 (TI service + Wazuh decoder pipeline) — Phase 30 reuses both. Phase 27 (asset graph) — new asset types `PaasApp` and `ManagedDb` extend it.
**Surfaced by:** customer environment reality. Phase 28's Wazuh-agent model assumes you can install something on the host. **You can't install Wazuh on Azure App Service, AWS App Runner, Heroku, or Google App Engine.** The platform owns the runtime; you only get the logs the cloud provider chooses to surface. Phase 30 closes the visibility gap for the entire managed-runtime tier — without ever touching an agent.

---

## What's broken when "the host" doesn't exist

Phase 28 + 28.5 catch what Wazuh sees. That model breaks completely on PaaS:

| Phase 28/28.5 capability | What it needs | PaaS reality |
|---|---|---|
| Container syscall monitoring | Wazuh agent on host | ❌ no host access — Azure/AWS/Heroku own it |
| Container FIM (file integrity) | Wazuh agent on host | ❌ no host access |
| Auditd ingestion | Wazuh agent | ❌ no agent possible |
| iptables / nftables logs | Host-level firewall | ❌ no host firewall — cloud provider's NSG/SG is the boundary |
| Custom application log files via Wazuh tail | Filesystem read | ⚠️ partial — many PaaS write to stdout only |
| Container image scan (Trivy) | OCI image | ⚠️ partial — Azure App Service supports custom containers; App Service for Code has no image to scan |
| Database audit log via local file | Filesystem | ❌ Azure SQL / Cosmos / RDS write audit elsewhere |

**What PaaS DOES expose** (and Phase 30 ingests):

| Source | Equivalent to | What we get |
|---|---|---|
| **Azure App Service Diagnostic Logs** | Container stdout + access log | HTTP requests, app errors, auth failures |
| **Azure Application Insights** | APM traces + custom events | Slow queries, exceptions, dependency calls |
| **AWS App Runner / App Mesh logs** | Container stdout + envoy access | HTTP requests, service-mesh traffic |
| **AWS X-Ray** | APM | Cross-service traces |
| **GCP App Engine logs** | App stdout + admin events | HTTP requests, deploy events |
| **Heroku log drains** | App + dyno + router | HTTP, deploys, dyno lifecycle |
| **Azure NSG Flow Logs** *(already in 28.5)* | iptables/nftables equivalent | L3/L4 allow/deny |
| **Azure VNet Service Endpoints + Private Endpoint logs** | east-west traffic | Container-to-managed-service traffic |
| **AWS PrivateLink + VPC Endpoint logs** | east-west traffic | Container-to-managed-service traffic |
| **Azure Application Gateway WAF logs** *(already in 28.5)* | WAF tier | already covered |
| **Cosmos DB / Synapse / Azure DB for PostgreSQL** | DB engine logs | DB tier — not currently in 28.5's v1 scope |

So PaaS isn't "no visibility" — it's "different visibility, all log-based, no agent." Phase 30 is the integration work to make BreachLens see PaaS at the same fidelity it sees self-managed Linux.

---

## Slice plan

### Slice A — PaaS app server log ingestion (~4-5 days)

**Goal**: ingest application-tier logs from the major PaaS runtimes; surface as `Finding` rows with `scanType: RUNTIME` + `targetType: PAAS_APP`. Same Wazuh decoder pattern as Phase 28.5, but the "agent" is the cloud provider's log API.

**Source coverage for v1**:
- Azure App Service Diagnostic Logs (Storage Account → polled into Wazuh)
- Azure Application Insights (queried via Log Analytics API)
- AWS App Runner application logs (CloudWatch → polled)
- AWS App Runner access logs (CloudWatch)
- AWS X-Ray traces (X-Ray API)
- GCP App Engine request + application logs (Cloud Logging API)
- Heroku log drains (HTTPS endpoint we expose; Heroku pushes)

**Changes**:
- `apps/api/prisma/schema.prisma`:
  ```prisma
  model PaasApp {
    id              String       @id @default(cuid())
    orgId           String
    name            String
    runtime         PaasRuntime
    cloudProvider   CloudProvider
    region          String
    logSource       String        // resource ID / app URL
    sourceRepositoryId String?    // Phase 27 asset graph link
    deployedAtDomainIds String[]  // Phase 27 asset graph link
    accessibleByContainerIds String[]  // east-west neighbours
  }
  enum PaasRuntime  { AZURE_APP_SERVICE  AZURE_FUNCTIONS  AWS_APP_RUNNER  AWS_LAMBDA  AWS_BEANSTALK  GCP_APP_ENGINE  GCP_CLOUD_RUN  HEROKU  RAILWAY  RENDER }
  enum CloudProvider { AZURE  AWS  GCP  HEROKU  OTHER }
  ```
- Add `TargetType.PAAS_APP` enum value
- `apps/scanner/decoders/paas/` — Wazuh decoder XML per source above
- `apps/api/src/services/runtime/paasIngestService.ts` — pulls logs via cloud-provider APIs (Azure: Log Analytics queries; AWS: CloudWatch GetLogEvents; GCP: Cloud Logging entries.list); transforms into Wazuh-event format then through the existing ingest pipeline
- Hourly aggregation per `(paasAppId, eventCategory)` to control finding volume
- Detection rules ride on existing patterns: HTTP 5xx spikes, auth failure brute-force, exception bursts, deploy-event correlation

**Verify**: deploy a sample app to Azure App Service with a forced 500 error endpoint; within 90s a finding appears tagged `paas.app.error-burst` linked to the PaasApp asset.

---

### Slice B — Extended managed DB coverage (~3-4 days)

**Goal**: extend Phase 28.5 Slice C beyond RDS/Aurora/Azure SQL to the managed DBs that didn't make v1: Cosmos DB, Synapse, Azure Database for PostgreSQL, Snowflake, BigQuery.

**Why these specifically**:
- **Cosmos DB**: NoSQL semantics differ from RDBMS — "bulk result" anomaly threshold needs RU-based rather than row-based detection
- **Synapse / BigQuery**: data warehouse query patterns; per-query cost is the anomaly signal (a runaway query can cost $thousands)
- **Azure Database for PostgreSQL**: pgaudit equivalent through Azure Monitor instead of self-managed log file
- **Snowflake**: query history + access history APIs

**Changes**:
- `apps/scanner/decoders/database/` — extend with: cosmos-db.xml, synapse.xml, azure-postgres.xml, snowflake.xml, bigquery.xml
- `apps/api/src/services/runtime/dbIngestService.ts` — extend with cloud-provider API pollers (Azure Monitor for Cosmos/Synapse/PG; Snowflake Account Usage views; BigQuery INFORMATION_SCHEMA.JOBS)
- Engine-specific anomaly rules:
  - Cosmos: `db.cosmos.ru-spike` (RU consumption × 10 baseline) instead of row-count
  - Synapse / BigQuery: `db.warehouse.query-cost-anomaly` (estimated cost > $X threshold, configurable)
  - Snowflake: `db.snowflake.warehouse-suspended-then-resumed` (suspicious resume outside business hours)
  - Add `db.azure-pg.role-assumption` for the Postgres-on-Azure variant
- Extend `enum DbEngine` from Phase 28.5:
  ```prisma
  enum DbEngine {
    MYSQL POSTGRES MARIADB MONGODB AURORA RDS_MYSQL RDS_POSTGRES AZURE_SQL  // existing
    COSMOS_DB SYNAPSE AZURE_POSTGRES SNOWFLAKE BIGQUERY  // new
  }
  ```

**Verify**: a Cosmos DB query consuming 50,000 RUs (vs 500 RU baseline) → finding `db.cosmos.ru-spike` within 60s.

---

### Slice C — Cloud-native east-west traffic visibility (~3-4 days)

**Goal**: catch container-to-managed-service traffic that the perimeter firewall (Phase 28.5 Slice A) doesn't see. PaaS apps frequently talk to managed services via VNet Service Endpoints / Private Endpoints / PrivateLink — that traffic stays inside the cloud provider's network and is invisible to traditional egress firewalls.

**Source coverage for v1**:
- Azure VNet Service Endpoints + Private Endpoint diagnostic logs
- Azure Front Door access logs (public-edge ingress)
- AWS PrivateLink endpoint logs (CloudWatch)
- AWS VPC Endpoint policy denials
- GCP Private Service Connect logs

**Changes**:
- `apps/scanner/decoders/cloud-network/` — decoder XML per source
- New `Finding` subtypes:
  - `cloud-network.private-endpoint.unauthorised-source` — container hits a private endpoint it shouldn't have access to
  - `cloud-network.exfil-via-storage-endpoint` — outbound to attacker-controlled storage account via Service Endpoint (bypasses perimeter egress)
  - `cloud-network.lateral-movement-detected` — east-west traffic between containers that have no business-logic reason to communicate (heuristic: traffic between containers with disjoint repository sources)
- New Phase 27 bridge: `cloudEastWestBridge` — links a private-endpoint traffic event to source PaasApp/Container + destination ManagedDb/CloudResource
- Phase 27 attack-path scoring: paths involving an east-west exfil get the `proofMultiplier` boost (these are the hard-to-detect attack patterns; high-confidence when caught)

**Verify**: from a PaaS app, attempt to access a Cosmos DB account in a different VNet; finding `cloud-network.private-endpoint.unauthorised-source` appears within 60s.

---

### Slice D — PaaS-aware Phase 27 asset graph + UI surface (~2-3 days)

**Goal**: register `PaasApp` + `ManagedDb` in Phase 27's graph; reuse existing bridges with PaaS-source semantics; add PaaS tab to the Network page.

**Changes**:
- `apps/api/src/services/correlation/` — extend bridges from 28.5 + 28.6 to recognise PaaS sources:
  - `firewallTrafficBridge` already works (NSG flow logs) — confirm coverage
  - `wafBypassBridge` extends to App Gateway WAF (Azure) — already in 28.5, confirm App Service binding
  - `dbAccessBridge` extends to PaasApp source (the "container" in the bridge becomes either Container OR PaasApp)
  - `dnsResolutionBridge` (Phase 28.6) — add Azure DNS query log + Route53 Resolver log as sources for PaaS-app DNS queries
- `apps/web/src/pages/NetworkPage.tsx` — add "PaaS" tab alongside Firewall / WAF / DB / DNS:
  - Top: tenant-discovered PaasApp grid (one card per app) with health dot, log-source status (HEALTHY / DEGRADED / NOT_CONFIGURED), recent finding count
  - Per-app drill-down: app log timeline + Phase 27 graph snippet showing "this app's connections to your other assets"
- New onboarding flow: Settings → "Add PaaS source" wizard with cloud-provider auth (reuse Phase 18 CSPM read-only IAM patterns)

**Verify**: connect an Azure subscription with App Service → BreachLens auto-discovers app; logs flow through within 5 minutes; app appears as a node in Phase 27 attack-path graph.

---

## Effort estimate

| Slice | Lines | Time |
|---|---|---|
| A — PaaS app server log ingestion (7 source decoders + cloud-provider API pollers) | ~700 | 4-5 days |
| B — Extended managed DB coverage (Cosmos / Synapse / Azure-PG / Snowflake / BigQuery) | ~600 | 3-4 days |
| C — Cloud-native east-west traffic + cloudEastWestBridge for Phase 27 | ~500 | 3-4 days |
| D — PaaS-aware Phase 27 graph + NetworkPage PaaS tab + onboarding wizard | ~400 | 2-3 days |
| **Total Phase 30** | **~2200** | **~2-2.5 weeks** |

**Recommend ship order: A → D → B → C.** A unlocks the basic "we can see your PaaS app" story; D makes it visible in the existing graph; B and C extend depth where customer signal points.

---

## Open questions to settle before Slice A

1. **Cloud-provider API rate limits** — Azure Monitor has 25 req/sec per subscription; CloudWatch GetLogEvents has 10 TPS per stream; GCP Cloud Logging quotas vary. Polling every 60s with 100+ apps per tenant blows through quotas. **Recommend**: per-source backoff + exponential jitter + Wazuh-side aggregation when per-app polling isn't feasible (use Azure Diagnostic Settings to push logs to a single Storage Account, poll the Storage Account once).

2. **Cost of cloud-provider log APIs** — CloudWatch Logs Insights queries are billed; Application Insights has data ingestion costs. Polling aggressively can run a customer's bill up. **Recommend**: ship with "log polling rate" as an operator-configurable per-source setting (default 60s, can dial to 5min or longer); document cost implications per source.

3. **Heroku log drains require BreachLens to expose a public endpoint** — push model, not pull. That endpoint becomes an attack target. **Recommend**: ship as opt-in "Add Heroku Drain" wizard that generates a per-source secret URL; rate-limit ingestion per source; document the inbound-endpoint requirement honestly.

4. **Multi-cloud customer onboarding** — many customers run AWS + Azure simultaneously. Onboarding flow should support multiple cloud accounts per org. **Recommend**: extend Phase 18 CSPM's per-cloud-account model; one PaasApp can belong to one cloud account; org has many cloud accounts.

5. **Azure Functions / AWS Lambda — serverless vs PaaS** — same model conceptually but invocation patterns differ (cold-start metrics, per-invocation logs vs continuous app log). **Recommend**: ship with PAAS_APP coverage in v1 (long-running app servers); add `enum PaasRuntime { ... AZURE_FUNCTIONS AWS_LAMBDA GCP_CLOUD_FUNCTIONS }` value but defer serverless-specific anomaly rules to Phase 30.x — different operational model.

6. **App Service for Code vs custom container** — Azure App Service supports both. Custom container has a Docker image we could scan via Phase 28; App Service for Code has no image. **Recommend**: ship Phase 30 for both cases; for custom-container case also link Phase 28 container scan findings via the existing `Container.deployedAtDomainIds` graph edge so a single asset gets unified findings from both perspectives.

---

## Strategic position

**The big move:** PaaS adoption is huge in mid-market — companies that don't want to manage Linux. Phase 28's container-centric model means BreachLens looks great in the demo against Linux + containers and **looks blind on a real Azure App Service customer**. Phase 30 closes that credibility gap.

**Coverage matrix update (post-30):**

| Tool | Self-managed Linux + containers | PaaS app servers (App Service / App Runner / Heroku) | Managed DBs (RDS / Cosmos / Synapse) | Correlated chain across both |
|---|---|---|---|---|
| Snyk | partial | partial (SAST works) | ❌ | ❌ |
| Wiz | partial | partial | partial | ✅ cloud-only |
| Aqua / Sysdig | ✅ | ❌ | ❌ | ❌ |
| Datadog | partial | ✅ | partial | partial |
| Microsoft Defender for Cloud | partial | ✅ Azure-native | ✅ Azure-native | partial Azure-only |
| **BreachLens (post-30)** | ✅ | ✅ | ✅ | ✅ unified across both |

**Most underserved buyer:** the "we run on Azure App Service + Cosmos + we don't want to manage anything" customer. Wiz covers them on the cloud-config side but not application/runtime; Snyk covers them on SAST but not runtime; Microsoft Defender locks them into the Azure-only world. BreachLens (post-30) gives them the unified story across all clouds without forcing them to run agents they don't want.

**Composes with Phase 18 (CSPM):** Phase 18 discovers cloud resources via read-only IAM; Phase 30 adds the runtime log streams from those discovered resources. Onboarding becomes one auth flow: "give us read-only IAM, we'll scan your cloud config AND ingest your PaaS logs." Same wizard, two values.

**Honest caveats**:
- Cloud-provider log APIs cost money — document per-source costs in onboarding so customers know
- Polling latency means PaaS findings are 1-5 minutes behind real-time; less responsive than Phase 28's 60s Wazuh agent
- Some PaaS sources only emit logs hourly (some Azure resources batch their diagnostic logs); document the per-source SLA
- We don't get syscall-level visibility on PaaS — that visibility is forever lost in exchange for not managing the runtime; document the tradeoff. PaaS customers accept this implicitly when they choose PaaS
