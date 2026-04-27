# Phase 28.5 — Network + database visibility (Wazuh log sources extending the chain)

**Status:** scoped, not started
**Predecessor:** Phase 28 (Wazuh ingestion pipeline must exist) AND Phase 27 (asset graph + correlation engine — new bridges plug into it)
**Surfaced by:** end-of-session conversation. Phase 28 catches what happens *inside* the container, but the traffic path before (firewall → WAF → load balancer) and after (database) is invisible. Adding those log sources to Wazuh closes the gap so the attack chain spans every hop from `185.x.x.x` to the dumped DB row.

---

## The gap

Today the visibility BreachLens has on production traffic looks like this:

| Tier | Visible? | How |
|---|---|---|
| Internet attacker IP | ❌ | No edge log ingestion |
| Edge firewall (pfsense / iptables / AWS Security Group / Azure NSG) | ❌ | No firewall log ingestion |
| WAF (ModSecurity / AWS WAF / Cloudflare / Azure WAF) | ❌ | No WAF log ingestion |
| Load balancer (nginx / ALB / Cloud LB) | ❌ | No LB access log ingestion |
| **Container runtime** | **✅ (Phase 28)** | Wazuh syscall + FIM + command exec rules |
| Application logs | partial | Wazuh tails container stdout if configured |
| Database (MySQL / PostgreSQL / MongoDB / RDS / Aurora) | ❌ | No DB audit log ingestion |
| Outbound traffic from compromised container (C2 callback, exfil) | ❌ | No firewall egress log ingestion |

Phase 28 catches Act 3 ("shell spawned in production"). Without 28.5, the platform can't answer the natural follow-on questions:
- *Where did the attacker come from?* (no edge logs)
- *Why didn't the WAF block them?* (no WAF logs — the WAF bypass is invisible)
- *What did they actually exfiltrate?* (no DB query logs — the SELECT that dumped 50,000 customer rows is undetected)
- *Where did the data go?* (no egress logs — the outbound POST to attacker-controlled S3 is invisible)

Phase 28.5 fills all four.

---

## The killshot: WAF-bypass detection

The most valuable single use case unlocked by this phase. Every enterprise that owns a WAF lives with the same anxiety: **"is our WAF actually blocking what it's supposed to?"** WAFs go stale, rules miss new payloads, the WAF gets bypassed via header smuggling / encoding tricks. Today that anxiety has no answer — operators only know their WAF works when it's *too late* to find out it doesn't.

With Phase 28.5, BreachLens correlates WAF log entries against app-tier alerts:

| WAF said | App container saw | Verdict |
|---|---|---|
| BLOCKED | nothing | ✅ WAF working — attack stopped at the edge |
| ALLOWED (low score) | static SAST CRITICAL on same path | ⚠️ **WAF blind spot** — rule for this payload class missing |
| ALLOWED | Wazuh shell-spawn alert on same container | 🔴 **WAF BYPASSED — active exploitation** — emergency |
| BLOCKED | Wazuh shell-spawn alert on same container | 🔴 **WAF BYPASSED via second path** — investigate immediately |
| no log | Wazuh alert | 🔴 **WAF blind to this traffic entirely** — routing misconfiguration |

That third row is the one that sells this. No competitor — not Wiz, not Snyk, not Aqua, not the WAF vendors themselves — tells operators "your $100k/year WAF was bypassed at 14:32 today." This is the demo that closes deals against vendors who think they're already covered.

---

## The full chain Phase 28.5 unlocks

```
[185.x.x.x — TOR exit node, Iran]
   ↓ inbound TCP/443
[Edge firewall (pfsense / AWS SG)]
   📋 ALLOW src=185.x.x.x dst=10.0.1.5 dport=443
   ↓
[WAF: AWS WAF v2]
   ⚠️ ALLOWED — payload "1' OR '1'='1" — score 4 (threshold: 8)
   📋 BreachLens flag: WAF blind spot — known SQLi pattern, low score
   ↓
[Load balancer: ALB]
   📋 GET /vulnerabilities/sqli/?id=1' OR '1'='1 → target group app-tg
   ↓
[Container: vulnerables/web-dvwa]   *(Phase 28)*
   ⚠️ Wazuh rule 5402: /bin/sh spawned by apache2 user
   📋 MITRE T1059.004
   ↓
[Database: aws-rds-mysql-prod]   *(Phase 28.5)*
   ⚠️ MySQL audit log: SELECT * FROM users WHERE 1=1 → returned 50,234 rows
   📋 BreachLens flag: anomalous result-set size for endpoint
   ↓
[Outbound to attacker S3]
   📋 Egress firewall: ALLOW dst=evil-s3.amazonaws.com (was missing from deny list)
   ↓
[Data exfiltrated · 47 MB]
```

Every line above is a real log entry that Wazuh can ingest with the right decoder. Phase 28.5 is the integration work to make that chain reconstructable end-to-end, not the invention of new sensors.

---

## Slice plan

### Slice A — Firewall log ingestion (~3-5 days)

**Goal**: ingest L3/L4 firewall events (allow / deny / connection-tracking) into Wazuh; surface as `Finding` rows with `scanType: NETWORK`. Both inbound (attacker → infra) and outbound (compromise → C2) directions.

**Source coverage for v1**:
- pfsense / OPNsense (syslog → Wazuh)
- iptables / nftables (auditd → Wazuh — agent already running)
- AWS VPC Flow Logs (CloudWatch → Wazuh via S3 polling)
- Azure NSG Flow Logs (Storage Account → Wazuh polling)
- GCP VPC Flow Logs (Pub/Sub → Wazuh)

**Changes**:
- `apps/scanner/decoders/firewall/` — Wazuh decoder XML + rule files for each source above
- `apps/api/src/services/runtime/wazuhIngestService.ts` — new alert categories `network.firewall.inbound` / `network.firewall.outbound` / `network.firewall.threat-intel-match`
- New `Finding.evidence` fields: `srcIp`, `dstIp`, `srcPort`, `dstPort`, `protocol`, `bytes`, `firewallVerdict`
- Threat intel enrichment: `srcIp` matched against AbuseIPDB / Spamhaus / TOR exit list (Wazuh has built-in modules) → flag with reason
- Hourly aggregation per `(srcIp, dstIp, dstPort, verdict)` to control finding volume — DDoS attempts shouldn't create 10,000 findings per minute

**Verify**: trigger an outbound connection from `vulnerables/web-dvwa` to a known-bad IP; within 60s a finding appears tagged `network.firewall.outbound.threat-intel-match`.

---

### Slice B — WAF log ingestion + bypass detection (~4-6 days, the killshot)

**Goal**: ingest WAF allow/block decisions; correlate with app-tier alerts to detect bypasses, blind spots, and misconfigurations.

**Source coverage for v1**:
- AWS WAF v2 (CloudWatch Logs → Wazuh)
- Cloudflare (Logpush → S3 → Wazuh)
- Azure Application Gateway WAF (Diagnostic Logs → Wazuh)
- ModSecurity (audit log → Wazuh agent — covers self-hosted nginx + Apache)
- Akamai App & API Protector (LDS / DataStream)

**Changes**:
- `apps/scanner/decoders/waf/` — decoder XMLs for each WAF format (CRS rules, AWS WAF JSON, Cloudflare ndjson)
- `apps/api/src/services/correlation/wafBypassBridge.ts` — **new Phase 27 bridge plugin**:
  - Match key: same `(srcIp, requestPath, timestampWindow=5min)` between a WAF "ALLOWED" log and an app-tier alert (Wazuh, DAST CONFIRMED, or pentest finding)
  - Edge metadata: `bridgeType: "waf_bypass"` with WAF score, rules triggered, and "should have blocked because" reason
- New `Finding` subtype `waf.bypass.confirmed` — fires when an ALLOWED WAF entry correlates with a same-path app alert
- New `Finding` subtype `waf.blindspot.suspected` — fires when WAF logged a suspicious-looking payload below the block threshold AND a static SAST finding exists for the same code path (high false-positive risk; flagged with confidence=POSSIBLE)
- New asset type `WAF` in Phase 27's asset graph; operator declares "this WAF protects this domain" via the existing chip-editor pattern
- UI: dedicated WAF tab on the new Network page (Slice D) with bypass count + recent bypass timeline

**Why this is bigger than the other slices**: WAF bypass is the demo killshot. Worth investing the extra days to get the correlation logic right and write the operator-facing playbook ("you found a WAF bypass — here's what to do in the next 4 hours").

---

### Slice C — Database log ingestion (~3-4 days)

**Goal**: ingest DB audit + slow-query + auth logs; surface as `Finding` rows with `scanType: DATABASE`. Catches data exfiltration, credential compromise, schema tampering.

**Source coverage for v1**:
- MySQL audit log (Percona Audit Plugin / MariaDB Audit Plugin / MySQL Enterprise Audit)
- PostgreSQL pgaudit
- MongoDB audit log
- AWS RDS audit logs (CloudWatch → Wazuh)
- AWS Aurora audit logs (S3 → Wazuh)
- Azure SQL audit (Storage Account → Wazuh)

**Changes**:
- `apps/scanner/decoders/database/` — decoder XMLs per DB engine
- New alert categories: `db.auth.failure` / `db.auth.unusual-source` / `db.query.privileged-table-access` / `db.query.bulk-result-set` / `db.schema.change-outside-maintenance-window`
- Anomaly detection rules (Wazuh stateful rules):
  - SELECT returning > 10× the rolling-7-day-median row count → flag
  - Privileged user login from new geolocation or off-hours → flag
  - DROP / ALTER / GRANT outside an operator-defined maintenance window → flag
- New asset type `Database` in Phase 27's asset graph (covers both self-hosted DB containers AND cloud-managed via Phase 18 CSPM RDS/Aurora discovery)
- New Phase 27 bridge plugin `dbAccessBridge`:
  - Match key: `(srcIp, timestampWindow=10s)` between an app container's outbound connection log and a DB query log → links app finding to DB finding
  - Same-IP-different-app-than-expected → flag as "unauthorised DB access"

**Verify**: trigger SELECT * FROM users on the DVWA MySQL container; finding appears tagged `db.query.bulk-result-set` if result > median × 10.

---

### Slice D — Network-tier asset model + correlation bridges (~3-4 days)

**Goal**: extend Phase 27's asset graph with the new asset types, wire all bridges into the correlation engine, ship the unified Network page.

**Changes**:
- `apps/api/prisma/schema.prisma` — new asset models, all org-scoped:
  ```prisma
  model Firewall   { id String @id; orgId String; name String; type FirewallType; protectedDomainIds String[]; protectedContainerIds String[]; logSource String }
  model Waf        { id String @id; orgId String; name String; type WafType; protectedDomainIds String[]; logSource String }
  model LoadBalancer { id String @id; orgId String; name String; backendContainerIds String[]; logSource String }
  model Database   { id String @id; orgId String; name String; engine DbEngine; selfHostedContainerId String?; cloudResourceId String?; accessibleByContainerIds String[]; logSource String }

  enum FirewallType { PFSENSE  IPTABLES  AWS_SG  AZURE_NSG  GCP_FW  PALO_ALTO  CHECKPOINT  CUSTOM }
  enum WafType      { AWS_WAF  CLOUDFLARE  AZURE_WAF  MODSECURITY  AKAMAI  IMPERVA  CUSTOM }
  enum DbEngine    { MYSQL  POSTGRES  MARIADB  MONGODB  AURORA  RDS_MYSQL  RDS_POSTGRES  AZURE_SQL  CUSTOM }
  ```
- `apps/api/src/services/correlation/` — all new bridges from Slices A-C registered with Phase 27's engine:
  - `firewallTrafficBridge` (firewall log ↔ container by `dstIp` + `dstPort`)
  - `wafBypassBridge` (Slice B)
  - `dbAccessBridge` (Slice C)
  - `egressC2Bridge` (outbound firewall log ↔ Wazuh container alert by `srcIp` + timestamp window — flags compromise + exfil paths together)
- Phase 27 `attackPathService.ts` — add `entryNode` detection: paths starting at a firewall ingress event with public-internet source IP get the `externalReach=1.0` multiplier (currently only DAST entry nodes get the boost)
- `apps/web/src/pages/NetworkPage.tsx` — new top-level nav between Runtime and Compliance:
  - Top: tier-by-tier health row (Firewall · WAF · LB · App · DB) with green/red dots and recent-event count per tier
  - Per-tier sub-tabs with filterable event tables
  - "WAF Bypasses" section pinned at top — count, sparkline, recent-bypass list with severity
- Phase 27 graph view: each new asset type gets its own node icon (firewall = shield, WAF = filter, LB = arrows, DB = cylinder); edges between tiers labelled by bridge type

---

## Effort estimate

| Slice | Lines | Time |
|---|---|---|
| A — Firewall log ingestion (5 source decoders + Wazuh rules + threat intel enrichment) | ~700 | 3-5 days |
| B — WAF log ingestion + bypass detection bridge (5 source decoders + correlation logic + dedicated UI tab + playbook) | ~900 | 4-6 days |
| C — Database log ingestion + DB asset type + dbAccessBridge (6 engine decoders + anomaly rules) | ~700 | 3-4 days |
| D — Network-tier asset model + Phase 27 wiring + Network page UI | ~700 | 3-4 days |
| **Total Phase 28.5** | **~3000** | **~3-4 weeks** |

**Note on incremental shipping**: Slices A-C are independent. A customer who only has WAF logs benefits from Slice B alone; a customer who only has DB logs benefits from Slice C alone. Slice D is the unifying UI but each individual slice produces value standalone. **Recommend ship in B → C → A → D order** — Slice B (WAF bypass) is the demo killshot, ship that first to validate the architecture; D collects them under one navigation last.

---

## Open questions to settle before Slice B (the first slice)

1. **Operator declaration of tier topology** — for the bypass detection to work, BreachLens needs to know "WAF X protects domain Y which routes to container Z." Phase 27's chip-editor pattern handles this for repo→container→domain; Phase 28.5 extends with firewall→domain, WAF→domain, DB→container relations. Same UI pattern, just more asset types. **Confirm: same chip-editor pattern, not a separate "topology builder" flow.**

2. **Time-window tolerance for cross-tier correlation** — WAF logs an event at `T`; app-tier alert fires at `T + N`. What's the right window? Too tight (1 sec) misses real bypasses on slow apps; too loose (5 min) creates false positives during traffic spikes. **Recommend**: 5-second default, configurable per-org, with `bridgeMatch.confidence` decreasing as the gap widens. Surface the gap in the path detail UI so operators can judge.

3. **Cloud-managed DB visibility** — RDS audit logs cost money to enable + ship to CloudWatch + poll into Wazuh. Some customers will balk at the bill. **Recommend**: degrade gracefully — if RDS audit logs aren't enabled, surface that as a "Phase 28.5 not fully active for this DB; enable RDS audit logs to complete coverage" message on the Database asset card. Don't pretend we have visibility we don't.

4. **WAF bypass false-positive rate** — Slice B's bypass bridge will fire false positives during legitimate testing (red team, pentest, BreachLens's OWN active scan). Need to suppress when the source IP matches a known-test-source list (Phase 27's asset graph could carry a `Domain.allowedTestSources[]` field). **Recommend**: surface bypass findings with `confidence=POSSIBLE` initially; let operator confirm to LIKELY; auto-CONFIRMED if PENTEST finding for same path also exists.

5. **Egress visibility scope** — `egressC2Bridge` requires both inbound firewall logs AND outbound firewall logs. Many customers only forward inbound. **Recommend**: ship the bridge but degrade gracefully when egress logs are absent; surface the gap on the Firewall asset card with operator instructions.

6. **Volume + storage** — firewall + WAF + DB logs at enterprise scale = TB/day. Wazuh handles ingestion, but our `Finding` table grows fast. Phase 28's hourly-bucket fingerprint pattern is mandatory for all 28.5 slices. **Confirm**: also add a per-org log retention policy (default 90 days for runtime/network/db Findings, configurable up to 7 years for compliance customers — overlaps with Phase 22 audit retention).

---

## Strategic position

Phase 28.5 doesn't open a new category — it deepens the runtime + correlation story Phase 27 + 28 already opened. Two specific competitive moves:

**1. The WAF-bypass demo (Slice B) is unique.**
- WAF vendors don't ship cross-tier correlation — they only see their own tier
- Snyk / Aikido / Endor have no runtime story at all
- Wiz Sensor sees container behaviour but doesn't ingest WAF logs
- Aqua / Sysdig see container behaviour but don't correlate against the app-tier vulns we found statically
- **BreachLens post-28.5 is the only product where "we found SQLi statically + WAF allowed it + container shell-spawned" all light up in one chain.**

**2. The full traffic-path visibility (all four slices) closes the SOC story.**
- Phase 28 alone makes the platform appealing to a security engineer
- Phase 28.5 makes it appealing to a SOC team — they now have the same pane-of-glass for static + active + runtime + network + database that they currently piece together from 4-6 separate tools
- Doubles down on Phase 23 (SIEM bridge) — instead of pushing findings *to* a SIEM, BreachLens *becomes* the SOC console for orgs without a dedicated SIEM

**Coverage matrix update** (post-28.5):

| Tool | Static | Active | Runtime | Network | Database | Cloud | Correlated chain |
|---|---|---|---|---|---|---|---|
| Snyk | ✅ | partial | ❌ | ❌ | ❌ | partial | ❌ |
| Wiz | partial | ❌ | ✅ Sensor | partial via Cloud | partial via Cloud | ✅ | ✅ cloud-only |
| Aqua / Sysdig | ❌ | ❌ | ✅ | partial | ❌ | partial | partial |
| Splunk + WAF + DB-audit (DIY) | ❌ | ❌ | partial | ✅ | ✅ | partial | manual |
| **BreachLens (post-27 + 28 + 28.5)** | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | **✅ all six tiers** |

**Honest caveats**:
- Wazuh volume at enterprise scale needs Wazuh cluster mode (Phase 25 SaaS scale work overlaps)
- Each new log source adds operational onboarding cost — document a "supported sources" page so operators self-serve which decoders exist
- Bypass detection is a high-stakes alert — false positives erode trust fast. Slice B's `confidence=POSSIBLE` default is mandatory; never ship CONFIRMED on a single-source bypass signal
- Phase 28.5 is Wazuh-locked just like Phase 28 — multi-vendor adapters (Slice D in Phase 28's deferred scope) eventually need to cover network/DB sources too, not just runtime
