# Phase 28 — Runtime detection (Wazuh-first)

**Status (2026-04-29):** Slices A + B + emergent D + E **shipped**. Slice C **pending** (~80 LOC, ~4 hours).

| Slice | Status | Notes |
|---|---|---|
| **A** — Wazuh alert → Finding ingestion | ✅ Shipped | Wazuh deployed at `20.205.154.88` (cloud spot); agent `c0263b172aab` linked to dvwa container; 61 alert findings ingested via the indexer fetcher (`wazuhIngestService.ts`). Hourly-bucket fingerprint dedup working. |
| **B** — `/runtime` UI tab | ✅ Shipped | `RuntimePage.tsx`: Agents + Install tabs, multi-OS install snippets (Linux/Windows/Docker), agent linking modal, per-agent Reachability drawer (refactored from initial top-level tab on operator feedback — per-agent context is the natural unit). |
| **C** — `runtimeBridge` plugin for Phase 27 correlation | ✅ Shipped | The bridge plugin (`runtimeBridge.ts`, 147 LOC) was already implemented + registered in `correlationService.ts:46` from an earlier session. The actual gap discovered when "shipping the remaining part of runtime": Wazuh ingest writes findings via direct `prisma.finding.create()` rather than `findingService.upsertFindings()`, bypassing the inline correlation refresh path. **Closed in commit `0c44e6c`** — fire-and-forget `runCorrelationForOrg(orgId)` per touched org at end of `runWazuhIngestionSweep()`. Verified: top DVWA chain has 81 findings spanning 5 tier types with 1,496 runtimeBridge edges. |
| **D** *(emergent — not in original plan)* — Wazuh VD state ingest | ✅ Shipped | Wazuh 4.13 retired the manager API path `/vulnerability/<id>` (returns 404 with valid auth). New ingestor pulls from `wazuh-states-vulnerabilities-*` indexer indices. 26 vulnerabilities ingested with full enrichment (cveId / packageName / packageVersion / fixVersion / cvssScore / references). Fingerprint = SHA-256(orgId\|agentId\|cveId\|pkgName\|pkgVersion). Idempotent on re-poll. |
| **E** *(emergent — not in original plan)* — Synthesised MITRE on VD findings | ✅ Shipped | Wazuh VD docs ship zero MITRE classification. Built a 7-rule heuristic classifier (`vulnToMitre()` in `wazuhIngestService.ts`) that infers tactics/techniques from CVE description + CVSS score. Stamps `evidence.mitre.synthesized: true` + `basis` string. Dashboard MITRE chart now sees vulnerability state alongside attack events. Honest UI: dashed-border render in FindingsPage column + "Inferred from CVE — <basis>" caveat in drawer. **Standard upgrade path**: replace heuristic with CWE-driven layer (CVE→CWE from NVD + CWE→ATT&CK from MITRE) + CTID/Vulnrichment dataset for KEV-tier CVEs. ~150 LOC + ~250 LOC respectively, scoped but not built. |

**Cross-cutting work shipped in the same session** (not strictly Phase 28 but enabled by it):

- **Server-side tag system** (`services/findingTags.ts`) — 5 named predicates (`runtime-exploit` / `runtime-attack` / `runtime-vulnerability` / `confirmed-exploit` / `ai-suppressed`); same evaluator powers `/findings?tag=` and `/findings/summary/stats?tag=` for card-count ≡ destination-count parity. Replaces client-side predicate replication that drifted.
- **Tag dropdown** on `/findings` toolbar — single-select, tab-scoped.
- **Per-target dashboard filter** — combined `<details>` dropdown across repos/containers/domains.
- **Per-scanner column pivot** in FindingsPage Runtime tab — headers dual-purpose ("Attacker / Package", "Process / Version", "Hits / CVSS"); per-row branch on `f.scanner === "wazuh-vd"` swaps cell content.
- **VdDetailPanel** drawer branch — Vulnerability / Package / Fix / Timeline / synthesised MITRE / References sections instead of the empty attack-event sections.
- **4-site predicate guard parity** — `scanner === "wazuh-vd"` exclusion added to (1) server `findingTags.hasActiveAttack`, (2) server `routes/runtime/dashboard activeAttacks24h`, (3) client `lib/findings.ts:hasActiveAttack`, (4) client `wasExploitSuccessful` + `hasProofOfExploit`. Site (3) was missed initially and false-fired ATTACK on 25/26 VD findings + EXPLOIT on 11/26 (DoS-class CVEs whose synthesised tactic "Impact" matched `SUCCESS_TACTICS`); caught + fixed in same session via direct user observation. **Lesson**: any new state-class scanner needs the guard at all 4 sites in parallel — worth a parity test if a 3rd state scanner ever lands (Trivy state? OpenSCAP?).

**Predecessor:** Phase 27 (attack-path correlation) — must ship first so the runtime bridge has a correlation engine to plug into. Slice C below is a no-op without Phase 27's `Bridge` interface.

**Surfaced by:** end-of-session conversation about coverage gaps. BreachLens was exclusively *static* + *active black-box*. Runtime — what the app is actually doing in production right now — was the missing third axis. Closes the gap to CNAPP buyers (Wiz, Aqua, Sysdig) who expect runtime as table stakes, and gives the Phase 27 attack chain a fourth act: "and 4 minutes ago someone tried to exploit it in production."

---

## Original plan below — preserved for context

The slice-by-slice plan that follows was the original scope. Slices A + B
+ C are still the canonical structure; D + E (Wazuh VD state ingest +
synthesised MITRE) emerged during integration when we discovered Wazuh
4.13 had retired the manager VD API. Read the slice details below for
the design rationale; read the status table above for what's actually
shipped.

---

## The gap

Static analysis says **what *could* go wrong**. Active scanning says **what responds when probed**. Neither tells you **what's happening right now**. Concretely:

- Phase 16 compliance dashboard says "OWASP A03 violation in `login.php:42`" — the bug has existed for 6 months
- Phase 24 Proof of Exploit says "we confirmed it's exploitable with this curl" — verified at scan time, an hour ago
- **Nobody tells the operator: someone exploited that exact endpoint 4 minutes ago, here's the Wazuh shell-spawn alert, the attack came from `185.x.x.x`**

That third sentence is what runtime detection delivers. Without it, BreachLens stops at "what could happen" — runtime closes the loop to "what *did* happen."

### What's already in our stack but ungated

Wazuh is **already running** in the dev compose stack. The MCP toolkit is wired in (`mcp__wazuh__*` tools — `get_wazuh_alert_summary`, `get_wazuh_critical_vulnerabilities`, `search_wazuh_manager_logs`, etc.). The Claude assistant has visibility into Wazuh alerts; **the BreachLens product does not**. There's no `Finding` ingestion, no UI surface, no correlation. Phase 28 closes that — without building a new agent.

### What runtime gives that static doesn't

| Bug class | Static catches it? | Runtime catches it? | Example |
|---|---|---|---|
| Source-line vulnerability | ✅ (Semgrep) | partial | SAST sees `eval($_GET)`; runtime sees the eval actually firing |
| Vulnerable dependency | ✅ (Trivy) | partial | SCA sees CVE-2021-44790 in libapache2; runtime sees the vulnerable function called |
| Shell spawn in container | ❌ | ✅ Wazuh syscall rule | Container should never exec `/bin/sh`; runtime catches when it does |
| Live exploitation in progress | ❌ | ✅ | Attacker runs `cat /etc/shadow` in the compromised container |
| Crypto-miner / lateral movement | ❌ | ✅ | Suspicious outbound connection to mining pool |
| File integrity / drift | ❌ | ✅ Wazuh FIM | `/tmp/.miner` appeared in container that was clean at start |
| Authentication anomaly | ❌ | ✅ Wazuh auth log | Brute-force, geolocation jump, time-of-day anomaly |

The first two rows are where we live today. The bottom five rows are entirely greenfield — and Wazuh covers all five out of the box.

---

## Two architectural shifts runtime forces

These are bigger than the code involved; they need to be designed, not retrofitted.

### Shift 1 — Point-in-time → continuous

Today every BreachLens scan is a finite job: operator clicks Scan, BullMQ runs for 30 minutes, findings written, done. `ScanJob` has `startedAt` + `completedAt`. Runtime is the opposite: an agent runs forever, streams events 24/7, has uptime + last-heartbeat + ingestion rate.

**What needs to exist that doesn't today:**
- New `WorkloadAgent` model with `lastHeartbeatAt`, `agentVersion`, `linkedContainerId`, `status: HEALTHY | STALE | OFFLINE`
- New ingestion path that runs as a long-lived worker, not as a queue job
- New "live" UI indicator pattern — heartbeat dot, ingestion-rate sparkline, "Last alert 4 minutes ago" — visually distinct from static scan results

**What can be reused as-is:**
- The `Finding` table (each runtime alert becomes a `Finding` with `scanType: RUNTIME` + `scanner: "wazuh"`)
- The fingerprint dedup machinery (with a different fingerprint formula — see Slice A)
- The Phase 27 correlation engine (runtime alerts plug in as Phase 27 graph nodes via `runtimeBridge`)
- The compliance mapping pipeline (Wazuh's MITRE ATT&CK tags map onto our existing ComplianceControl table)

### Shift 2 — Code I read → code I instrument

Static + active analysis only need the artifact (repo, image, URL). Runtime requires deploying *into* the customer's production environment. That's an entirely new procurement conversation:

- Agent permissions (Wazuh agent runs as root, hooks auditd)
- Performance overhead (~50MB RAM per host; non-trivial on small VMs)
- Kill-switch story (if our agent crashes, does the customer's app crash with it?)
- Data residency of events (alerts contain sensitive command lines)
- FIPS compliance for the agent binary

Wiz built a $12B company partly on the *agentless* story precisely because agents are hard to sell. Phase 28 v1 piggybacks on Wazuh — customers who already run Wazuh (huge install base in regulated verticals, free + open-source) get runtime for "free." Customers who don't get to evaluate whether they want to install Wazuh, and we document that tradeoff honestly. **Slice D** (a Falco/eBPF agent for non-Wazuh customers) is deliberately out of scope for v1.

---

## Slice plan (suggested commit shape)

### Slice A — Wazuh alert → Finding ingestion (foundation, ~3-4 days)

**Goal**: poll Wazuh's alert API on a schedule, normalise alerts to `Finding` rows, dedupe by fingerprint. New findings flow through the existing pipeline (compliance mapping, notifications, SSE updates) without any other code change.

**Changes**:
- `apps/api/prisma/schema.prisma`:
  ```prisma
  model WorkloadAgent {
    id                String          @id @default(cuid())
    orgId             String
    wazuhAgentId      String          @unique
    wazuhAgentName    String
    linkedContainerId String?         // populated by Phase 27 asset graph
    status            AgentStatus     @default(HEALTHY)
    lastHeartbeatAt   DateTime?
    lastAlertAt       DateTime?
    createdAt         DateTime        @default(now())
  }
  enum AgentStatus { HEALTHY  STALE  OFFLINE  UNKNOWN }
  ```
- Add `ScanType.RUNTIME` to enum + types
- `apps/api/src/services/runtime/wazuhIngestService.ts` — pulls alerts via Wazuh REST API (the same endpoints `mcp__wazuh__*` tools use); runs as a 60-second BullMQ recurring job; transforms alerts → `Finding` rows
- **Fingerprint formula** for runtime findings: `SHA-256(orgId + wazuhAgentId + rule.id + hourBucket)` — aggregates by rule per hour to prevent 100 shell-spawn alerts from creating 100 Findings; the underlying alerts stay in `rawOutput.alerts[]`
- **Severity mapping**: Wazuh 0-15 → BreachLens severity (table doc'd in service):
  - 13-15 → CRITICAL
  - 10-12 → HIGH
  - 7-9   → MEDIUM
  - 4-6   → LOW
  - 0-3   → INFO
- Compliance mapping: Wazuh alerts include MITRE ATT&CK tags — map MITRE technique IDs → existing `ComplianceControl` rows where they overlap (T1059 Command Line → OWASP A03 + SOC2 CC6.7 + PCI Req 6.5.x)

**Verify**:
1. Trigger a Wazuh alert manually inside `vulnerables/web-dvwa` (`docker exec dvwa /bin/sh -c "echo test"` triggers a syscall rule)
2. Within 60s, a new `Finding` appears in `/api/findings?scanType=RUNTIME`
3. Re-trigger same alert in same hour bucket → `lastSeen` updates, no duplicate row

---

### Slice B — Runtime tab + live UI patterns (~3-4 days)

**Goal**: surface runtime findings + agent health in their own UI section so operators can tell at a glance "is the platform watching production right now?" Honest UI matters here — heartbeat staleness must be visible, not hidden.

**Changes**:
- `apps/web/src/pages/RuntimePage.tsx` — new top-level nav between Findings and Compliance:
  - **Top strip**: WorkloadAgent grid — one card per agent, heartbeat dot (green = HEALTHY < 2min ago, amber = STALE 2-10min, red = OFFLINE > 10min), ingestion-rate sparkline, "Last alert: 4 minutes ago" timestamp
  - **Main view**: filterable Wazuh alert table grouped by category (FIM / syscall / command exec / authentication / network anomaly / vulnerability detection)
  - Click row → opens existing `FindingDetailDrawer` (no new drawer needed; rawOutput contains Wazuh alert detail)
- `apps/web/src/components/RuntimeBadge.tsx` — surfaces on every Finding row in `/findings` for runtime-type findings: amber "Live · 4m ago" pill linking to RuntimePage
- `apps/web/src/components/AgentHealthBadge.tsx` — heartbeat dot + relative time, reused on Containers page when the container has a linked agent

**UX guardrails (from `breachlens-ux-patterns.md`)**:
- **Truth-in-advertising**: agent OFFLINE state shows specific message ("agent stopped sending events 12 minutes ago — check `/var/ossec/logs/ossec.log` on the host"), not generic "no data"
- **Empty state should reward**: zero runtime alerts in last hour for a HEALTHY agent = green "All quiet — agent watching" badge, NOT a gray dash that reads as "broken"
- **Badge meaning**: RuntimeBadge says "Live" + timestamp — explicit about freshness; SeverityBadge stays separate so the two axes don't compete on one channel

---

### Slice C — `runtimeBridge` plugin for Phase 27 correlation (~2-3 days)

**Goal**: extend Phase 27's correlation engine with a runtime-to-static bridge, so the attack-path graph gains a fourth act. A static SAST/SCA finding on a target + a runtime alert on the same target's agent → linked, attack path now reads "static CVE → confirmed exploitation in production."

**Changes** (depends on Phase 27 Slice B `Bridge` interface):
- `apps/api/src/services/correlation/runtimeBridge.ts`:
  - Match key: same `linkedContainerId` between a runtime Finding's `WorkloadAgent` and a static Finding's `Container` target
  - Confidence boost: when a runtime alert matches the SAME rule category as a static finding (e.g. SAST sqli + Wazuh "command injection detected" on same container), score multiplier increases — that's the "confirmed in prod" signal
  - Edge metadata: `bridgeType: "runtime_confirmation"`, includes timestamp of runtime alert as a "last observed" field on the path
- Update Phase 27 attack-path scoring: paths that include a runtime confirmation get `proofMultiplier × 2.0` (was `× 1.5` for PENTEST CONFIRMED). Live exploitation > scan-time CONFIRMED > theoretical.
- Update AttackPathBadge: paths with runtime confirmation render as red "Active exploitation observed" instead of "Verified."

**The demo this unlocks** (DVWA + Phase 27 + Phase 28):

```
[Internet]
   ↓  Static + DAST + PENTEST chain (Phase 27 already shows this)
[https://dvwa/vulnerabilities/sqli/?id=1]
   ├─ SAST:    low.php:6
   ├─ DAST:    reflection
   └─ PENTEST: CONFIRMED — DB extraction
   ↓
[container: vulnerables/web-dvwa]
   ├─ CVE:     libapache2 RCE
   ├─ SECRET:  hardcoded MYSQL_PASS
   └─ ⚠️  RUNTIME alert (4 min ago):
              Wazuh rule 5402 — "/bin/sh spawned by apache2 user"
              Source IP: 185.x.x.x · Geolocation: TOR exit node
              MITRE: T1059.004
   ↓  *(active exploitation observed)*
[Phase 18 cloud chain continues...]
```

That red runtime line is the killshot. No competitor pulls all four (static + active + runtime + cloud) into one chain.

---

### Slice D — Multi-vendor runtime adapters (DEFERRED to 28.x)

**Goal**: customers who already run Falco / Sysdig / Datadog Cloud Workload Security don't want a second runtime agent. Adapters that turn other vendors' alerts into BreachLens runtime Findings, same fingerprint + severity mapping pattern as Slice A.

**Why deferred**: Wazuh-only covers v1 (huge install base in regulated verticals where BreachLens already wins). Build adapters when a customer explicitly asks — order of priority: Falco (CNCF, broadest install base) → Datadog ASM → Sysdig → SentinelOne.

**Effort if/when needed**: each adapter is ~200-400 lines (the heavy lifting is normalisation, not transport — every vendor has a JSON event API).

---

## Effort estimate

| Slice | Lines | Time |
|---|---|---|
| A — Wazuh alert ingestion + WorkloadAgent model + severity/MITRE mapping | ~500 | 3-4 days |
| B — Runtime tab + live UI patterns + RuntimeBadge + AgentHealthBadge | ~600 | 3-4 days |
| C — `runtimeBridge` plugin for Phase 27 correlation engine | ~300 | 2-3 days |
| D — Multi-vendor adapters (DEFERRED to 28.x; documented above for future picker) | n/a | n/a |
| **Total Phase 28 v1 (A+B+C)** | **~1400** | **~1.5–2 weeks** |

Slice A is the killer move — once Wazuh alerts flow into `Finding` rows, the rest is integration work. Ship A first, then B gives operators the live view, then C extends Phase 27's chain to span runtime. **Together with Phase 27 this is ~4 weeks for the full unified-correlation + runtime story.**

---

## Open questions to settle before Slice A

1. **WorkloadAgent → Container linking** — Wazuh agents have a `name` (usually hostname) but no native concept of "this agent monitors this BreachLens container." Options: (a) operator declares the link in Slice A's UI ("this agent watches this container"); (b) auto-match by hostname against `Container.deployedAtDomainIds` from Phase 27's asset graph; (c) require Wazuh agent labels with our IDs. **Recommend: (a) for v1** — simplest, operator stays in control. (b) is a Phase 28.x auto-suggester.

2. **Pull vs push ingestion** — polling Wazuh's API every 60s is simple but adds latency. Wazuh supports webhook integrations (active-response) that POST to an external URL on alert. Push is more responsive but requires a public webhook endpoint with auth. **Recommend: pull-based for v1** — works in air-gapped setups, no inbound endpoint required. Push as Phase 28.x option.

3. **Alert deduplication granularity** — Wazuh emits ~100 alerts/day per agent in a busy environment. The hourly-bucket fingerprint above means a `Finding` row aggregates all matching alerts within that hour. Tradeoff: lose per-alert chronology in the row's `firstSeen` / `lastSeen`, but `rawOutput.alerts[]` preserves the underlying events for drill-down. **Confirm this is the right tradeoff before Slice A** — operator might prefer one Finding per alert with auto-status-resolved when alert ages out (more rows, clearer timeline).

4. **Alert retention vs Finding lifecycle** — Wazuh alerts age out at 30/90 days by default; BreachLens Findings live forever. Three options when a Wazuh alert is no longer queryable: (a) Finding stays as historical record, marked "alert source aged out"; (b) Finding deleted; (c) Finding marked stale + filterable. **Recommend: (a)** — destroying historical evidence is a compliance no-go for SOC2/PCI orgs that adopt BreachLens.

5. **Severity mapping dispute resolution** — when Wazuh's severity disagrees with our static finding's severity (e.g. Wazuh fires a level-7 MEDIUM "command exec" alert on a container that has a static CRITICAL CVE), what does the path scorer do? **Recommend: max(severities)** — the path is as critical as its most critical node. Phase 27's score formula already does this; just confirm runtime is included in the max.

6. **Multi-tenant Wazuh** — the dev stack runs one Wazuh manager. Production multi-tenant deployments need either (a) one Wazuh manager per BreachLens org, or (b) shared Wazuh manager with `agent.id` namespacing. **Recommend: (a) for self-hosted (one BreachLens deploy = one Wazuh)**, defer (b) to Phase 25 (SaaS scale) since it's a multi-tenant problem.

---

## Strategic position

The four-act story this completes:

| Act | Phase | The pitch |
|---|---|---|
| 1. Static | 14 + 16 + 22.7 | "Here's the vulnerable source line, here's the OWASP/SOC2/PCI control it violates" |
| 2. Active | 24 + 24.6 | "We ran sqlmap and confirmed it with this curl command" |
| 3. **Runtime** | **28** | **"And 4 minutes ago someone tried to exploit it in production — Wazuh caught the shell spawn"** |
| 4. Cloud | 18 + 27 Slice D | "The shell would have reached your customer-data S3 bucket via the container's IAM role" |

Coverage matrix vs incumbents (with Phase 28 shipped):

| Tool | Static | Active | Runtime | Cloud | Correlated chain |
|---|---|---|---|---|---|
| Snyk | ✅ | partial | ❌ | partial | ❌ |
| Wiz | partial | ❌ | ✅ Sensor | ✅ | ✅ cloud-only |
| Aqua / Sysdig | ❌ | ❌ | ✅ | ✅ | partial |
| Aikido | ✅ | ✅ | ❌ | partial | ❌ |
| Endor | ✅ | ❌ | partial (function reach) | ❌ | ❌ |
| Wazuh standalone | ❌ | ❌ | ✅ | ❌ | ❌ |
| **BreachLens (post-27 + 28)** | ✅ | ✅ | ✅ via Wazuh | ✅ | ✅ all four |

**Nobody else spans all four**. Wiz dominates 4. Snyk dominates 1. Aqua dominates 3. Pentera dominates 2. BreachLens is the only product that pulls all four into a single correlated attack chain — which is the demo arc no incumbent can match.

**Honest caveats** worth documenting:
- Wazuh agent has ~50MB RAM overhead per host; not free, document the tradeoff for resource-constrained environments
- Wazuh-only v1 means customers without Wazuh need to install it (or wait for Slice D's Falco/Datadog adapters); document the operational cost
- "Continuous" model adds operational surface area BreachLens hasn't had before — agent-down alerting, ingestion-rate monitoring, log retention policies. Phase 28 adds the WorkloadAgent table and basic heartbeat tracking; advanced ops (alerting on agent-down, ingestion rate SLO) is Phase 28.x

**Without Phase 28**: BreachLens's pitch tops out at "we found and confirmed the bug." That's strong but bounded — the prospect can ask "but is anyone exploiting it right now?" and the honest answer is "we don't know."

**With Phase 28**: the answer becomes "yes, here's the alert, here's the source IP, and here's the chain that connects it back to the source line in `login.php:42`." That's the difference between a security tool and a security platform.
