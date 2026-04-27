# Phase 27 — Attack-path correlation (asset graph foundation)

**Status:** scoped, not started
**Predecessor:** Phase 18 (CSPM — cloud config + drift) — must ship first so the graph has cloud nodes on day one
**Surfaced by:** end-of-session conversation about how to demo BreachLens as more than "another scanner aggregator." The findings exist (~600 in dev today across SAST/SCA/Secrets/IaC/Container/DAST/PENTEST) but they're an unindexed pile — no chain, no story. Sequenced after CSPM specifically so the demo lands as "internet → web vuln → container → cloud → exfil" rather than "internet → web vuln → container → ???"

---

## The gap

Every `Finding` row in the DB today has a `targetType` (REPOSITORY / CONTAINER / DOMAIN / CLOUD_ACCOUNT) + `targetId` pointing at a single asset. There are zero relations between those assets. So a query like:

> "Show me every finding that's part of an internet-reachable exploit chain ending in customer-data exposure"

is currently impossible to answer — not because the findings are missing, but because the platform has no idea that `repo X` builds `container Y` deployed at `domain Z` running with `IAM role R` that can read `S3 bucket B`.

Five real findings sit in the dev DB right now from DVWA scans:

1. **SAST**: `vulnerabilities/sqli/source/low.php:6` — unsanitized `$_GET["id"]` → SQL
2. **DAST**: `/vulnerabilities/sqli/?id=1` reflected SQL injection
3. **PENTEST**: same URL, **CONFIRMED** by sqlmap with extracted DB schema
4. **CONTAINER SCA**: CVE-2021-44790 in `libapache2` (mod_lua stack overflow → RCE)
5. **SECRETS**: hardcoded `MYSQL_PASS` in `config/config.inc.php`

Five rows. Three target types. One attack chain. Today they're displayed in three separate tabs with no connection between them. That's the gap Phase 27 fills.

---

## The use case (the demo we want to ship)

```
[Internet]
   ↓  unauthenticated GET
[https://dvwa/vulnerabilities/sqli/?id=1]
   ├─ SAST proof:    low.php:6 source-line
   ├─ DAST proof:    black-box reflection
   └─ PENTEST proof: CONFIRMED — DB schema extracted (curl reproducer attached)
   ↓  shell-equivalent reached inside
[container: vulnerables/web-dvwa]
   ├─ CONTAINER CVE: CVE-2021-44790 libapache2 RCE (escalates to container-root)
   └─ SECRETS: hardcoded MYSQL_PASS in /var/www/html/config/
   ↓  pivoted with credentials
[MySQL container]
   ↓  via container's IAM role  *(Phase 18 CSPM enrichment)*
[overprivileged S3 read on customer-data bucket]
   ↓
[Data exfiltration]
```

Eight findings. Four target types (repo / container / domain / cloud). One score. One graph view. One thing the salesperson points at and says "this is what 'unified DevSecOps' actually means."

Without Phase 27, the same eight findings render as eight separate rows in eight separate filters. Phase 27 turns the pile into the picture.

---

## Slice plan (suggested commit shape)

### Slice A — Asset relations schema + operator-declared seeding (foundation, ~2-3 days)

**Goal**: give Repository, Container, Domain, and CloudResource bidirectional relations so the correlation engine has edges to walk. v1 is operator-declared via Settings UI; CI-based inference is Phase 27.x follow-up.

**Changes**:
- `apps/api/prisma/schema.prisma` — extend existing models:
  ```prisma
  model Repository {
    buildsContainerImages  String[]   // operator-declared image refs
  }
  model Container {
    deployedAtDomainIds    String[]
    sourceRepositoryId     String?
    runsInClusterId        String?    // populated by Phase 18 CSPM
  }
  model Domain {
    servesContainerIds     String[]
  }
  model CloudResource {                // already exists from Phase 18
    accessibleByContainerIds String[]  // populated by IAM bridge
  }
  ```
- `apps/api/src/routes/<resource>/router.ts` — `PATCH` endpoint accepting the new linkage fields, ADMIN-gated, audit-logged
- `apps/web/src/components/AssetLinksPanel.tsx` — multi-select + chip editor on each resource detail page; "this domain serves these containers" / "this repo builds these images"
- Validation: cross-org references rejected; `getActiveMembership(req)` scopes the linkage choices to the operator's org

**Why this is the foundation**: nothing else works without it. `correlationGroupId` can't be populated until there's a graph to walk. Ship A standalone first; B and C are no-ops until A exists.

---

### Slice B — Correlation engine + 4 base bridge plugins (~3-4 days)

**Goal**: introduce a pluggable `Bridge` interface that takes two `Finding` rows and returns a `BridgeMatch | null`. Run all bridges across all findings on a periodic + on-write basis; populate `correlationGroupId` and `correlationEdges` on each finding.

**Changes**:
- `apps/api/prisma/schema.prisma`:
  ```prisma
  model Finding {
    correlationGroupId  String?    @index
    correlationEdges    Json?      // [{toFindingId, bridgeType, confidence}]
  }
  ```
- `apps/api/src/services/correlation/` — new dir:
  - `bridgeInterface.ts` — `interface Bridge { id: string; match(a: Finding, b: Finding): BridgeMatch | null }`
  - `cveBridge.ts` — same `cveId` across repo SCA + container SCA → strong link
  - `routeBridge.ts` — DAST/PENTEST URL path heuristically maps to SAST file path (e.g. `/vulnerabilities/sqli/` → `vulnerabilities/sqli/source/*.php`); rule-id table augments
  - `portBridge.ts` — nmap-discovered exposed port from PENTEST ↔ container's `EXPOSE` directive
  - `secretBridge.ts` — secret-value SHA-256 from secrets scanner ↔ env var SHA-256 found in container layer config
  - `correlationService.ts` — runs the bridge graph against a target's findings; called from `findingService.upsertFindings` after each scan + nightly backfill job
- New BullMQ job `correlation` — re-runs the engine for an org on schedule (cheap; bounded by O(n²) within a single org's findings)

**Why this design**: making bridges pluggable means Phase 27 ships with 4 bridges, Slice D adds 2 more (IAM, network), and future phases (Phase 19 K8s, Phase 20 API security) plug in their own without touching the engine.

---

### Slice C — Attack path graph UI (~4-5 days)

**Goal**: render the correlation graph as a force-directed view + a sortable list of "top attack paths" by score.

**Changes**:
- `apps/api/src/routes/attackPaths/router.ts`:
  - `GET /api/attack-paths` — returns scored paths (top N) for the active org
  - `GET /api/attack-paths/:id` — returns full chain + every finding's evidence
- `apps/api/src/services/attackPathService.ts` — graph traversal: BFS from each "entry" finding (CVSS attack vector = NETWORK + reachable from internet), max depth 6; score formula:
  ```
  pathScore = max(severity in path)
            × pathLength            (more hops = scarier)
            × externalReach         (1.0 if entry node is internet-facing, else 0.3)
            × proofMultiplier       (1.5 if any node has confidence=CONFIRMED)
  ```
- `apps/web/src/pages/AttackPathsPage.tsx` — top-level nav entry between Findings and Compliance:
  - Left: scored list with severity colour band, length, "Verified" badge if any node has Proof of Exploit
  - Right: force-directed graph (use existing `react-force-graph` from npm — keeps the bundle lean) with node = finding, edge tooltip = bridge type + reason
  - Click node → opens existing `FindingDetailDrawer`
- `apps/web/src/components/AttackPathBadge.tsx` — surfaces on each Finding row in `/findings`: "Part of attack path · 4 hops" link → opens the path on `/attack-paths/:id`

**UX guardrails (from `breachlens-ux-patterns.md`)**:
- **Truth-in-advertising**: empty state ("no attack paths discovered yet") explains *why* — either "no asset relations declared, set them in Settings" OR "scans haven't found enough chained findings"
- **Empty state should reward**: zero-paths-after-scan = green checkmark, not a gray dash
- **Badge meaning**: AttackPathBadge label is explicit ("Part of attack path") not ambiguous ("Linked")

---

### Slice D — Cloud bridges (composes on Phase 18 CSPM, ~3-4 days)

**Goal**: add `iamBridge` and `networkBridge` that consume Phase 18's CloudResource findings to extend chains into cloud-tier exfiltration.

**Changes**:
- `apps/api/src/services/correlation/iamBridge.ts` — Container's `runsInClusterId` → cluster's IAM role → CloudResource permissions; finds "container has S3:GetObject on bucket X"
- `apps/api/src/services/correlation/networkBridge.ts` — Domain's public-facing flag from CSPM + cloud security group ingress rules + container's port → "domain Y → container Z → MySQL container reachable on private subnet"
- These bridges only fire when Phase 18 has populated `CloudResource` rows; degrades gracefully (graph is repo+container+domain only) when CSPM isn't configured yet

**Why slot D in Phase 27 and not Phase 18**: Phase 18 ships CloudResource as standalone findings. Slice D wires them into the correlation engine. Cleanest separation — CSPM team owns "discover cloud misconfigs"; Phase 27 owns "connect them to everything else."

---

## Effort estimate

| Slice | Lines | Time |
|---|---|---|
| A — Asset relations schema + operator-declared seeding UI | ~400 | 2-3 days |
| B — Correlation engine + 4 base bridges | ~600 | 3-4 days |
| C — Attack path graph UI | ~500 | 4-5 days |
| D — Cloud bridges (composes on Phase 18) | ~600 | 3-4 days |
| **Total Phase 27** | **~2100** | **~2.5-3 weeks** |

Slice A is the killer move — it's the foundation everything else stacks on. Ship A first, verify the chip-editor UX feels right, then B unlocks the engine, C unlocks the demo, D folds in the cloud chain.

---

## Open questions to settle before Slice A

1. **CI-based inference of repo→container** — operator-declared is the v1 default, but `Dockerfile` presence in a repo + image name parsing is a 90%-accurate auto-suggester. Ship as a "we found this likely link, accept?" Settings prompt, or defer entirely to Phase 27.x? Recommend: ship as suggestion only, never auto-apply, so the operator stays in control of what gets correlated.

2. **k8s manifest scrape for container→domain** — Phase 19 (K8s security) will scrape Service + Ingress manifests. Does Phase 27 wait for 19 to land, or ship with operator-declared + add 19's automation later? Recommend: don't wait. The Phase 19 scrape is a v2 enhancement to Slice A's seeding, not a blocker.

3. **Attack path scoring tuning** — the formula above is a first-pass guess. After backfilling against the dev DB, eyeball the top-10 paths and ask: do these match what an operator would manually call the "scariest" chains? If the Juice Shop / DVWA top-paths feel off, tune `proofMultiplier` and `pathLength` weights before shipping. The scoring should be transparent + tweakable per-org, not a black box.

4. **Cross-org graph isolation** — bridges must scope by `orgId` on both sides. Cross-org correlation is a privacy violation. Add a unit test that asserts every bridge call returns null when `a.orgId !== b.orgId`. Belt-and-suspenders alongside the existing `getActiveMembership` scoping.

5. **Performance ceiling** — correlation engine is O(n²) within an org. For 10k findings, that's 100M comparisons per pass — fine if each bridge runs in microseconds (CVE-equality is a HashMap lookup; route-bridge is a regex). Real risk is `secretBridge` with SHA-256 hashing — pre-hash on write, cache on the Finding row, lookup is then O(1). Bound the worst case before Slice B starts.

---

## Why this is the right phase to land after CSPM

The pitch BreachLens makes today is "unified DevSecOps platform." After Phase 18, that's literally true on the *coverage* axis (every scanner type ships). But coverage without correlation is still seven independent dashboards. Phase 27 is what makes the unified pitch real on the *experience* axis — one chain, one story, one number on the report.

**Strategic position vs competitors:**
- **Snyk** has separate dashboards per scan type; no graph. Cross-scan correlation is roadmap-only as of Apr 2026
- **Wiz** has the cloud-side graph (their famous attack-path view) but no SAST/SCA/DAST integration; they're the "left" half of the BreachLens chain, we'd cover the full chain
- **Aikido** has unified findings but no graph; same dashboard problem as Snyk
- **Endor** has reachability within SCA, no cross-tier correlation
- **Nobody** ships the full repo→container→domain→cloud chain in one product today. Phase 27 makes that the BreachLens demo

**The demo arc post-Phase-27**: prospect uploads repo, connects AWS via Phase 18, scans for 10 minutes. Salesperson opens `/attack-paths`, points at the top scored chain, says: "this is the bug your devs introduced last sprint, this is the container it ships in, this is the IAM role it inherits, this is the customer data it can reach. Snyk shows you the bug. Wiz shows you the cloud. We show you the bridge — and we proved it's exploitable with this curl command." That's the deal-closing moment Phase 27 unlocks.

Without 27: BreachLens is "one platform that runs seven scanners."
With 27: BreachLens is "one platform that finds the attack path through your stack."
