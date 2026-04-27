# Phase 28.6 — DNS visibility + threat intel correlation

**Status:** scoped, not started
**Predecessor:** Phase 28 (Wazuh ingestion pipeline) AND Phase 28.5 (firewall / WAF / DB tier ingestion + Phase 27 bridge pattern). Phase 27 must exist for the bridges to plug in.
**Surfaced by:** end-of-session conversation. Phase 28.5 added firewall/WAF/DB logs but skipped DNS — yet DNS is where compromise *first becomes visible*. Outbound C2 callbacks resolve a domain before they open a connection; data exfil tunnels through DNS queries when firewalls block direct egress; supply-chain compromise via a base image shows up as 1000 containers suddenly resolving the same C2 domain. Without DNS, BreachLens sees the connection (firewall) but not the *meaning* of where it's going.

This phase also introduces a **generic threat-intel service** that DNS uses first but is reusable by every other tier — Phase 28.5's firewall logs, future API security in Phase 20, even container scans (image registry domain check). One TI engine, many consumers.

---

## What DNS catches that no other tier does

| Attack pattern | Other tiers see | DNS catches it because |
|---|---|---|
| **C2 beacon** (compromise calling home) | Firewall sees outbound IP | DNS sees the *domain* — domains are slow-changing IOCs even when IPs rotate; TI feeds index by domain |
| **DNS tunneling exfil** | Firewall sees normal-looking DNS traffic | High-entropy random subdomains under one parent = encoded data; volume + entropy together is unmistakable |
| **DGA malware** (Conficker, Emotet, etc.) | Firewall sees rapid IP changes | DGA-generated domains have measurable statistical signatures (high entropy, no real-word n-grams) |
| **Typosquatting / homograph** | Nothing else sees this | Internal request to `g00gle.com` or `paypa1.com` — phishing or compromised insider |
| **Newly Registered Domain (NRD)** | Nothing else sees this | Domains registered <30 days ago are 10× more likely to be malicious; baseline signal for everything else |
| **Fast-flux** | Firewall sees changing IPs but no pattern | Same domain resolving to many IPs in short window = botnet infrastructure |
| **Supply-chain compromise via base image** | Container scan finds the bad package later | 1000 containers all resolving the same C2 domain at once = something in the build pipeline went bad TODAY |
| **Sinkhole indicator** | Nothing else sees this | Domain resolves to a known security-vendor sinkhole IP = *another* security tool classified it as bad; we should know about that signal |

DNS is the **earliest** signal in most attack chains. By the time the firewall sees the C2 callback IP, the malware already knew to call it because DNS resolved it first. Phase 28.6 catches the resolution before the beacon.

---

## The two halves of this phase

This phase has two architecturally separable concerns. Doing them as one phase keeps the design coherent; documenting them as separate halves keeps the slice plan honest.

### Half 1 — DNS log ingestion (the data)

Wazuh decoders + ingestion for DNS log sources:

- **Self-hosted**: dnsmasq, BIND/named, CoreDNS (k8s default), Unbound, Pi-hole
- **Cloud-managed**: AWS Route53 Resolver Query Logs (CloudWatch → Wazuh), Azure DNS Query Logs, GCP Cloud DNS audit logs
- **Endpoint-level**: auditd (Linux DNS syscall tracing) via Wazuh agent, Sysmon Event 22 (Windows hosts if any)

Same decoder + ingestion pattern as Phase 28.5. The new wrinkle is **container-to-query attribution** — a host-level DNS log says "the host resolved evil.com at 14:32" but doesn't say which of the 50 containers running on that host made the query. Three options ranked by cost/value:

1. **Heuristic correlation (v1, cheap)**: the resolving container = the container with an outbound connection to the resolved IP within N seconds (default N=10). Leaky but works for the C2-beacon case. **Recommend for v1.**
2. **eBPF per-cgroup DNS tracing (v2)**: kernel-level capture of DNS syscalls tagged with cgroup → container ID. Accurate but requires an eBPF agent (not in our stack). Defer to Phase 28.7 or Phase 30.
3. **Per-container DNS sidecar (alternative)**: each container gets a sidecar DNS proxy that logs queries with the container ID. Operationally heavy; only viable in service-mesh customers (Istio / Linkerd already do this).

### Half 2 — Threat intel service (the meaning)

A **generic indicator-to-verdict service** that DNS Phase uses first but every future tier can call. The architectural decision worth getting right:

```
tiService.lookup(indicator: { type: 'domain' | 'ip' | 'url' | 'hash', value: string })
   → { verdict: 'clean' | 'suspicious' | 'malicious',
       sources: [{name, confidence, firstSeen, tags}],
       cached: bool,
       lookupTimestamp: Date }
```

**Source coverage for v1**:
- AbuseIPDB (free tier, 1k/day)
- AlienVault OTX (free)
- URLhaus / ThreatFox / Malware Bazaar (abuse.ch — free, no rate limit)
- Spamhaus DBL (free for non-commercial)
- Quad9 threat feeds
- Tor exit node list (free)
- Optional: MISP integration if customer runs their own MISP instance
- **NOT in v1**: WhoisXML API (NRD database — paid; recommend customer brings their own key)

**Caching layer**: external API calls cost money + rate-limit fast. All lookups cached in a `ThreatIntelCache` table with `(indicator, source) → verdict + ttl`. Cache TTL per source (AbuseIPDB: 24h, OTX: 6h, abuse.ch: 4h, Tor list: 24h). Background job refreshes about-to-expire entries before queries hit them.

**Why this design**: the TI service becomes its own internal API. Phase 28.5's `firewallTrafficBridge` already calls Wazuh's built-in TI modules ad-hoc; this consolidates into one service with one cache, one rate-limiting policy, one set of operator-controlled sources. Future Phase 20 (API security) can call it on incoming request IPs; future container scans can check image registry domains; the engine pays once per indicator, all callers benefit.

---

## Slice plan

### Slice A — Threat intel service (foundation, ~3-4 days)

**Goal**: build the TI service first so DNS Slice B has a real engine to call. Standalone value: also wires into Phase 28.5's existing firewall/network findings retroactively.

**Changes**:
- `apps/api/prisma/schema.prisma`:
  ```prisma
  model ThreatIntelSource {
    id            String     @id @default(cuid())
    name          String     @unique
    type          TiSourceType
    apiUrl        String
    apiKeyEncrypted String?  // AES-256-GCM
    isEnabled     Boolean    @default(true)
    rateLimit     Int        // queries per day
    lastFetchAt   DateTime?
  }
  model ThreatIntelCache {
    id            String     @id @default(cuid())
    indicator     String     @index
    indicatorType IndicatorType
    sourceId      String
    verdict       TiVerdict
    confidence    Int        // 0-100
    rawResponse   Json
    fetchedAt     DateTime   @default(now())
    expiresAt     DateTime   @index
    @@unique([indicator, sourceId])
  }
  enum TiSourceType  { ABUSEIPDB OTX URLHAUS SPAMHAUS QUAD9 TOR_EXIT MISP CUSTOM }
  enum IndicatorType { DOMAIN IP URL HASH }
  enum TiVerdict     { CLEAN SUSPICIOUS MALICIOUS UNKNOWN }
  ```
- `apps/api/src/services/threatIntel/` — new dir:
  - `tiService.ts` — main `lookup(indicator)` entry point; checks cache first, falls back to source(s), writes through cache
  - `sources/` — one file per TI source with a normalised `IIntelSource` interface (`fetch(indicator) → TiVerdict + confidence + tags`)
  - `cacheCleanupJob.ts` — BullMQ recurring job that refreshes about-to-expire entries
- Settings UI: new "Threat Intel" tab — operator enables/disables sources, supplies API keys (encrypted same pattern as integrations), sees rate-limit usage
- Audit log: every TI source addition + key rotation logged

**Verify**: `tiService.lookup({ type: 'domain', value: 'evil.tk' })` returns SUSPICIOUS within 50ms cached, < 500ms uncached.

---

### Slice B — DNS log ingestion + container attribution heuristic (~4-5 days)

**Goal**: ingest DNS query logs from the supported sources; create `Finding` rows for queries that match TI verdict ≥ SUSPICIOUS; attribute container-level queries via the heuristic above.

**Changes**:
- `apps/scanner/decoders/dns/` — Wazuh decoder XML + rule files for dnsmasq, BIND, CoreDNS, Unbound, Pi-hole, Route53, Azure DNS, GCP DNS, auditd
- `apps/api/src/services/runtime/dnsIngestService.ts` — pulls Wazuh DNS alerts, calls `tiService.lookup(domain)` for each, creates `Finding` rows when verdict ≥ SUSPICIOUS
- New `Finding` subtypes:
  - `dns.query.ti-malicious` — TI hit, verdict MALICIOUS (high confidence)
  - `dns.query.ti-suspicious` — TI hit, verdict SUSPICIOUS (medium confidence)
  - `dns.query.sinkhole` — resolved to known security-vendor sinkhole IP
- New `Container.dnsAttributedQueries[]` — backed by heuristic correlation (host DNS log + outbound connection within 10s window) — populated as a derived view, not stored
- Hourly aggregation per `(domain, sourceContainer)` — one Finding per hour-bucket, all underlying queries in `rawOutput.queries[]`
- Severity mapping: TI confidence → BreachLens severity:
  - confidence ≥ 90, MALICIOUS → CRITICAL
  - confidence 70-89, MALICIOUS → HIGH
  - confidence 50-69, SUSPICIOUS → MEDIUM
  - confidence < 50, SUSPICIOUS → LOW

**Verify**: from inside `vulnerables/web-dvwa`, `curl evil.tk` (or any test-domain on a TI list) → finding appears within 60s tagged `dns.query.ti-malicious` with the container ID populated.

---

### Slice C — DNS-specific detection rules (~3-4 days)

**Goal**: detect attack patterns that don't show up in TI feeds — DGA, NRD, tunneling, typosquatting. These are *behavioural* signals over DNS queries, not lookup-based.

**Changes**:
- `apps/scanner/decoders/dns/behavioural-rules.xml` — Wazuh stateful rules for:
  - **DGA detection**: domain entropy > threshold + no English n-grams + short TTL → flag. Use shipped lists of known-good high-entropy domains (e.g. CDN cache subdomains) as exclusion list.
  - **DNS tunneling**: > 50 unique subdomains under same parent in 5min window with average subdomain length > 30 chars → flag
  - **Typosquatting**: Levenshtein distance ≤ 2 to a known popular/internal domain (configurable allowlist) → flag with the matched-against domain
  - **Fast-flux**: same domain resolved to > 5 unique IPs in 1 hour → flag
  - **NRD detection**: requires a Newly Registered Domain feed; v1 ships with a free WHOIS-RDAP-based check (slower, rate-limited) and supports a paid feed (WhoisXML API, optional operator key) for high-volume environments
- New `Finding` subtypes:
  - `dns.query.dga-suspected`
  - `dns.query.tunneling-suspected`
  - `dns.query.typosquatting`
  - `dns.query.fast-flux`
  - `dns.query.nrd` — Newly Registered Domain (under 30 days)
- Confidence calibration: behavioural rules ship as POSSIBLE confidence by default; only escalate to LIKELY if the same source container also has a static or runtime finding (Phase 27 correlation)

**Verify**: from a test container, run `dig <high-entropy-random-string>.test` — finding `dns.query.dga-suspected` appears at POSSIBLE confidence.

---

### Slice D — Phase 27 bridges + Network page DNS tab (~2-3 days)

**Goal**: register two new bridges with Phase 27's correlation engine; add DNS visibility to the Network page from Phase 28.5 Slice D.

**Changes**:
- `apps/api/src/services/correlation/`:
  - `dnsResolutionBridge.ts` — links a DNS finding (`dns.query.ti-malicious` etc.) on container X to ANY other finding on container X — DNS query is enrichment for any chain involving that container. Edge label: "resolved <domain> · TI verdict <verdict>"
  - `c2BeaconBridge.ts` — links a DNS finding + a Phase 28.5 firewall outbound finding + a Phase 28 runtime alert ALL on the same container within a short window → flags as "**confirmed C2 beacon**" with high confidence. This is the killshot pattern: shell + DNS + outbound = compromise + control channel established.
- Phase 27 attack-path scoring: paths that include a confirmed C2 beacon get the `proofMultiplier × 2.5` (was `× 2.0` for runtime, `× 1.5` for PENTEST CONFIRMED) — C2 beacon is the highest-confidence "active compromise" signal.
- `apps/web/src/pages/NetworkPage.tsx` — new DNS tab:
  - **Top strip**: "DNS queries today" + "TI hits today" + "DGA/NRD flags today" + active C2 beacon count (red if > 0)
  - **Main view**: filterable query table with TI verdict badge per row + container attribution (when known)
  - **Pinned section** at top: "Active C2 beacons" — any C2 beacon detected in the last 24h, with one-click jump to the attack path
- Update Phase 28.5 firewall page: each outbound connection now shows the resolved domain (when DNS attribution is available) and its TI verdict — cross-tier enrichment in both directions

---

## Effort estimate

| Slice | Lines | Time |
|---|---|---|
| A — Threat intel service (model, sources, cache, settings UI) | ~700 | 3-4 days |
| B — DNS log ingestion + container attribution heuristic | ~600 | 4-5 days |
| C — DNS behavioural detection rules (DGA, NRD, tunneling, typosquat, fast-flux) | ~500 | 3-4 days |
| D — Phase 27 bridges (`dnsResolutionBridge`, `c2BeaconBridge`) + Network page DNS tab | ~400 | 2-3 days |
| **Total Phase 28.6** | **~2200** | **~2.5-3 weeks** |

**Recommend ship order: A → B → D → C.** Slice A unlocks every future enrichment (not just DNS); B + D give a working DNS visibility story with TI matching; C adds the harder-to-tune behavioural rules last so we can calibrate against real customer DNS volume before declaring confidence levels.

**Note on incremental value**:
- Slice A alone retroactively enriches Phase 28.5 firewall findings — every IP in firewall logs gets a TI verdict. Standalone value before any DNS work lands.
- Slice B + Phase 27 = "we saw container X resolve evil.com" attack chain enrichment. Without C, the behavioural rules don't fire but TI hits still do.
- Slice C alone (without TI) catches malware that uses unknown-but-statistically-suspicious domains. Composes with B but doesn't require it.

---

## Open questions to settle before Slice A

1. **Default TI sources enabled out of the box vs operator opt-in** — abuse.ch (URLhaus/ThreatFox) is free and unrate-limited; safe to enable by default. AbuseIPDB / OTX have free tiers with daily caps; operator might prefer to bring their own keys. **Recommend**: ship abuse.ch + Tor exit list enabled by default; AbuseIPDB / OTX disabled with a "supply API key to enable" prompt. Documented in operator setup guide.

2. **TI cache TTL vs verdict-change responsiveness** — long TTLs save API calls but a domain that goes from clean to malicious (compromise of legitimate site) won't update for hours. **Recommend**: shorter TTLs (4-6h) for domains, longer (24h) for IPs which change classification more slowly. Background refresh job pre-warms about-to-expire entries to avoid request-time latency spikes.

3. **Container attribution heuristic accuracy** — the "container with outbound connection to resolved IP within 10s" heuristic is leaky. Two containers might resolve the same domain at the same time; the heuristic credits one. False attribution is worse than no attribution for an audit story. **Recommend**: when ambiguous (multiple candidate containers), credit "host-level" with a note "ambiguous — N candidate containers" rather than picking one. Operators with the eBPF agent (Phase 28.7) get accurate per-container attribution.

4. **DGA detection false positive baseline** — CDN cache hostnames, AWS S3 randomised bucket prefixes, and many SaaS provider URLs look DGA-like. Need a curated allowlist shipped with the rule set. **Recommend**: ship with a baseline allowlist of top-1000 popular providers; expose a Settings tab where operators add their own custom allowlist entries; learn from operator suppressions over time (when operator marks a DGA finding as FALSE_POSITIVE, suggest auto-allowlisting that domain).

5. **NRD lookup volume vs cost** — every novel domain lookup needs a WHOIS check to determine registration age. Free WHOIS RDAP is rate-limited; paid feeds (WhoisXML) cost money. **Recommend**: cache WHOIS results aggressively (registration date doesn't change for the lifetime of the domain), use free RDAP for v1, document the WhoisXML option for high-volume customers. NRD detection becomes optional — ships disabled until operator chooses a backend.

6. **Per-container DNS in cloud-managed environments** — k8s clusters typically use CoreDNS as a centralised resolver. Per-container attribution requires either a service-mesh DNS layer or eBPF tracing. **Recommend**: for v1, the heuristic in Slice B works; document the limitation. Phase 19 (K8s security) might naturally extend per-container attribution as the eBPF agent lands there.

---

## Strategic position

DNS + threat intel correlation is the **earliest detection signal** in most attack chains. Compromise → DNS lookup → connect → execute → exfil. By the time you see the firewall connection, the DNS lookup already happened — and that lookup contained the IOC (the domain string) that TI feeds index by. Catching the lookup gives you minutes-to-hours of lead time over catching the connection.

**Coverage matrix update (post-28.6):**

| Tool | Static | Active | Runtime | Network | Database | DNS+TI | Cloud | Correlated chain |
|---|---|---|---|---|---|---|---|---|
| Snyk | ✅ | partial | ❌ | ❌ | ❌ | ❌ | partial | ❌ |
| Wiz | partial | ❌ | ✅ | partial | partial | ❌ | ✅ | ✅ cloud-only |
| Aqua / Sysdig | ❌ | ❌ | ✅ | partial | ❌ | partial | partial | partial |
| Cisco Umbrella | ❌ | ❌ | ❌ | ❌ | ❌ | ✅ | ❌ | ❌ |
| **BreachLens (post-27 + 28 + 28.5 + 28.6)** | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | **✅ all seven tiers** |

**The new killshot demo (post-28.6):**

```
[14:30:14] DNS: container X resolved `c2-tk2024.tk` (URLhaus MALICIOUS, NRD 7d, registrar known-bad)
   ↓ Phase 27 c2BeaconBridge
[14:30:15] FIREWALL: outbound 185.x.x.x:443 from container X
   ↓
[14:30:18] WAZUH: /bin/sh spawned by apache2 user in container X
   ↓
[14:31:05] FIREWALL: 47MB outbound to evil-s3.amazonaws.com from container X
   ↓
🔴 ATTACK PATH: confirmed C2 beacon · active exploitation · data exfiltration in progress
   Source IP: 185.x.x.x · Threat actor likely: APT-XX (URLhaus tag match)
   Recommended action: isolate container X immediately
```

That's the call your CISO wants at 14:35, not after a customer notifies them at 09:00 the next morning.

**Strategic moves Phase 28.6 enables:**

1. **Threat-actor attribution** — TI feeds tag IOCs with threat-actor names (APT-29, FIN-7, etc.). BreachLens can surface "this attack chain matches known TTPs of <actor>" in the path UI. None of Snyk/Aikido/Aqua do this.

2. **Supply-chain compromise detection at scale** — when 100 containers across 20 customers resolve the same TI-listed domain in the same hour, that's a supply-chain incident in progress (compromised base image, malicious npm package phoning home, etc.). BreachLens has the cross-org visibility to spot this; nobody else does.

3. **The TI service is reusable** — Slice A is foundational for any future tier needing IOC enrichment. Phase 20 API security can check incoming request IPs; container scans can check registry domains; even Phase 17 auto-fix PRs can verify the fix-version dep doesn't pull from a TI-listed registry.

**Honest caveats**:
- DGA/tunneling rules will false-positive on legitimate weird-looking traffic (CDN, S3, some SaaS providers); needs operator-tunable allowlist. Ship with baseline list of top-1000 providers.
- Container attribution heuristic is leaky; document the limitation, accurate per-container DNS needs eBPF (Phase 28.7+) or service mesh.
- TI feeds have lag — newly malicious domains take hours-days to appear in feeds. Behavioural rules (Slice C) catch what TI misses but at lower confidence.
- WhoisXML / paid feeds cost money — NRD detection ships disabled until operator chooses backend; documented in setup.
