/**
 * Phase 28 Slice B — Runtime asset (Wazuh agent) management endpoints.
 *
 * The ingestion poller (services/runtime/wazuhIngestService.ts) handles
 * the read path; this router is the *operator-facing* CRUD that lets
 * someone:
 *
 *   1. Discover the agents the Wazuh manager already knows about and
 *      register them as WorkloadAgent rows in BreachLens.
 *   2. Link a WorkloadAgent to a Container — the missing graph edge
 *      that lets runtimeBridge correlate RUNTIME findings with
 *      CONTAINER / DAST findings on the same workload.
 *   3. Trigger an immediate ingestion sweep instead of waiting for the
 *      next scheduled poll. Useful right after enrolling an agent
 *      (otherwise the operator stares at "0 alerts" for 30 minutes).
 *
 * All routes are org-scoped via getActiveMembership(req). DELETE /
 * PATCH (linking) require ADMIN+ because mis-linking causes incorrect
 * cross-tier correlation — same gate applied to Container's
 * /asset-links endpoint.
 */
import { Router } from "express";
import { z } from "zod";
import { requireAuth } from "../../middleware/requireAuth.js";
import { requireRole } from "../../middleware/requireRole.js";
import prisma from "../../db.js";
import { getActiveMembership } from "../../services/activeOrgService.js";
import * as audit from "../../services/auditService.js";
import {
  discoverWazuhAgents,
  runWazuhIngestionSweep,
} from "../../services/runtime/wazuhIngestService.js";

const router = Router();
router.use(requireAuth);

// ── Schemas ───────────────────────────────────────────────────────────────

const updateAgentSchema = z.object({
  // null clears the link; undefined leaves it untouched.
  linkedContainerId: z.string().min(1).nullable().optional(),
});

// ── List ──────────────────────────────────────────────────────────────────
//
// One row per WorkloadAgent in the active org, plus rolled-up alert counts
// from RUNTIME findings (so the table can show "12 alerts last hour" without
// a second fetch). We also hydrate the linked container's imageRef so the UI
// can show a friendly label ("nginx:1.25") instead of a raw cuid.

router.get("/agents", async (req, res, next) => {
  try {
    const member = await getActiveMembership(req);
    if (!member) { res.json([]); return; }

    const [agents, alertCounts] = await Promise.all([
      prisma.workloadAgent.findMany({
        where:   { orgId: member.orgId },
        // Healthy agents that have alerted recently surface first. STALE/
        // OFFLINE drop to the bottom because that's where investigation
        // attention is needed least.
        orderBy: [{ status: "asc" }, { lastAlertAt: { sort: "desc", nulls: "last" } }],
      }),
      prisma.finding.groupBy({
        by:    ["containerId"],
        where: {
          orgId:    member.orgId,
          scanType: "RUNTIME",
          status:   { not: "FALSE_POSITIVE" },
        },
        _count: { id: true },
      }),
    ]);

    const linkedIds = agents
      .map((a) => a.linkedContainerId)
      .filter((x): x is string => Boolean(x));
    const containers = linkedIds.length
      ? await prisma.container.findMany({
          where:  { id: { in: linkedIds }, orgId: member.orgId },
          select: { id: true, imageRef: true },
        })
      : [];
    const containerMap = new Map(containers.map((c) => [c.id, c.imageRef]));

    // Alert counts are keyed by Finding.containerId (which mirrors
    // WorkloadAgent.linkedContainerId at ingest time). When the agent
    // isn't linked yet, runtime findings have null containerId — those
    // counts get bucketed onto a synthetic null row that we ignore here.
    const countByContainerId = new Map<string, number>();
    for (const row of alertCounts) {
      if (!row.containerId) continue;
      countByContainerId.set(row.containerId, row._count.id);
    }

    const rows = agents.map((a) => ({
      ...a,
      linkedContainerImageRef: a.linkedContainerId
        ? containerMap.get(a.linkedContainerId) ?? null
        : null,
      runtimeFindingCount: a.linkedContainerId
        ? countByContainerId.get(a.linkedContainerId) ?? 0
        : 0,
    }));

    res.json(rows);
  } catch (err) { next(err); }
});

// ── Single agent (with last 50 raw alerts for drill-down) ────────────────

router.get("/agents/:id", async (req, res, next) => {
  try {
    const member = await getActiveMembership(req);
    if (!member) { res.status(404).json({ error: "Agent not found" }); return; }

    const agent = await prisma.workloadAgent.findFirst({
      where: { id: req.params["id"], orgId: member.orgId },
    });
    if (!agent) { res.status(404).json({ error: "Agent not found" }); return; }

    const linkedContainer = agent.linkedContainerId
      ? await prisma.container.findFirst({
          where:  { id: agent.linkedContainerId, orgId: member.orgId },
          select: { id: true, imageRef: true },
        })
      : null;

    res.json({ ...agent, linkedContainer });
  } catch (err) { next(err); }
});

// ── Update — operator declares linkedContainerId. ADMIN+. ────────────────
//
// Validates the container belongs to the SAME org so a malicious member
// can't link an agent to another org's container. Audit logged because
// graph linkage drives cross-tier correlation — silent edits would
// confuse the chain history.

router.patch("/agents/:id", requireRole("ADMIN"), async (req, res, next) => {
  try {
    const body = updateAgentSchema.parse(req.body);
    const user = req.user as { id: string };

    const agent = await prisma.workloadAgent.findFirst({
      where: { id: req.params["id"], orgId: req.orgId! },
    });
    if (!agent) { res.status(404).json({ error: "Agent not found" }); return; }

    let linkedContainerId: string | null = agent.linkedContainerId ?? null;
    if (body.linkedContainerId !== undefined) {
      if (body.linkedContainerId === null) {
        linkedContainerId = null;
      } else {
        const container = await prisma.container.findFirst({
          where:  { id: body.linkedContainerId, orgId: req.orgId! },
          select: { id: true },
        });
        if (!container) {
          res.status(400).json({
            error:   "Container not found in this organization",
            details: { missing: [body.linkedContainerId] },
          });
          return;
        }
        linkedContainerId = container.id;
      }
    }

    const updated = await prisma.workloadAgent.update({
      where: { id: agent.id },
      data:  { linkedContainerId },
    });

    await audit.log({
      orgId:        req.orgId!,
      userId:       user.id,
      action:       "runtime.agent.link",
      resourceType: "WorkloadAgent",
      resourceId:   agent.id,
      metadata:     {
        wazuhAgentId:   agent.wazuhAgentId,
        wazuhAgentName: agent.wazuhAgentName,
        linkedContainerId,
      },
    });

    res.json(updated);
  } catch (err) { next(err); }
});

// ── Delete (disassociate from BreachLens; agent stays in Wazuh). ADMIN+. ──

router.delete("/agents/:id", requireRole("ADMIN"), async (req, res, next) => {
  try {
    const user = req.user as { id: string };
    const agent = await prisma.workloadAgent.findFirst({
      where: { id: req.params["id"], orgId: req.orgId! },
    });
    if (!agent) { res.status(404).json({ error: "Agent not found" }); return; }

    await prisma.workloadAgent.delete({ where: { id: agent.id } });
    await audit.log({
      orgId:        req.orgId!,
      userId:       user.id,
      action:       "runtime.agent.delete",
      resourceType: "WorkloadAgent",
      resourceId:   agent.id,
      metadata:     {
        wazuhAgentId:   agent.wazuhAgentId,
        wazuhAgentName: agent.wazuhAgentName,
      },
    });

    res.json({ ok: true });
  } catch (err) { next(err); }
});

// ── Discover — pull agents from Wazuh manager + upsert. ADMIN+. ──────────
//
// Returns the discovered list so the UI can show "found N agents,
// upserted M". Idempotent — re-running preserves operator-set
// linkedContainerId choices.

router.post("/agents/discover", requireRole("ADMIN"), async (req, res, next) => {
  try {
    const user = req.user as { id: string };
    const result = await discoverWazuhAgents(req.orgId!);

    if (result.enabled) {
      await audit.log({
        orgId:        req.orgId!,
        userId:       user.id,
        action:       "runtime.agent.discover",
        resourceType: "Organization",
        resourceId:   req.orgId!,
        metadata:     { upserted: result.upserted },
      });
    }

    res.json(result);
  } catch (err) { next(err); }
});

// ── Dashboard aggregation ────────────────────────────────────────────────
//
// Single bundled endpoint — the dashboard renders five widgets that all
// derive from the same Finding/WorkloadAgent dataset. Bundling avoids
// 5 round-trips on page load and lets us share the per-finding evidence
// parse across all aggregations.
router.get("/dashboard", async (req, res, next) => {
  try {
    const member = await getActiveMembership(req);
    if (!member) {
      res.json({
        summary: { totalFindings: 0, activeAttacks24h: 0, exploitsSucceeded24h: 0, healthyAgents: 0, totalAgents: 0, falsePositives24h: 0 },
        mitreTactics: [], topAttackers: [], topAgents: [], recentEvents: [], agentHealth: [], compliance: {},
      });
      return;
    }
    const orgId = member.orgId;

    const since24h = new Date(Date.now() - 24 * 60 * 60 * 1000);

    const [allRuntime, since24hRuntime, agents] = await Promise.all([
      prisma.finding.findMany({
        where:  { orgId, scanType: "RUNTIME", status: { not: "FALSE_POSITIVE" } },
        select: { id: true, severity: true, title: true, evidence: true, lastSeen: true, firstSeen: true, scanType: true, confidence: true, aiFpAnalysis: true, status: true, ruleId: true, scanner: true, description: true },
        orderBy: { lastSeen: "desc" },
        take:    500, // cap the workload — dashboard never needs more
      }),
      prisma.finding.findMany({
        where:  {
          orgId,
          scanType: "RUNTIME",
          status:   { not: "FALSE_POSITIVE" },
          lastSeen: { gte: since24h },
        },
        // title + description are read by the success-text regex below
        // (matches "Successful sudo to root", "privilege escalation", etc.)
        select: { evidence: true, aiFpAnalysis: true, title: true, description: true },
      }),
      prisma.workloadAgent.findMany({
        where:   { orgId },
        orderBy: [{ status: "asc" }, { lastAlertAt: { sort: "desc", nulls: "last" } }],
      }),
    ]);

    // ── Summary cards ────────────────────────────────────────────
    const healthyAgents   = agents.filter((a) => a.status === "HEALTHY").length;
    let activeAttacks24h  = 0;
    let exploitsSucceeded24h = 0;
    let falsePositives24h = 0;
    for (const f of since24hRuntime) {
      const ai = f.aiFpAnalysis as { verdict?: string; confidence?: string } | null;
      if (ai?.verdict === "LIKELY_FP" && (ai.confidence === "HIGH" || ai.confidence === "MEDIUM")) {
        falsePositives24h++;
        continue;
      }
      const ev = f.evidence as Record<string, unknown> | null;
      const det = ev?.["detection"] as { groups?: string[] } | undefined;
      const groups = det?.groups ?? [];
      const mitre = ev?.["mitre"]  as { tactics?: string[] } | null;
      const tactics = mitre?.tactics ?? [];
      const isAttack = groups.some((g) => ["attack", "exploit", "intrusion", "web_attack"].includes(g))
                    || tactics.some((t) => ["Initial Access","Execution","Persistence","Privilege Escalation","Defense Evasion","Credential Access","Lateral Movement","Collection","Command and Control","Exfiltration","Impact"].includes(t));
      if (!isAttack) continue;
      activeAttacks24h++;
      // Mirror the frontend `wasExploitSuccessful` predicate after the
      // tightening: HTTP 2xx/3xx alone was too noisy (apache returns
      // 200 to most well-formed requests). Strong signals only:
      //   1. audit.success — kernel confirmed
      //   2. post-compromise MITRE tactic — the tactic IS the success
      //   3. file integrity event — something on disk changed
      //   4. title/description text match for success language
      //      ("Successful sudo", "privilege escalation", "compromised", etc.)
      const audit = ev?.["audit"] as { success?: string | boolean } | null;
      const titleAndDesc = `${f.title ?? ""} ${f.description ?? ""}`;
      const SUCCESS_TEXT_RE = /\b(successful|compromised?|backdoor[ -](installed|created|opened)|privilege[s]?[ -]escalat(?:ion|ed)|rce|remote[ -]code[ -]execution|root[ -]shell|root[ -]access|gained?[ -]root|data[ -]exfiltrat(ion|ed)|breached)\b/i;
      const succeeded =
        audit?.success === "yes" || audit?.success === true || audit?.success === "success" ||
        tactics.some((t) => ["Impact","Exfiltration","Collection","Command and Control"].includes(t)) ||
        (typeof ev?.["fileEvent"] === "string" && (ev["fileEvent"] as string).length > 0) ||
        SUCCESS_TEXT_RE.test(titleAndDesc);
      if (succeeded) exploitsSucceeded24h++;
    }

    // ── MITRE tactic distribution ────────────────────────────────
    const tacticCounts = new Map<string, number>();
    const techniqueByTactic = new Map<string, Set<string>>();
    // ── Attacker IP rollup ────────────────────────────────────────
    const attackerCounts = new Map<string, { count: number; country?: string; agents: Set<string> }>();
    // ── Per-agent activity ───────────────────────────────────────
    const perAgent = new Map<string, { findings: number; lastSeen: Date | null }>();
    // ── Compliance rollup ────────────────────────────────────────
    const compliance = { pci_dss: new Set<string>(), gdpr: new Set<string>(), hipaa: new Set<string>(), nist_800_53: new Set<string>(), tsc: new Set<string>() };

    for (const f of allRuntime) {
      const ev = f.evidence as Record<string, unknown> | null;
      if (!ev) continue;

      // MITRE
      const mitre = ev["mitre"] as { tactics?: string[]; techniques?: string[] } | null;
      for (const t of mitre?.tactics ?? []) {
        tacticCounts.set(t, (tacticCounts.get(t) ?? 0) + 1);
        if (!techniqueByTactic.has(t)) techniqueByTactic.set(t, new Set());
        for (const tech of mitre?.techniques ?? []) techniqueByTactic.get(t)!.add(tech);
      }

      // Attacker IPs — both primary + bucket-aggregated
      const ips = new Set<string>();
      const primary = ev["attackerIp"] as string | undefined;
      if (primary) ips.add(primary);
      for (const ip of (ev["attackerIps"] as string[] | undefined) ?? []) ips.add(ip);
      const geo = ev["geo"] as { country?: string } | null;
      const agentName = ev["wazuhAgentName"] as string | undefined;
      for (const ip of ips) {
        const cur = attackerCounts.get(ip) ?? { count: 0, country: undefined, agents: new Set() };
        cur.count += 1;
        if (geo?.country) cur.country = String(geo.country);
        if (agentName)    cur.agents.add(agentName);
        attackerCounts.set(ip, cur);
      }

      // Per-agent
      if (agentName) {
        const cur = perAgent.get(agentName) ?? { findings: 0, lastSeen: null };
        cur.findings += 1;
        if (!cur.lastSeen || f.lastSeen > cur.lastSeen) cur.lastSeen = f.lastSeen;
        perAgent.set(agentName, cur);
      }

      // Compliance
      const comp = ev["compliance"] as Record<string, string[]> | null;
      if (comp) {
        for (const c of comp.pci_dss     ?? []) compliance.pci_dss.add(c);
        for (const c of comp.gdpr        ?? []) compliance.gdpr.add(c);
        for (const c of comp.hipaa       ?? []) compliance.hipaa.add(c);
        for (const c of comp.nist_800_53 ?? []) compliance.nist_800_53.add(c);
        for (const c of comp.tsc         ?? []) compliance.tsc.add(c);
      }
    }

    // Top recent HIGH+ events for the timeline (cap 10).
    const recentEvents = allRuntime
      .filter((f) => f.severity === "HIGH" || f.severity === "CRITICAL")
      .slice(0, 10)
      .map((f) => ({
        id:        f.id,
        severity:  f.severity,
        title:     f.title,
        scanner:   f.scanner,
        ruleId:    f.ruleId,
        lastSeen:  f.lastSeen,
        attackerIp:    (f.evidence as Record<string, unknown> | null)?.["attackerIp"] ?? null,
        wazuhAgentName: (f.evidence as Record<string, unknown> | null)?.["wazuhAgentName"] ?? null,
        mitreTactics:  ((f.evidence as Record<string, unknown> | null)?.["mitre"] as { tactics?: string[] } | null)?.tactics ?? [],
      }));

    res.json({
      summary: {
        totalFindings:        allRuntime.length,
        activeAttacks24h,
        exploitsSucceeded24h,
        falsePositives24h,
        healthyAgents,
        totalAgents:          agents.length,
      },
      mitreTactics: [...tacticCounts.entries()]
        .map(([tactic, count]) => ({
          tactic,
          count,
          techniques: [...(techniqueByTactic.get(tactic) ?? [])].slice(0, 5),
        }))
        .sort((a, b) => b.count - a.count),
      topAttackers: [...attackerCounts.entries()]
        .map(([ip, v]) => ({ ip, count: v.count, country: v.country ?? null, agents: [...v.agents] }))
        .sort((a, b) => b.count - a.count)
        .slice(0, 10),
      topAgents: [...perAgent.entries()]
        .map(([name, v]) => ({ name, findings: v.findings, lastSeen: v.lastSeen }))
        .sort((a, b) => b.findings - a.findings)
        .slice(0, 10),
      recentEvents,
      agentHealth: agents.map((a) => ({
        id:               a.id,
        wazuhAgentId:     a.wazuhAgentId,
        wazuhAgentName:   a.wazuhAgentName,
        status:           a.status,
        lastHeartbeatAt:  a.lastHeartbeatAt,
        lastAlertAt:      a.lastAlertAt,
        agentVersion:     a.agentVersion,
        linkedContainerId: a.linkedContainerId,
      })),
      compliance: {
        pci_dss:     [...compliance.pci_dss].sort(),
        gdpr:        [...compliance.gdpr].sort(),
        hipaa:       [...compliance.hipaa].sort(),
        nist_800_53: [...compliance.nist_800_53].sort(),
        tsc:         [...compliance.tsc].sort(),
      },
    });
  } catch (err) { next(err); }
});

// ── Vulnerabilities (cross-tier: Container CVEs ↔ Wazuh VD CVEs) ─────────
//
// The story this endpoint serves:
//
//   Trivy (CONTAINER scan)  → "package X v1.0 has CVE-2024-1234 in image"
//   Wazuh VD (RUNTIME scan) → "package X v1.0 is INSTALLED on host with CVE"
//
// Cross-tier matching by CVE ID:
//   BOTH         — image scanner saw it AND Wazuh sees it on the host
//                   ⇒ CONFIRMED present in production
//   CONTAINER_ONLY — image has it, Wazuh hasn't reported it
//                   ⇒ may be unreachable / removed in deployment
//   RUNTIME_ONLY  — Wazuh sees it, image scan didn't catch it
//                   ⇒ post-deployment package install or stale image scan
//
// The CONTAINER_ONLY tier is the suppression candidate: if the package
// isn't observed live, the operator can mark it NOT_REACHABLE in bulk.
// Combined with Phase 14's reachability classification, this gives us
// runtime-grounded prioritisation that no static SCA tool can produce
// alone.
router.get("/vulnerabilities", async (req, res, next) => {
  try {
    const member = await getActiveMembership(req);
    if (!member) {
      res.json({ summary: { containerCves: 0, runtimeCves: 0, both: 0, containerOnly: 0, runtimeOnly: 0, unreachableCandidates: 0 }, rows: [] });
      return;
    }
    const orgId = member.orgId;

    // Linked-container map: which containers are runtime-monitored?
    const agents = await prisma.workloadAgent.findMany({
      where:  { orgId, linkedContainerId: { not: null } },
      select: { linkedContainerId: true, wazuhAgentName: true },
    });
    const monitoredContainerIds = new Set(
      agents.map((a) => a.linkedContainerId).filter((id): id is string => Boolean(id)),
    );
    const containerToAgent = new Map<string, string>();
    for (const a of agents) {
      if (a.linkedContainerId) containerToAgent.set(a.linkedContainerId, a.wazuhAgentName);
    }

    // Fetch in parallel: Container CVEs (Trivy) + Runtime CVEs (Wazuh VD)
    const [containerFindings, runtimeFindings] = await Promise.all([
      prisma.finding.findMany({
        where: {
          orgId,
          scanType: "CONTAINER",
          cveId:    { not: null },
          status:   { not: "FALSE_POSITIVE" },
        },
        select: {
          id: true, cveId: true, severity: true, packageName: true, packageVersion: true,
          fixVersion: true, cvssScore: true, containerId: true, lastSeen: true,
          status: true, container: { select: { imageRef: true } },
          // Phase 14 reachability — read so we can show + filter
          reachability: true,
        },
        orderBy: { lastSeen: "desc" },
      }),
      // Wazuh VD findings — currently zero on our manager, but the
      // shape will populate once the VD module emits alerts. Match by
      // evidence.vulnerability.cve being non-null.
      prisma.$queryRaw<Array<{
        id: string; severity: string; cve: string; packageName: string | null;
        packageVersion: string | null; agentName: string | null; lastSeen: Date;
      }>>`
        SELECT
          id,
          severity,
          (evidence -> 'vulnerability' ->> 'cve')             AS cve,
          (evidence -> 'vulnerability' ->> 'packageName')     AS "packageName",
          (evidence -> 'vulnerability' ->> 'packageVersion')  AS "packageVersion",
          (evidence ->> 'wazuhAgentName')                     AS "agentName",
          "lastSeen"
        FROM "Finding"
        WHERE "orgId" = ${orgId}
          AND "scanType" = 'RUNTIME'
          AND evidence -> 'vulnerability' ->> 'cve' IS NOT NULL
          AND status <> 'FALSE_POSITIVE'
        ORDER BY "lastSeen" DESC
      `,
    ]);

    // Build cross-tier index by CVE ID. A given CVE can appear on
    // multiple containers (different scans of different images) — keep
    // them as separate rows but tag each with its tier classification.
    const runtimeByCve = new Map<string, typeof runtimeFindings>();
    for (const r of runtimeFindings) {
      if (!r.cve) continue;
      const arr = runtimeByCve.get(r.cve) ?? [];
      arr.push(r);
      runtimeByCve.set(r.cve, arr);
    }

    type Tier = "BOTH" | "CONTAINER_ONLY" | "RUNTIME_ONLY";
    interface Row {
      tier:           Tier;
      cve:            string;
      severity:       string;
      packageName:    string | null;
      packageVersion: string | null;
      fixVersion:     string | null;
      cvssScore:      number | null;
      reachability:   string | null;
      // Container side
      containerFindingId: string | null;
      containerId:        string | null;
      imageRef:           string | null;
      // Runtime side
      runtimeFindingIds:  string[];
      agentName:          string | null;
      // Suppression flag — TRUE when this is a candidate for the
      // "mark NOT_REACHABLE" bulk action (CONTAINER row whose container
      // is monitored by an agent but the agent never reported the CVE)
      unreachableCandidate: boolean;
      lastSeen:           Date;
    }

    const rows: Row[] = [];

    for (const c of containerFindings) {
      if (!c.cveId) continue;
      const matchingRuntime = runtimeByCve.get(c.cveId) ?? [];
      const tier: Tier = matchingRuntime.length > 0 ? "BOTH" : "CONTAINER_ONLY";
      const isMonitored = c.containerId ? monitoredContainerIds.has(c.containerId) : false;
      rows.push({
        tier,
        cve:            c.cveId,
        severity:       c.severity,
        packageName:    c.packageName,
        packageVersion: c.packageVersion,
        fixVersion:     c.fixVersion,
        cvssScore:      c.cvssScore,
        reachability:   c.reachability,
        containerFindingId: c.id,
        containerId:    c.containerId,
        imageRef:       c.container?.imageRef ?? null,
        runtimeFindingIds: matchingRuntime.map((r) => r.id),
        agentName:      matchingRuntime[0]?.agentName ?? (c.containerId ? containerToAgent.get(c.containerId) ?? null : null),
        // Suppression candidate: container is monitored, finding is
        // CONTAINER_ONLY (Wazuh hasn't seen the CVE), and Phase 14
        // reachability isn't already explicitly set. The operator
        // can manually flip these to NOT_REACHABLE in bulk.
        unreachableCandidate:
          tier === "CONTAINER_ONLY" &&
          isMonitored &&
          (c.reachability === null || c.reachability === "UNKNOWN" || c.reachability === undefined),
        lastSeen:       c.lastSeen,
      });
    }

    // RUNTIME_ONLY rows: CVEs Wazuh saw that no Container scan flagged.
    // These are interesting because they suggest either (a) the image
    // was scanned before the package was added or (b) post-deployment
    // installation happened on the host.
    const containerCveSet = new Set(containerFindings.map((c) => c.cveId).filter(Boolean) as string[]);
    for (const r of runtimeFindings) {
      if (!r.cve) continue;
      if (containerCveSet.has(r.cve)) continue;
      rows.push({
        tier:           "RUNTIME_ONLY",
        cve:            r.cve,
        severity:       r.severity,
        packageName:    r.packageName,
        packageVersion: r.packageVersion,
        fixVersion:     null,
        cvssScore:      null,
        reachability:   null,
        containerFindingId: null,
        containerId:    null,
        imageRef:       null,
        runtimeFindingIds: [r.id],
        agentName:      r.agentName,
        unreachableCandidate: false,
        lastSeen:       r.lastSeen,
      });
    }

    // Summary counts
    const bothCount          = rows.filter((r) => r.tier === "BOTH").length;
    const containerOnlyCount = rows.filter((r) => r.tier === "CONTAINER_ONLY").length;
    const runtimeOnlyCount   = rows.filter((r) => r.tier === "RUNTIME_ONLY").length;
    const unreachableCandidates = rows.filter((r) => r.unreachableCandidate).length;

    res.json({
      summary: {
        containerCves: containerFindings.length,
        runtimeCves:   runtimeFindings.length,
        both:          bothCount,
        containerOnly: containerOnlyCount,
        runtimeOnly:   runtimeOnlyCount,
        unreachableCandidates,
        monitoredContainers: monitoredContainerIds.size,
      },
      rows,
    });
  } catch (err) { next(err); }
});

// POST /api/runtime/vulnerabilities/suppress — bulk-mark Container
// findings as NOT_REACHABLE. Operator-driven action: they've reviewed
// the runtime evidence and confirmed the package is not invoked.
router.post("/vulnerabilities/suppress", requireRole("ADMIN"), async (req, res, next) => {
  try {
    const body = z.object({
      findingIds: z.array(z.string().min(1)).min(1).max(500),
    }).parse(req.body);

    const user = req.user as { id: string };

    // Update only findings that belong to this org and are CONTAINER scans.
    // Use updateMany so a malicious payload can't flip findings outside scope.
    const updated = await prisma.finding.updateMany({
      where: {
        id:       { in: body.findingIds },
        orgId:    req.orgId!,
        scanType: "CONTAINER",
      },
      data: {
        reachability: "NOT_REACHABLE",
      },
    });

    await audit.log({
      orgId:        req.orgId!,
      userId:       user.id,
      action:       "runtime.vulnerability.suppress",
      resourceType: "Finding",
      resourceId:   "bulk",
      metadata:     { count: updated.count, findingIds: body.findingIds.slice(0, 50) },
    });

    res.json({ updated: updated.count });
  } catch (err) { next(err); }
});

// ── Trigger ingest now (no role gate — read-only side effect) ────────────

router.post("/ingest", async (_req, res, next) => {
  try {
    const summary = await runWazuhIngestionSweep();
    res.json(summary);
  } catch (err) { next(err); }
});

export default router;
