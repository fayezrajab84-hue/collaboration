import { Router } from "express";
import axios from "axios";
import { z } from "zod";
import { requireAuth } from "../../middleware/requireAuth.js";
import { requireRole } from "../../middleware/requireRole.js";
import prisma from "../../db.js";
import { config } from "../../config.js";
import { analyseFinding } from "../../services/aiService.js";
import { getOrgFindingGroups, generateGroupInsight } from "../../services/findingGroupService.js";
import { checkFalsePositive } from "../../services/falsePositiveService.js";
import { generateFixSuggestion } from "../../services/fixSuggestionService.js";
import { activeSuppressedFingerprints } from "../../services/suppressionService.js";
import * as audit from "../../services/auditService.js";

const router = Router();
router.use(requireAuth);

const updateFindingSchema = z.object({
  status: z.enum(["OPEN", "ACKNOWLEDGED", "FALSE_POSITIVE", "FIXED", "IGNORED"]).optional(),
});

/**
 * Legacy-SECRET exclusion filter.
 *
 * TruffleHog occasionally flags the clone-time OAuth URL that git itself
 * writes into `.git/config`, and older scans produced SECRET rows with an
 * empty `filePath`. Both are non-actionable noise. The scanner's secrets.py
 * already skips `.git/` on new scans, but legacy rows persist — this filter
 * keeps them out of list/export responses unless ?includeLegacy=true is
 * explicitly passed (e.g. for admin audit tooling).
 */
const LEGACY_SECRET_EXCLUSION = {
  NOT: {
    scanType: "SECRET" as const,
    OR: [
      { filePath: null },
      { filePath: "" },
      { filePath: { contains: "/.git/" } },
    ],
  },
};

/** Append the legacy-SECRET exclusion to an existing `where` via an AND array. */
function applyLegacySecretFilter(where: Record<string, unknown>, includeLegacy: boolean): void {
  if (includeLegacy) return;
  const existing = where["AND"];
  if (Array.isArray(existing)) {
    existing.push(LEGACY_SECRET_EXCLUSION);
  } else if (existing && typeof existing === "object") {
    where["AND"] = [existing, LEGACY_SECRET_EXCLUSION];
  } else {
    where["AND"] = [LEGACY_SECRET_EXCLUSION];
  }
}

// List findings with filters
router.get("/", async (req, res, next) => {
  try {
    const user = req.user as { id: string };
    const member = await prisma.organizationMember.findFirst({ where: { userId: user.id } });
    if (!member) { res.json({ data: [], total: 0 }); return; }

    const q = req.query;
    const page = Math.max(1, parseInt(q["page"] as string || "1"));
    const limit = Math.min(100, parseInt(q["limit"] as string || "25"));
    const skip = (page - 1) * limit;

    const where: Record<string, unknown> = { orgId: member.orgId };
    if (q["severity"])   where["severity"]      = { in: [q["severity"]].flat() };
    if (q["scanType"])   where["scanType"]       = { in: [q["scanType"]].flat() };
    if (q["status"])     where["status"]         = { in: [q["status"]].flat() };
    if (q["confidence"]) where["confidence"]     = { in: [q["confidence"]].flat() };
    if (q["repoId"])     where["repositoryId"]   = q["repoId"];
    if (q["containerId"]) where["containerId"]   = q["containerId"];
    if (q["domainId"])   where["domainId"]       = q["domainId"];
    if (q["search"]) {
      where["OR"] = [
        { title:       { contains: q["search"] as string, mode: "insensitive" } },
        { description: { contains: q["search"] as string, mode: "insensitive" } },
        { cveId:       { contains: q["search"] as string, mode: "insensitive" } },
      ];
    }

    // AI triage filter — matches on aiAnalysedAt / aiFixSuggestedAt presence.
    // Values: analysed | fix_ready | triaged (both) | untriaged (neither)
    switch (q["ai"]) {
      case "analysed":  where["aiAnalysedAt"]     = { not: null }; break;
      case "fix_ready": where["aiFixSuggestedAt"] = { not: null }; break;
      case "triaged":
        where["AND"] = [
          { aiAnalysedAt:     { not: null } },
          { aiFixSuggestedAt: { not: null } },
        ];
        break;
      case "untriaged":
        where["AND"] = [
          { aiAnalysedAt:     null },
          { aiFixSuggestedAt: null },
        ];
        break;
    }

    // Suppression filter — hide suppressed findings unless ?includeSuppressed=true
    const includeSuppressed = q["includeSuppressed"] === "true";
    if (!includeSuppressed) {
      const suppressed = await activeSuppressedFingerprints(member.orgId);
      if (suppressed.size > 0) {
        where["fingerprint"] = { notIn: Array.from(suppressed) };
      }
    }

    // Legacy-SECRET false-positive filter (see LEGACY_SECRET_EXCLUSION above).
    applyLegacySecretFilter(where, q["includeLegacy"] === "true");

    // ── Sort ──────────────────────────────────────────────────────────────
    // Accept ?sort=<field>&sortOrder=asc|desc — whitelist to guard against
    // Prisma orderBy injection (any invalid column would throw at runtime).
    const SORT_FIELDS = new Set([
      "severity", "firstSeen", "lastSeen", "title", "scanType", "status", "confidence",
    ]);
    const sortField = q["sort"] && SORT_FIELDS.has(q["sort"] as string) ? (q["sort"] as string) : null;
    const sortOrder = (q["sortOrder"] === "asc" || q["sortOrder"] === "desc") ? q["sortOrder"] as "asc"|"desc" : null;
    const orderBy = sortField
      ? [{ [sortField]: sortOrder ?? "desc" } as Record<string, "asc"|"desc">, { firstSeen: "desc" as const }]
      : [{ severity: "asc" as const }, { firstSeen: "desc" as const }];

    const [data, total] = await Promise.all([
      prisma.finding.findMany({
        where,
        orderBy,
        skip,
        take: limit,
        include: {
          ticket:     { select: { id: true, status: true, jiraKey: true } },
          repository: { select: { fullName: true } },
          container:  { select: { imageRef: true } },
          domain:     { select: { domain: true } },
        },
      }),
      prisma.finding.count({ where }),
    ]);

    res.json({ data, total, page, limit, totalPages: Math.ceil(total / limit) });
  } catch (err) { next(err); }
});

// ── GET /api/findings/groups — Phase 6 smart deduplication ───────────────────
router.get("/groups", async (req, res, next) => {
  try {
    const user   = req.user as { id: string };
    const member = await prisma.organizationMember.findFirst({ where: { userId: user.id } });
    if (!member) { res.json([]); return; }
    const groups = await getOrgFindingGroups(member.orgId);
    res.json(groups);
  } catch (err) { next(err); }
});

// ── POST /api/findings/groups/insight — generate AI insight for a group ───────
router.post("/groups/insight", async (req, res, next) => {
  try {
    const { groupKey } = req.body as { groupKey?: string };
    if (!groupKey) { res.status(400).json({ error: "groupKey required" }); return; }
    const user   = req.user as { id: string };
    const member = await prisma.organizationMember.findFirst({ where: { userId: user.id } });
    if (!member) { res.status(403).json({ error: "No organization" }); return; }
    const insight = await generateGroupInsight(member.orgId, groupKey);
    res.json({ insight });
  } catch (err) { next(err); }
});

// Dashboard summary  (must come before /:id)
router.get("/summary/stats", async (req, res, next) => {
  try {
    const user = req.user as { id: string };
    const member = await prisma.organizationMember.findFirst({ where: { userId: user.id } });
    if (!member) { res.json({}); return; }

    const [severityCounts, scanTypeCounts, statusCounts, confidenceCounts] = await Promise.all([
      prisma.finding.groupBy({
        by: ["severity"],
        where: { orgId: member.orgId, status: { notIn: ["FALSE_POSITIVE", "IGNORED"] } },
        _count: true,
      }),
      prisma.finding.groupBy({
        by: ["scanType"],
        where: { orgId: member.orgId },
        _count: true,
      }),
      prisma.finding.groupBy({
        by: ["status"],
        where: { orgId: member.orgId },
        _count: true,
      }),
      prisma.finding.groupBy({
        by: ["confidence"],
        where: { orgId: member.orgId, status: { notIn: ["FALSE_POSITIVE", "IGNORED"] } },
        _count: true,
      }),
    ]);

    res.json({ severityCounts, scanTypeCounts, statusCounts, confidenceCounts });
  } catch (err) { next(err); }
});

// Dashboard — top "noisy" targets ranked by open CRITICAL+HIGH count
// (must come before /:id)
router.get("/summary/top-targets", async (req, res, next) => {
  try {
    const user   = req.user as { id: string };
    const member = await prisma.organizationMember.findFirst({ where: { userId: user.id } });
    if (!member) { res.json([]); return; }

    const limit = Math.min(10, parseInt(req.query["limit"] as string || "5"));

    // Group-by each target-type column in parallel — Prisma doesn't let us
    // group by a derived "targetName" so we aggregate per column and merge.
    const baseWhere = {
      orgId: member.orgId,
      status:   { notIn: ["FALSE_POSITIVE", "IGNORED"] as Array<"FALSE_POSITIVE" | "IGNORED"> },
      severity: { in:    ["CRITICAL", "HIGH"]         as Array<"CRITICAL" | "HIGH"> },
    };
    const [repoAgg, containerAgg, domainAgg] = await Promise.all([
      prisma.finding.groupBy({
        by: ["repositoryId"],
        where: { ...baseWhere, repositoryId: { not: null } },
        _count: { _all: true },
      }),
      prisma.finding.groupBy({
        by: ["containerId"],
        where: { ...baseWhere, containerId: { not: null } },
        _count: { _all: true },
      }),
      prisma.finding.groupBy({
        by: ["domainId"],
        where: { ...baseWhere, domainId: { not: null } },
        _count: { _all: true },
      }),
    ]);

    // Hydrate names
    const [repos, containers, domains] = await Promise.all([
      prisma.repository.findMany({
        where: { id: { in: repoAgg.map((r) => r.repositoryId!).filter(Boolean) } },
        select: { id: true, fullName: true },
      }),
      prisma.container.findMany({
        where: { id: { in: containerAgg.map((c) => c.containerId!).filter(Boolean) } },
        select: { id: true, imageRef: true },
      }),
      prisma.domain.findMany({
        where: { id: { in: domainAgg.map((d) => d.domainId!).filter(Boolean) } },
        select: { id: true, domain: true },
      }),
    ]);
    const repoName = new Map(repos.map((r) => [r.id, r.fullName]));
    const contName = new Map(containers.map((c) => [c.id, c.imageRef]));
    const domName  = new Map(domains.map((d) => [d.id, d.domain]));

    type Row = { targetType: "REPOSITORY"|"CONTAINER"|"DOMAIN"; targetId: string; targetName: string; count: number };
    const all: Row[] = [
      ...repoAgg.map((r) => ({
        targetType: "REPOSITORY" as const,
        targetId:   r.repositoryId!,
        targetName: repoName.get(r.repositoryId!) ?? r.repositoryId!,
        count:      r._count._all,
      })),
      ...containerAgg.map((c) => ({
        targetType: "CONTAINER" as const,
        targetId:   c.containerId!,
        targetName: contName.get(c.containerId!) ?? c.containerId!,
        count:      c._count._all,
      })),
      ...domainAgg.map((d) => ({
        targetType: "DOMAIN" as const,
        targetId:   d.domainId!,
        targetName: domName.get(d.domainId!) ?? d.domainId!,
        count:      d._count._all,
      })),
    ];
    all.sort((a, b) => b.count - a.count);

    res.json(all.slice(0, limit));
  } catch (err) { next(err); }
});

// ── Dashboard — top noisy rules (must come before /:id) ─────────────────────
// Groups open CRITICAL+HIGH findings by ruleId and returns the top-N by count.
// Helps identify rules that produce the most alert volume and are candidates
// for suppression/tuning.
router.get("/summary/top-rules", async (req, res, next) => {
  try {
    const user   = req.user as { id: string };
    const member = await prisma.organizationMember.findFirst({ where: { userId: user.id } });
    if (!member) { res.json([]); return; }

    const limit = Math.min(20, parseInt(req.query["limit"] as string || "5"));

    const agg = await prisma.finding.groupBy({
      by: ["ruleId", "scanType"],
      where: {
        orgId:    member.orgId,
        status:   { notIn: ["FALSE_POSITIVE", "IGNORED"] as Array<"FALSE_POSITIVE" | "IGNORED"> },
        severity: { in:    ["CRITICAL", "HIGH"]         as Array<"CRITICAL" | "HIGH"> },
        ruleId:   { not: null },
      },
      _count: { _all: true },
      orderBy: { _count: { ruleId: "desc" } },
      take: limit,
    });

    // Join a representative title for each ruleId (first occurrence).
    const ruleIds = agg.map((a) => a.ruleId!).filter(Boolean);
    const samples = await prisma.finding.findMany({
      where:  { orgId: member.orgId, ruleId: { in: ruleIds } },
      select: { ruleId: true, title: true },
      distinct: ["ruleId"],
    });
    const titleByRule = new Map(samples.map((s) => [s.ruleId!, s.title]));

    res.json(agg.map((a) => ({
      ruleId:   a.ruleId!,
      scanType: a.scanType,
      title:    titleByRule.get(a.ruleId!) ?? a.ruleId!,
      count:    a._count._all,
    })));
  } catch (err) { next(err); }
});

// ── CSV export (must come before /:id) ──────────────────────────────────────
// Same filters as GET /api/findings, but streams a CSV of the full result set
// (capped at 10k rows to prevent runaway downloads).
router.get("/export.csv", async (req, res, next) => {
  try {
    const user = req.user as { id: string };
    const member = await prisma.organizationMember.findFirst({ where: { userId: user.id } });
    if (!member) { res.status(403).send("Forbidden"); return; }

    const q = req.query;
    const where: Record<string, unknown> = { orgId: member.orgId };
    if (q["severity"])    where["severity"]     = { in: [q["severity"]].flat() };
    if (q["scanType"])    where["scanType"]     = { in: [q["scanType"]].flat() };
    if (q["status"])      where["status"]       = { in: [q["status"]].flat() };
    if (q["confidence"])  where["confidence"]   = { in: [q["confidence"]].flat() };
    if (q["repoId"])      where["repositoryId"] = q["repoId"];
    if (q["containerId"]) where["containerId"]  = q["containerId"];
    if (q["domainId"])    where["domainId"]     = q["domainId"];
    if (q["search"]) {
      where["OR"] = [
        { title:       { contains: q["search"] as string, mode: "insensitive" } },
        { description: { contains: q["search"] as string, mode: "insensitive" } },
        { cveId:       { contains: q["search"] as string, mode: "insensitive" } },
      ];
    }
    switch (q["ai"]) {
      case "analysed":  where["aiAnalysedAt"]     = { not: null }; break;
      case "fix_ready": where["aiFixSuggestedAt"] = { not: null }; break;
      case "triaged":
        where["AND"] = [{ aiAnalysedAt: { not: null } }, { aiFixSuggestedAt: { not: null } }];
        break;
      case "untriaged":
        where["AND"] = [{ aiAnalysedAt: null }, { aiFixSuggestedAt: null }];
        break;
    }
    if (q["includeSuppressed"] !== "true") {
      const suppressed = await activeSuppressedFingerprints(member.orgId);
      if (suppressed.size > 0) where["fingerprint"] = { notIn: Array.from(suppressed) };
    }
    applyLegacySecretFilter(where, q["includeLegacy"] === "true");

    const rows = await prisma.finding.findMany({
      where,
      orderBy: [{ severity: "asc" }, { firstSeen: "desc" }],
      take: 10_000,
      include: {
        repository: { select: { fullName: true } },
        container:  { select: { imageRef: true } },
        domain:     { select: { domain: true } },
      },
    });

    const esc = (v: unknown): string => {
      if (v === null || v === undefined) return "";
      const s = String(v).replace(/\r?\n/g, " ");
      return /[",]/.test(s) ? `"${s.replace(/"/g, '""')}"` : s;
    };
    const header = [
      "id","severity","status","scanType","confidence","title","cveId","cvssScore",
      "ruleId","scanner","target","filePath","lineStart","firstSeen","lastSeen","resolvedAt",
    ].join(",");
    const body = rows.map((f) => [
      f.id, f.severity, f.status, f.scanType, f.confidence, f.title, f.cveId ?? "",
      f.cvssScore ?? "", f.ruleId ?? "", f.scanner,
      f.repository?.fullName ?? f.container?.imageRef ?? f.domain?.domain ?? "",
      f.filePath ?? "", f.lineStart ?? "",
      f.firstSeen.toISOString(), f.lastSeen.toISOString(),
      f.resolvedAt?.toISOString() ?? "",
    ].map(esc).join(",")).join("\n");

    const filename = `findings-${new Date().toISOString().slice(0, 10)}.csv`;
    res.setHeader("Content-Type", "text/csv; charset=utf-8");
    res.setHeader("Content-Disposition", `attachment; filename="${filename}"`);
    res.send(`${header}\n${body}\n`);
  } catch (err) { next(err); }
});

// Get finding
router.get("/:id", async (req, res, next) => {
  try {
    const user = req.user as { id: string };
    const member = await prisma.organizationMember.findFirst({ where: { userId: user.id } });
    const finding = await prisma.finding.findFirst({
      where: { id: req.params["id"], orgId: member?.orgId },
      include: {
        ticket:     true,
        scanJob:    true,
        repository: { select: { fullName: true, defaultBranch: true } },
      },
    });
    if (!finding) { res.status(404).json({ error: "Finding not found" }); return; }
    res.json(finding);
  } catch (err) { next(err); }
});

/**
 * Lazy-fetch the untruncated HTTP exchange for a DAST finding occurrence.
 * Proxies the scanner's /dast/message/:id route after verifying the caller
 * owns the finding.  404s when ZAP has evicted the message from memory.
 */
router.get("/:id/http-message/:messageId", async (req, res, next) => {
  try {
    const user = req.user as { id: string };
    const member = await prisma.organizationMember.findFirst({ where: { userId: user.id } });
    if (!member) { res.status(403).json({ error: "Forbidden" }); return; }

    // Verify the finding belongs to this org before proxying.
    const finding = await prisma.finding.findFirst({
      where:  { id: req.params["id"], orgId: member.orgId },
      select: { id: true },
    });
    if (!finding) { res.status(404).json({ error: "Finding not found" }); return; }

    const msgId = req.params["messageId"];
    if (!msgId || !/^\d+$/.test(msgId)) { res.status(400).json({ error: "Invalid messageId" }); return; }

    try {
      const r = await axios.get(`${config.SCANNER_URL}/dast/message/${msgId}`, {
        timeout: 15_000,
      });
      res.json(r.data);
    } catch (err) {
      const status = (err as { response?: { status?: number } }).response?.status ?? 502;
      res.status(status === 404 ? 404 : 502).json({
        error: status === 404
          ? "Message no longer available in ZAP (session evicted)"
          : "Scanner unreachable",
      });
    }
  } catch (err) { next(err); }
});

// ── Bulk status update — SECURITY+ ──────────────────────────────────────────
// Accepts up to 500 finding ids and a target status; atomic via updateMany
// scoped to the caller's org so IDs from other orgs are silently ignored.
const bulkSchema = z.object({
  ids:    z.array(z.string().min(1)).min(1).max(500),
  status: z.enum(["OPEN", "ACKNOWLEDGED", "FALSE_POSITIVE", "FIXED", "IGNORED"]),
});
router.post("/bulk", requireRole("SECURITY"), async (req, res, next) => {
  try {
    const body = bulkSchema.parse(req.body);
    const user = req.user as { id: string };
    const result = await prisma.finding.updateMany({
      where: { id: { in: body.ids }, orgId: req.orgId! },
      data: {
        status:     body.status,
        resolvedAt: body.status === "FIXED" ? new Date() : null,
      },
    });
    await audit.log({
      orgId:        req.orgId!,
      userId:       user.id,
      action:       "finding.bulk_status_change",
      resourceType: "Finding",
      resourceId:   `bulk:${result.count}`,
      metadata:     { status: body.status, count: result.count, requested: body.ids.length },
    });
    res.json({ updated: result.count });
  } catch (err) { next(err); }
});

// ── Bulk create tickets — SECURITY+ ─────────────────────────────────────────
// For each finding ID that doesn't already have a ticket, create one.
// Priority derived from severity (CRITICAL→CRITICAL, HIGH→HIGH, MEDIUM→MEDIUM,
// LOW/INFO→LOW). Jira sync is NOT performed here — too slow for bulk, and
// per-ticket Jira creation can be triggered individually afterwards if needed.
const bulkTicketSchema = z.object({
  ids: z.array(z.string().min(1)).min(1).max(500),
});
const SEVERITY_TO_PRIORITY: Record<string, "CRITICAL"|"HIGH"|"MEDIUM"|"LOW"> = {
  CRITICAL: "CRITICAL", HIGH: "HIGH", MEDIUM: "MEDIUM", LOW: "LOW", INFO: "LOW",
};
router.post("/bulk-tickets", requireRole("SECURITY"), async (req, res, next) => {
  try {
    const body = bulkTicketSchema.parse(req.body);
    const user = req.user as { id: string };

    // Scope to org + drop any findings that already have a ticket.
    const findings = await prisma.finding.findMany({
      where:  { id: { in: body.ids }, orgId: req.orgId!, ticket: null },
      select: { id: true, title: true, severity: true, description: true },
    });

    const created = await prisma.$transaction(
      findings.map((f) =>
        prisma.ticket.create({
          data: {
            orgId:       req.orgId!,
            findingId:   f.id,
            title:       f.title.slice(0, 255),
            description: f.description?.slice(0, 4000) ?? null,
            priority:    SEVERITY_TO_PRIORITY[f.severity] ?? "LOW",
            createdById: user.id,
          },
        })
      )
    );

    await audit.log({
      orgId:        req.orgId!,
      userId:       user.id,
      action:       "ticket.bulk_create",
      resourceType: "Ticket",
      resourceId:   `bulk:${created.length}`,
      metadata:     { created: created.length, requested: body.ids.length, skipped: body.ids.length - findings.length },
    });

    res.json({
      created: created.length,
      skipped: body.ids.length - findings.length,  // either not-found or already had a ticket
    });
  } catch (err) { next(err); }
});

// ── Per-sub-issue status change — SECURITY+ ────────────────────────────────
//
// Merged findings keep their sub-issues inline inside `rawOutput`
// (locations[]  for SAST, occurrences[] for DAST/SECRET). We don't promote
// them to first-class rows yet — instead we thread a status map:
//
//   rawOutput.subStatus = { "0": "ACKNOWLEDGED", "3": "FALSE_POSITIVE", ... }
//
// Only scan families where each sub-issue is a genuinely independent fix
// (SAST/DAST/PENTEST/SECRET) are allowed. SCA/CONTAINER/IAC stay
// parent-level: one upstream action resolves every sub-issue at once.
const SUB_ACTION_SCAN_TYPES = new Set([
  "SAST", "DAST", "DAST_INTERACTIVE", "PENTEST_FULL", "SECRET",
]);
const SUB_STATUS = ["OPEN", "ACKNOWLEDGED", "FALSE_POSITIVE", "FIXED", "IGNORED"] as const;
const subStatusSchema = z.object({ status: z.enum(SUB_STATUS) });

router.patch("/:id/sub/:index", requireRole("SECURITY"), async (req, res, next) => {
  try {
    const { status } = subStatusSchema.parse(req.body);
    const idx = parseInt(req.params["index"] ?? "", 10);
    if (!Number.isInteger(idx) || idx < 0) {
      res.status(400).json({ error: "Invalid sub-index" });
      return;
    }
    const user = req.user as { id: string };
    const finding = await prisma.finding.findFirst({
      where: { id: req.params["id"], orgId: req.orgId! },
    });
    if (!finding) { res.status(404).json({ error: "Finding not found" }); return; }

    if (!SUB_ACTION_SCAN_TYPES.has(finding.scanType)) {
      res.status(422).json({
        error: `Per-sub-issue actions are not supported for ${finding.scanType}. Use the parent-level action instead — one upstream fix resolves all sub-issues for SCA/CONTAINER/IAC.`,
      });
      return;
    }

    const raw = (finding.rawOutput ?? {}) as Record<string, unknown>;
    if (raw["merged"] !== true) {
      res.status(422).json({ error: "This finding is not merged — no sub-issues to update." });
      return;
    }

    // Sub-index must fall within the appropriate sub-array for the scan type.
    const subArray =
      (raw["locations"]   as unknown[] | undefined) ??
      (raw["occurrences"] as unknown[] | undefined) ??
      null;
    if (!subArray || idx >= subArray.length) {
      res.status(400).json({ error: "Sub-index out of range" });
      return;
    }

    const prevMap = (raw["subStatus"] as Record<string, string> | undefined) ?? {};
    const prev = prevMap[String(idx)] ?? "OPEN";
    const nextMap = { ...prevMap, [String(idx)]: status };
    // Prune entries that revert back to OPEN to keep rawOutput tidy.
    if (status === "OPEN") delete nextMap[String(idx)];

    const updated = await prisma.finding.update({
      where: { id: finding.id },
      data: { rawOutput: { ...raw, subStatus: nextMap } },
    });

    if (prev !== status) {
      await audit.log({
        orgId:        req.orgId!,
        userId:       user.id,
        action:       "finding.sub_status_change",
        resourceType: "Finding",
        resourceId:   finding.id,
        metadata:     { subIndex: idx, from: prev, to: status, scanType: finding.scanType },
      });
    }

    res.json({
      id:        updated.id,
      subIndex:  idx,
      status,
      subStatus: nextMap,
    });
  } catch (err) { next(err); }
});

// Update finding status / confidence — SECURITY+
router.patch("/:id", requireRole("SECURITY"), async (req, res, next) => {
  try {
    const body = updateFindingSchema.parse(req.body);
    const user = req.user as { id: string };
    const finding = await prisma.finding.findFirst({
      where: { id: req.params["id"], orgId: req.orgId! },
    });
    if (!finding) { res.status(404).json({ error: "Finding not found" }); return; }

    const updated = await prisma.finding.update({
      where: { id: finding.id },
      data: {
        ...(body.status && {
          status: body.status,
          resolvedAt: body.status === "FIXED" ? new Date() : null,
        }),
      },
    });

    if (body.status && body.status !== finding.status) {
      await audit.log({
        orgId:        req.orgId!,
        userId:       user.id,
        action:       "finding.status_change",
        resourceType: "Finding",
        resourceId:   finding.id,
        metadata:     { from: finding.status, to: body.status, title: finding.title },
      });
    }

    res.json(updated);
  } catch (err) { next(err); }
});

// ── Verify a finding (re-run the specific check) ──────────────────────────
router.post("/:id/verify", async (req, res, next) => {
  try {
    const user = req.user as { id: string };
    const member = await prisma.organizationMember.findFirst({ where: { userId: user.id } });
    const finding = await prisma.finding.findFirst({
      where: { id: req.params["id"], orgId: member?.orgId },
      include: { domain: true, repository: true, container: true },
    });
    if (!finding) { res.status(404).json({ error: "Finding not found" }); return; }

    // Only DAST and PENTEST_FULL findings support live re-verification
    if (!["DAST", "PENTEST_FULL"].includes(finding.scanType)) {
      res.status(422).json({
        error: "Live verification is only available for DAST and PENTEST_FULL findings.",
        confidence: finding.confidence,
      });
      return;
    }

    const targetUrl = finding.domain?.domain
      ? `https://${finding.domain.domain}`
      : null;

    if (!targetUrl) {
      res.status(422).json({ error: "Cannot determine target URL for this finding." });
      return;
    }

    // Route to correct scanner service
    const scannerUrl = finding.scanType === "PENTEST_FULL" && config.SCANNER_PENTEST_URL
      ? config.SCANNER_PENTEST_URL
      : config.SCANNER_URL;

    const verifyResp = await axios.post(
      `${scannerUrl}/verify`,
      { rule_id: finding.ruleId, target_url: targetUrl, scan_type: finding.scanType },
      { timeout: 30_000 }
    );

    const { confirmed, confidence, evidence } = verifyResp.data as {
      confirmed: boolean;
      confidence: string;
      evidence: Record<string, unknown>;
    };

    // Update the finding with fresh confidence + evidence
    const updated = await prisma.finding.update({
      where: { id: finding.id },
      data: {
        confidence: confidence as "CONFIRMED" | "LIKELY" | "POSSIBLE",
        evidence: evidence as object,
        verifiedAt: new Date(),
        // If verification says it no longer exists, mark as FIXED
        ...(finding.status === "OPEN" && confidence === "POSSIBLE" && !confirmed && {
          status: "FIXED",
          resolvedAt: new Date(),
        }),
      },
    });

    res.json({ confirmed, confidence, evidence, finding: updated });
  } catch (err) { next(err); }
});

// ── AI Analysis ───────────────────────────────────────────────────────────────
// POST /api/findings/:id/analyse
// Returns cached analysis instantly, or generates a fresh one via Ollama.
// Pass ?force=true to regenerate even when a cached result exists.
router.post("/:id/analyse", async (req, res, next) => {
  try {
    const user = req.user as { id: string };
    const member = await prisma.organizationMember.findFirst({ where: { userId: user.id } });
    const finding = await prisma.finding.findFirst({
      where: { id: req.params["id"], orgId: member?.orgId },
    });
    if (!finding) { res.status(404).json({ error: "Finding not found" }); return; }

    const force = req.query["force"] === "true";
    const analysis = await analyseFinding(finding.id, force);

    // Return fresh record so client has the updated aiAnalysedAt timestamp
    const updated = await prisma.finding.findUniqueOrThrow({ where: { id: finding.id } });
    res.json({ analysis, aiAnalysedAt: updated.aiAnalysedAt });
  } catch (err) { next(err); }
});

// ── AI False Positive Check ────────────────────────────────────────────────────
// POST /api/findings/:id/check-fp
// Returns cached result instantly; pass ?force=true to regenerate.
router.post("/:id/check-fp", async (req, res, next) => {
  try {
    const user   = req.user as { id: string };
    const member = await prisma.organizationMember.findFirst({ where: { userId: user.id } });
    const finding = await prisma.finding.findFirst({
      where: { id: req.params["id"], orgId: member?.orgId },
    });
    if (!finding) { res.status(404).json({ error: "Finding not found" }); return; }

    const force    = req.query["force"] === "true";
    const analysis = await checkFalsePositive(finding.id, force);

    const updated = await prisma.finding.findUniqueOrThrow({ where: { id: finding.id } });
    res.json({ analysis, aiFpAnalysedAt: updated.aiFpAnalysedAt });
  } catch (err) { next(err); }
});

// ── AI Fix Suggestion ─────────────────────────────────────────────────────────
// POST /api/findings/:id/fix
// Returns cached diff instantly; pass ?force=true to regenerate.
router.post("/:id/fix", async (req, res, next) => {
  try {
    const user    = req.user as { id: string };
    const member  = await prisma.organizationMember.findFirst({ where: { userId: user.id } });
    const finding = await prisma.finding.findFirst({
      where: { id: req.params["id"], orgId: member?.orgId },
    });
    if (!finding) { res.status(404).json({ error: "Finding not found" }); return; }

    const force = req.query["force"] === "true";
    // Optional sub-location index: when present, generate a per-location diff
    // for merged SAST findings instead of the shared primary-location diff.
    const locIdxRaw = req.query["locationIndex"];
    const locationIndex = typeof locIdxRaw === "string" && /^\d+$/.test(locIdxRaw)
      ? Number(locIdxRaw)
      : undefined;

    const diff  = await generateFixSuggestion(finding.id, force, locationIndex);

    const updated = await prisma.finding.findUniqueOrThrow({ where: { id: finding.id } });
    res.json({ diff, aiFixSuggestedAt: updated.aiFixSuggestedAt });
  } catch (err) { next(err); }
});

export default router;
