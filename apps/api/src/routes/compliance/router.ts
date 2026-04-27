/**
 * Compliance dashboard routes (Phase 16 Slice C).
 *
 * Three endpoints — all org-scoped via getActiveMembership(req), all
 * VIEWER+ (read-only). Aggregations are computed server-side because
 * the matrix-style numbers (control × severity × status) would be
 * tedious to assemble in the UI from raw findings.
 *
 *   GET  /api/compliance/frameworks
 *        → list every seeded framework with high-level totals
 *
 *   GET  /api/compliance/:framework/dashboard
 *        → per-control breakdown (open, total, severity, status) for
 *          the named framework. The page-level data the dashboard
 *          renders.
 *
 *   GET  /api/compliance/:framework/controls/:code/findings
 *        → paginated drill-down of findings mapped to one control.
 *          Used when an auditor clicks a control row to see "show
 *          me what's actually wrong here".
 *
 * Slice E (PDF / CSV evidence export) will add ADMIN-gated export
 * endpoints under the same prefix.
 */

import { Router } from "express";
import { requireAuth } from "../../middleware/requireAuth.js";
import { requireRole } from "../../middleware/requireRole.js";
import prisma from "../../db.js";
import { getActiveMembership } from "../../services/activeOrgService.js";
import * as audit from "../../services/auditService.js";
import {
  buildComplianceCsv,
  buildComplianceHtml,
} from "../../services/complianceExportService.js";
import type { ComplianceFramework } from "@prisma/client";

const router = Router();
router.use(requireAuth);

// Human-friendly display labels for frameworks. Kept here (not on the
// model) because the frontend may want them too — exposing via the
// /frameworks endpoint avoids a second hardcoded map in the UI.
const FRAMEWORK_LABELS: Record<ComplianceFramework, string> = {
  OWASP_TOP_10: "OWASP Top 10 2021",
  SOC2:         "SOC 2 — Trust Services Criteria",
  PCI_DSS:      "PCI DSS 4.0",
};

// Type guard so we can return 400 instead of leaking Prisma errors when
// the caller passes a typo'd framework name in the URL.
function isFramework(s: string): s is ComplianceFramework {
  return Object.prototype.hasOwnProperty.call(FRAMEWORK_LABELS, s);
}

// ── GET /api/compliance/frameworks ─────────────────────────────────────────
//
// Top-level "what frameworks does BreachLens know about, and how many
// findings hit each in this org" summary. Drives the framework picker
// in the UI; also useful as a single API call to power the auditor
// elevator pitch ("8 of 10 OWASP Top 10 categories have open findings
// in this org right now").

router.get("/frameworks", async (req, res, next) => {
  try {
    const member = await getActiveMembership(req);
    if (!member) { res.json({ frameworks: [] }); return; }

    // Pull every control + the org-scoped finding counts in two queries.
    // Cheap because frameworks/controls are tiny (~26 rows total today).
    const [controls, mappingsByControl] = await Promise.all([
      prisma.complianceControl.findMany({
        select: { id: true, framework: true },
      }),
      prisma.findingControl.groupBy({
        by:    ["controlId"],
        where: {
          finding: { orgId: member.orgId, status: "OPEN" },
        },
        _count: { _all: true },
      }),
    ]);

    const openByControl = new Map(
      mappingsByControl.map((m) => [m.controlId, m._count._all]),
    );

    // Aggregate per framework.
    const summary = new Map<ComplianceFramework, {
      controlCount:         number;
      controlsWithFindings: number;
      openFindingCount:     number;
    }>();
    for (const fw of Object.keys(FRAMEWORK_LABELS) as ComplianceFramework[]) {
      summary.set(fw, { controlCount: 0, controlsWithFindings: 0, openFindingCount: 0 });
    }
    for (const c of controls) {
      const s = summary.get(c.framework)!;
      s.controlCount += 1;
      const open = openByControl.get(c.id) ?? 0;
      if (open > 0) {
        s.controlsWithFindings += 1;
        s.openFindingCount     += open;
      }
    }

    res.json({
      frameworks: Array.from(summary.entries()).map(([framework, s]) => ({
        framework,
        label:                FRAMEWORK_LABELS[framework],
        controlCount:         s.controlCount,
        controlsWithFindings: s.controlsWithFindings,
        openFindingCount:     s.openFindingCount,
      })),
    });
  } catch (err) { next(err); }
});

// ── GET /api/compliance/:framework/dashboard ──────────────────────────────
//
// Per-control matrix for one framework. Each control row carries:
//   - total / open / acknowledged / fixed / falsePositive / ignored counts
//   - severity histogram of OPEN findings (CRITICAL → INFO)
//
// Computed server-side via groupBy. With ~10 controls × 5 severities × 5
// statuses we're at ≤250 cells — not a perf concern.

router.get("/:framework/dashboard", async (req, res, next) => {
  try {
    const fw = req.params["framework"]!;
    if (!isFramework(fw)) { res.status(400).json({ error: `Unknown framework: ${fw}` }); return; }

    const member = await getActiveMembership(req);
    if (!member) { res.json({ framework: fw, label: FRAMEWORK_LABELS[fw], controls: [] }); return; }

    const controls = await prisma.complianceControl.findMany({
      where:   { framework: fw },
      orderBy: [{ sortOrder: "asc" }, { code: "asc" }],
    });

    // One query that returns (controlId, status, severity) → count, then
    // bucket in JS. Simpler than 25 queries and cheap (≤250 rows).
    const buckets = await prisma.findingControl.groupBy({
      by:    ["controlId"],
      where: {
        finding:   { orgId: member.orgId },
        controlId: { in: controls.map((c) => c.id) },
      },
      _count: { _all: true },
    });

    // We also need severity + status breakdowns per control. Easiest
    // path is one more groupBy that includes finding fields — but
    // Prisma's groupBy doesn't traverse relations. Pull the raw mappings
    // + finding fields in one query and reduce in JS.
    const mappings = await prisma.findingControl.findMany({
      where: {
        finding:   { orgId: member.orgId },
        controlId: { in: controls.map((c) => c.id) },
      },
      select: {
        controlId: true,
        finding:   { select: { severity: true, status: true, reachability: true } },
      },
    });

    type Row = {
      total: number;
      open: number; acknowledged: number; fixed: number; falsePositive: number; ignored: number;
      severity: { CRITICAL: number; HIGH: number; MEDIUM: number; LOW: number; INFO: number };
    };
    const empty = (): Row => ({
      total: 0,
      open: 0, acknowledged: 0, fixed: 0, falsePositive: 0, ignored: 0,
      severity: { CRITICAL: 0, HIGH: 0, MEDIUM: 0, LOW: 0, INFO: 0 },
    });
    const stats = new Map<string, Row>();
    for (const c of controls) stats.set(c.id, empty());

    // Phase 14 — framework-wide reachability summary. Drives the
    // "noise reduction" stat in the dashboard header ("of N open
    // findings, K can't actually be reached → focus on the other
    // N-K"). Counted across all controls in this framework, OPEN
    // status only — fixed/acknowledged/FP findings aren't part of
    // the active triage backlog.
    const reachabilitySummary = {
      reachable:     0,
      notReachable:  0,
      unknown:       0,
      notApplicable: 0,
    };

    for (const m of mappings) {
      const r = stats.get(m.controlId);
      if (!r) continue;
      r.total += 1;
      switch (m.finding.status) {
        case "OPEN":           r.open           += 1; break;
        case "ACKNOWLEDGED":   r.acknowledged   += 1; break;
        case "FIXED":          r.fixed          += 1; break;
        case "FALSE_POSITIVE": r.falsePositive  += 1; break;
        case "IGNORED":        r.ignored        += 1; break;
      }
      // Only include OPEN in the severity histogram — that's the
      // auditor-relevant "what's currently broken" view.
      if (m.finding.status === "OPEN") {
        const sev = m.finding.severity as keyof Row["severity"];
        if (sev in r.severity) r.severity[sev] += 1;
        switch (m.finding.reachability) {
          case "REACHABLE":      reachabilitySummary.reachable     += 1; break;
          case "NOT_REACHABLE":  reachabilitySummary.notReachable  += 1; break;
          case "UNKNOWN":        reachabilitySummary.unknown       += 1; break;
          case "NOT_APPLICABLE": reachabilitySummary.notApplicable += 1; break;
        }
      }
    }

    res.json({
      framework: fw,
      label:     FRAMEWORK_LABELS[fw],
      // Sanity field — useful for the UI to show "0 findings" empty state
      // without re-summing the row counts.
      totalMappings: buckets.reduce((acc, b) => acc + b._count._all, 0),
      reachabilitySummary,
      controls: controls.map((c) => ({
        id:          c.id,
        code:        c.code,
        name:        c.name,
        description: c.description,
        category:    c.category,
        sortOrder:   c.sortOrder,
        cweIds:      c.cweIds,
        ...(stats.get(c.id) ?? empty()),
      })),
    });
  } catch (err) { next(err); }
});

// ── GET /api/compliance/:framework/controls/:code/findings ────────────────
//
// Drill-down: given a framework + control code (e.g. "A01:2021"), return
// the actual findings that satisfy it. Paginated. Status filter optional
// (default: only OPEN — the auditor-relevant default).
//
// 404 if the framework/code combo doesn't exist (vs returning empty),
// because an empty list is a valid answer for a real control with zero
// findings — distinguishing "no such control" from "control has no
// findings" matters for UI.

router.get("/:framework/controls/:code/findings", async (req, res, next) => {
  try {
    const fw   = req.params["framework"]!;
    const code = req.params["code"]!;
    if (!isFramework(fw)) { res.status(400).json({ error: `Unknown framework: ${fw}` }); return; }

    const member = await getActiveMembership(req);
    if (!member) { res.json({ control: null, findings: [], total: 0, page: 1, limit: 20 }); return; }

    const control = await prisma.complianceControl.findUnique({
      where: { framework_code: { framework: fw, code } },
    });
    if (!control) { res.status(404).json({ error: `No control ${code} in ${fw}` }); return; }

    const status = typeof req.query["status"] === "string" ? req.query["status"] : "OPEN";
    const page   = Math.max(1,  Number(req.query["page"]  ?? 1));
    const limit  = Math.min(100, Math.max(1, Number(req.query["limit"] ?? 20)));
    const skip   = (page - 1) * limit;

    // Build the where clause: findings in this org that are mapped to
    // this control AND match the requested status (or any status if
    // status="ALL").
    const findingWhere = {
      orgId: member.orgId,
      ...(status === "ALL" ? {} : { status: status as "OPEN" | "ACKNOWLEDGED" | "FIXED" | "FALSE_POSITIVE" | "IGNORED" }),
      complianceMappings: {
        some: { controlId: control.id },
      },
    };

    const [findings, total] = await Promise.all([
      prisma.finding.findMany({
        where:   findingWhere,
        orderBy: [{ severity: "asc" }, { firstSeen: "desc" }],
        skip, take: limit,
        select: {
          id: true, title: true, description: true, severity: true, status: true,
          scanType: true, scanner: true, cweId: true, cveId: true,
          packageName: true, packageVersion: true, fixVersion: true,
          filePath: true, lineStart: true, firstSeen: true, lastSeen: true,
          repositoryId: true, containerId: true, domainId: true,
          confidence: true,
          // Phase 14 — show the reachability badge in the compliance
          // drill-down too. Auditors care about REACHABLE first.
          reachability: true, reachabilityEvidence: true,
        },
      }),
      prisma.finding.count({ where: findingWhere }),
    ]);

    res.json({
      control: {
        id:          control.id,
        framework:   control.framework,
        code:        control.code,
        name:        control.name,
        description: control.description,
        category:    control.category,
      },
      findings,
      total,
      page,
      limit,
    });
  } catch (err) { next(err); }
});

// ── Evidence export (Slice E) ─────────────────────────────────────────────
//
// Two formats:
//   * CSV  — RFC 4180, one row per (control × finding) tuple. Suitable for
//            attaching to a SOC 2 evidence folder, importing into auditor
//            spreadsheets, or running ad-hoc analysis.
//   * HTML — printable, self-contained, no external assets. Auditors open
//            in a browser → "Save as PDF" / Cmd-P. Matches the existing
//            reportHtmlService pattern; avoids adding a heavy PDF runtime.
//
// Both ADMIN+ (auditor-facing data; same gate as the audit log itself).
// Audit-logged so you can answer "who exported what compliance evidence
// when" if that question ever shows up in a security-program review.

router.get("/:framework/export.csv", requireRole("ADMIN"), async (req, res, next) => {
  try {
    const fw = req.params["framework"]!;
    if (!isFramework(fw)) { res.status(400).json({ error: `Unknown framework: ${fw}` }); return; }
    const member = await getActiveMembership(req);
    if (!member) { res.status(403).json({ error: "No organization membership" }); return; }

    const csv = await buildComplianceCsv(member.orgId, fw);

    await audit.log({
      orgId:        member.orgId,
      userId:       (req.user as { id: string }).id,
      action:       "compliance.export.csv",
      resourceType: "ComplianceFramework",
      resourceId:   fw,
      metadata:     { framework: fw, format: "csv", rowCount: (csv.match(/\n/g)?.length ?? 1) - 1 },
    });

    const filename = `${fw}-evidence-${new Date().toISOString().split("T")[0]}.csv`;
    res.setHeader("Content-Type",        "text/csv; charset=utf-8");
    res.setHeader("Content-Disposition", `attachment; filename="${filename}"`);
    res.send(csv);
  } catch (err) { next(err); }
});

router.get("/:framework/export.html", requireRole("ADMIN"), async (req, res, next) => {
  try {
    const fw = req.params["framework"]!;
    if (!isFramework(fw)) { res.status(400).json({ error: `Unknown framework: ${fw}` }); return; }
    const member = await getActiveMembership(req);
    if (!member) { res.status(403).json({ error: "No organization membership" }); return; }

    const html = await buildComplianceHtml(member.orgId, fw, FRAMEWORK_LABELS[fw]);

    await audit.log({
      orgId:        member.orgId,
      userId:       (req.user as { id: string }).id,
      action:       "compliance.export.html",
      resourceType: "ComplianceFramework",
      resourceId:   fw,
      metadata:     { framework: fw, format: "html" },
    });

    const filename = `${fw}-evidence-${new Date().toISOString().split("T")[0]}.html`;
    res.setHeader("Content-Type",        "text/html; charset=utf-8");
    res.setHeader("Content-Disposition", `attachment; filename="${filename}"`);
    res.send(html);
  } catch (err) { next(err); }
});

export default router;
