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

    // Suppression filter — hide suppressed findings unless ?includeSuppressed=true
    const includeSuppressed = q["includeSuppressed"] === "true";
    if (!includeSuppressed) {
      const suppressed = await activeSuppressedFingerprints(member.orgId);
      if (suppressed.size > 0) {
        where["fingerprint"] = { notIn: Array.from(suppressed) };
      }
    }

    const [data, total] = await Promise.all([
      prisma.finding.findMany({
        where,
        orderBy: [{ severity: "asc" }, { firstSeen: "desc" }],
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
