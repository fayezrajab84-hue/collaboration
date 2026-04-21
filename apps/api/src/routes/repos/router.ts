import { Router } from "express";
import { requireAuth } from "../../middleware/requireAuth.js";
import { requireRole } from "../../middleware/requireRole.js";
import prisma from "../../db.js";
import * as audit from "../../services/auditService.js";
import * as gh from "../../github/client.js";
import { createRepoSchema, updateRepoSchema, triggerScanSchema } from "./validators.js";
import { scoreTarget } from "../../services/riskScoringService.js";
import { encrypt } from "../../services/encryptionService.js";
import { randomBytes } from "crypto";
import { triggerScan } from "../../services/scanService.js";
import { generateRepoSbom } from "../../services/sbomService.js";
import type { ScanType } from "@devsecops/types";

const router = Router();
router.use(requireAuth);

// List repos
router.get("/", async (req, res, next) => {
  try {
    const user = req.user as { id: string };
    const member = await prisma.organizationMember.findFirst({ where: { userId: user.id } });
    if (!member) { res.json([]); return; }

    const [repos, countRows] = await Promise.all([
      prisma.repository.findMany({ where: { orgId: member.orgId }, orderBy: { addedAt: "desc" } }),
      prisma.finding.groupBy({
        by: ["repositoryId", "severity"],
        where: { orgId: member.orgId, repositoryId: { not: null }, status: { not: "FALSE_POSITIVE" } },
        _count: { id: true },
      }),
    ]);

    const countMap: Record<string, Record<string, number>> = {};
    for (const row of countRows) {
      const rid = row.repositoryId!;
      if (!countMap[rid]) countMap[rid] = {};
      countMap[rid][row.severity] = row._count.id;
    }

    const result = repos.map((r) => ({
      ...r,
      findingCounts: {
        CRITICAL: countMap[r.id]?.CRITICAL ?? 0,
        HIGH: countMap[r.id]?.HIGH ?? 0,
        MEDIUM: countMap[r.id]?.MEDIUM ?? 0,
        LOW: countMap[r.id]?.LOW ?? 0,
      },
    }));

    res.json(result);
  } catch (err) { next(err); }
});

// Add repo
router.post("/", async (req, res, next) => {
  try {
    const body = createRepoSchema.parse(req.body);
    const parsed = gh.parseGitHubUrl(body.githubUrl);
    if (!parsed) { res.status(400).json({ error: "Invalid GitHub URL" }); return; }

    const user = req.user as { id: string };
    const dbUser = await prisma.user.findUnique({ where: { id: user.id } });
    if (!dbUser) { res.status(404).json({ error: "User not found" }); return; }

    const member = await prisma.organizationMember.findFirst({ where: { userId: user.id } });
    if (!member) { res.status(400).json({ error: "No organization found" }); return; }

    // Verify repo exists & user has access
    const ghRepo = await gh.getRepo(dbUser.accessToken, parsed.owner, parsed.name);

    // Check not already added
    const existing = await prisma.repository.findUnique({ where: { githubId: ghRepo.id } });
    if (existing) { res.status(409).json({ error: "Repository already added" }); return; }

    // Generate webhook secret
    const webhookSecret = randomBytes(32).toString("hex");
    const encryptedWebhookSecret = encrypt(webhookSecret);

    // Create repo in DB
    const repo = await prisma.repository.create({
      data: {
        orgId: member.orgId,
        githubId: ghRepo.id,
        fullName: ghRepo.full_name,
        url: ghRepo.html_url,
        defaultBranch: body.defaultBranch ?? ghRepo.default_branch,
        isPrivate: ghRepo.private,
        language: ghRepo.language,
        webhookSecret: encryptedWebhookSecret,
      },
    });

    // Register webhook on GitHub (best-effort)
    const webhook = await gh.createWebhook(
      dbUser.accessToken,
      parsed.owner,
      parsed.name,
      gh.getWebhookUrl(),
      webhookSecret
    );
    if (webhook) {
      await prisma.repository.update({
        where: { id: repo.id },
        data: { webhookId: webhook.id },
      });
    }

    res.status(201).json(repo);
  } catch (err) { next(err); }
});

// GET /api/repos/github — list the user's GitHub repos available to add
// Returns each repo with an `added` flag so the frontend can disable ones already tracked.
router.get("/github", async (req, res, next) => {
  try {
    const user   = req.user as { id: string };
    const dbUser = await prisma.user.findUnique({ where: { id: user.id } });
    if (!dbUser) { res.status(404).json({ error: "User not found" }); return; }
    const member = await prisma.organizationMember.findFirst({ where: { userId: user.id } });
    if (!member) { res.status(400).json({ error: "No organization found" }); return; }

    const page = Math.max(1, parseInt((req.query["page"] as string) || "1", 10));
    const ghRepos = await gh.listUserRepos(dbUser.accessToken, page);

    const existing = await prisma.repository.findMany({
      where: { orgId: member.orgId, githubId: { in: ghRepos.map((r) => r.id) } },
      select: { githubId: true },
    });
    const addedSet = new Set(existing.map((e) => e.githubId));

    res.json(
      ghRepos.map((r) => ({
        id:            r.id,
        fullName:      r.full_name,
        url:           r.html_url,
        defaultBranch: r.default_branch,
        isPrivate:     r.private,
        language:      r.language,
        added:         addedSet.has(r.id),
      })),
    );
  } catch (err) { next(err); }
});

// Get repo
router.get("/:id", async (req, res, next) => {
  try {
    const user = req.user as { id: string };
    const member = await prisma.organizationMember.findFirst({ where: { userId: user.id } });
    const repo = await prisma.repository.findFirst({
      where: { id: req.params["id"], orgId: member?.orgId },
    });
    if (!repo) { res.status(404).json({ error: "Repository not found" }); return; }
    res.json(repo);
  } catch (err) { next(err); }
});

// Update repo
router.patch("/:id", async (req, res, next) => {
  try {
    const body = updateRepoSchema.parse(req.body);
    const user = req.user as { id: string };
    const member = await prisma.organizationMember.findFirst({ where: { userId: user.id } });
    const repo = await prisma.repository.findFirst({
      where: { id: req.params["id"], orgId: member?.orgId },
    });
    if (!repo) { res.status(404).json({ error: "Repository not found" }); return; }
    const updated = await prisma.repository.update({
      where: { id: repo.id },
      data: { ...(body.defaultBranch && { defaultBranch: body.defaultBranch }) },
    });
    res.json(updated);
  } catch (err) { next(err); }
});

// Delete repo — ADMIN+
router.delete("/:id", requireRole("ADMIN"), async (req, res, next) => {
  try {
    const user = req.user as { id: string };
    const repo = await prisma.repository.findFirst({
      where: { id: req.params["id"], orgId: req.orgId! },
    });
    if (!repo) { res.status(404).json({ error: "Repository not found" }); return; }
    await prisma.repository.delete({ where: { id: repo.id } });
    await audit.log({
      orgId:        req.orgId!,
      userId:       user.id,
      action:       "repo.delete",
      resourceType: "Repository",
      resourceId:   repo.id,
      metadata:     { fullName: repo.fullName },
    });
    res.json({ ok: true });
  } catch (err) { next(err); }
});

// Trigger scan
router.post("/:id/scan", async (req, res, next) => {
  try {
    const body = triggerScanSchema.parse(req.body);
    const user = req.user as { id: string };
    const member = await prisma.organizationMember.findFirst({ where: { userId: user.id } });
    const repo = await prisma.repository.findFirst({
      where: { id: req.params["id"], orgId: member?.orgId },
    });
    if (!repo) { res.status(404).json({ error: "Repository not found" }); return; }

    const defaultScanTypes: ScanType[] = ["SAST", "SCA", "SECRET", "IAC"];
    const scanTypes = (body.scanTypes as ScanType[] | undefined) ?? defaultScanTypes;

    const dbUser = await prisma.user.findUnique({ where: { id: user.id } });
    if (!dbUser) { res.status(404).json({ error: "User not found" }); return; }

    const result = await triggerScan({
      orgId: member!.orgId,
      targetType: "REPOSITORY",
      targetId: repo.id,
      scanTypes,
      repoUrl: repo.url,
      branch: body.branch ?? repo.defaultBranch,
      encryptedGitToken: dbUser.accessToken,
    });

    res.status(202).json(result);
  } catch (err) { next(err); }
});

// POST /api/repos/:id/risk-score — regenerate AI risk score on demand
router.post("/:id/risk-score", async (req, res, next) => {
  try {
    const user   = req.user as { id: string };
    const member = await prisma.organizationMember.findFirst({ where: { userId: user.id } });
    const repo   = await prisma.repository.findFirst({ where: { id: req.params["id"], orgId: member?.orgId } });
    if (!repo) { res.status(404).json({ error: "Repository not found" }); return; }
    await scoreTarget("REPOSITORY", repo.id);
    const updated = await prisma.repository.findUniqueOrThrow({ where: { id: repo.id } });
    res.json({ aiRiskScore: updated.aiRiskScore, aiRiskReason: updated.aiRiskReason, aiRiskScoredAt: updated.aiRiskScoredAt });
  } catch (err) { next(err); }
});

// GET /api/repos/:id/sbom — CycloneDX SBOM download
router.get("/:id/sbom", async (req, res, next) => {
  try {
    const user   = req.user as { id: string };
    const member = await prisma.organizationMember.findFirst({ where: { userId: user.id } });
    const repo   = await prisma.repository.findFirst({
      where: { id: req.params["id"], orgId: member?.orgId },
    });
    if (!repo) { res.status(404).json({ error: "Repository not found" }); return; }
    const dbUser = await prisma.user.findUnique({ where: { id: user.id } });
    if (!dbUser) { res.status(404).json({ error: "User not found" }); return; }

    const sbom = await generateRepoSbom({
      repoUrl:           repo.url,
      branch:            repo.defaultBranch,
      encryptedGitToken: dbUser.accessToken,
    });

    const safeName = repo.fullName.replace(/[^a-zA-Z0-9._-]/g, "_");
    res.setHeader("Content-Type", "application/vnd.cyclonedx+json");
    res.setHeader("Content-Disposition", `attachment; filename="${safeName}-sbom.cdx.json"`);
    res.send(JSON.stringify(sbom, null, 2));
  } catch (err) { next(err); }
});

export default router;
