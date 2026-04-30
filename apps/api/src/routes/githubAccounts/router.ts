/**
 * /api/github-accounts — Phase 29 Slice C1.
 *
 * CRUD over the GitHubAccount asset model (GitHub posture target).
 * Mirrors the shape of /api/cloud-accounts so the web UI can reuse
 * the same react-query + modal pattern.
 *
 * Two auth paths via discriminator:
 *   - APP_INSTALLATION (preferred): operator supplies installationId,
 *     encryptedCredentials stays null. Token mints on demand.
 *   - PAT (fallback): operator pastes a Personal Access Token, gets
 *     encrypted at rest via encryptionService.
 *
 * Routes:
 *   GET    /                     list (orgId-scoped, with finding counts)
 *   POST   /                     create
 *   GET    /:id                  fetch one (encrypted blob never returned)
 *   PATCH  /:id                  update display name / re-paste token / toggle active
 *   DELETE /:id                  ADMIN+ — cascade-deletes scans + findings
 *   POST   /:id/test-connection  validate stored credentials hit GitHub
 *   POST   /:id/scan             trigger a GITHUB_POSTURE scan
 *   POST   /test-connection-inline  validate raw creds before save
 */
import { Router } from "express";
import { z } from "zod";
import { requireAuth } from "../../middleware/requireAuth.js";
import { requireRole } from "../../middleware/requireRole.js";
import prisma from "../../db.js";
import { getActiveMembership } from "../../services/activeOrgService.js";
import { encrypt } from "../../services/encryptionService.js";
import { testGitHubConnection } from "../../services/github/githubAccountAuth.js";
import { triggerScan } from "../../services/scanService.js";
import * as audit from "../../services/auditService.js";
import type { ScanType } from "@devsecops/types";

const router = Router();
router.use(requireAuth);

// ── Validators ──────────────────────────────────────────────────────────

const accountTypeSchema = z.enum(["USER", "ORGANIZATION"]);
const accountLoginSchema = z.string().min(1).max(100).regex(/^[A-Za-z0-9](?:[A-Za-z0-9-]{0,38}[A-Za-z0-9])?$/, "must be a valid GitHub login");

// Discriminated create — exactly one of installationId / token must be set.
const createSchema = z.object({
  displayName:    z.string().min(1).max(100),
  accountLogin:   accountLoginSchema,
  accountType:    accountTypeSchema,
  installationId: z.number().int().positive().optional(),
  token:          z.string().min(20).optional(),  // PAT — `ghp_` / `github_pat_` etc are 40+ chars
}).refine(
  (v) => Boolean(v.installationId) !== Boolean(v.token),
  { message: "Provide exactly one of installationId or token" },
);

const updateSchema = z.object({
  displayName:    z.string().min(1).max(100).optional(),
  accountLogin:   accountLoginSchema.optional(),
  accountType:    accountTypeSchema.optional(),
  installationId: z.number().int().positive().nullable().optional(),
  token:          z.string().min(20).optional(),
  isActive:       z.boolean().optional(),
});

const testInlineSchema = z.object({
  accountLogin:   accountLoginSchema,
  accountType:    accountTypeSchema,
  installationId: z.number().int().positive().optional(),
  token:          z.string().min(20).optional(),
}).refine(
  (v) => Boolean(v.installationId) !== Boolean(v.token),
  { message: "Provide exactly one of installationId or token" },
);

// ── Helpers ─────────────────────────────────────────────────────────────

type GitHubAccountRow = {
  id:                   string;
  orgId:                string;
  displayName:          string;
  accountLogin:         string;
  accountType:          string;
  installationId:       number | null;
  encryptedCredentials: string | null;
  isActive:             boolean;
  lastScannedAt:        Date | null;
  lastScanError:        string | null;
  addedAt:              Date;
  updatedAt:            Date;
};

function shapeForClient(row: GitHubAccountRow) {
  const { encryptedCredentials, ...rest } = row;
  return {
    ...rest,
    credentialsConfigured: encryptedCredentials != null || row.installationId != null,
  };
}

// ── Routes ──────────────────────────────────────────────────────────────

router.get("/", async (req, res, next) => {
  try {
    const member = await getActiveMembership(req);
    if (!member) { res.json([]); return; }

    const [rows, countRows] = await Promise.all([
      prisma.gitHubAccount.findMany({
        where:   { orgId: member.orgId },
        orderBy: { addedAt: "desc" },
      }),
      prisma.finding.groupBy({
        by:    ["githubAccountId", "severity"],
        where: { orgId: member.orgId, githubAccountId: { not: null }, status: { not: "FALSE_POSITIVE" } },
        _count: { id: true },
      }),
    ]);

    const countMap: Record<string, Record<string, number>> = {};
    for (const r of countRows) {
      const id = r.githubAccountId!;
      if (!countMap[id]) countMap[id] = {};
      countMap[id][r.severity] = r._count.id;
    }

    res.json(rows.map((r) => ({
      ...shapeForClient(r),
      findingCounts: {
        CRITICAL: countMap[r.id]?.CRITICAL ?? 0,
        HIGH:     countMap[r.id]?.HIGH     ?? 0,
        MEDIUM:   countMap[r.id]?.MEDIUM   ?? 0,
        LOW:      countMap[r.id]?.LOW      ?? 0,
      },
    })));
  } catch (err) { next(err); }
});

router.post("/", async (req, res, next) => {
  try {
    const body   = createSchema.parse(req.body);
    const user   = req.user as { id: string };
    const member = await getActiveMembership(req);
    if (!member) { res.status(400).json({ error: "No organization found" }); return; }

    const encryptedCredentials = body.token
      ? encrypt(JSON.stringify({ token: body.token }))
      : null;

    try {
      const created = await prisma.gitHubAccount.create({
        data: {
          orgId:          member.orgId,
          displayName:    body.displayName,
          accountLogin:   body.accountLogin,
          accountType:    body.accountType,
          installationId: body.installationId ?? null,
          encryptedCredentials,
        },
      });
      await audit.log({
        orgId:        member.orgId,
        userId:       user.id,
        action:       "github_account.create",
        resourceType: "GitHubAccount",
        resourceId:   created.id,
        metadata:     { accountLogin: body.accountLogin, accountType: body.accountType, authPath: body.installationId ? "APP" : "PAT" },
      });
      res.status(201).json(shapeForClient(created));
    } catch (e: unknown) {
      if (e && typeof e === "object" && (e as { code?: string }).code === "P2002") {
        res.status(409).json({ error: "A GitHub account with this login already exists in this organisation" });
        return;
      }
      throw e;
    }
  } catch (err) { next(err); }
});

router.get("/:id", async (req, res, next) => {
  try {
    const member = await getActiveMembership(req);
    const row = await prisma.gitHubAccount.findFirst({
      where: { id: req.params["id"], orgId: member?.orgId },
    });
    if (!row) { res.status(404).json({ error: "GitHub account not found" }); return; }
    res.json(shapeForClient(row));
  } catch (err) { next(err); }
});

router.patch("/:id", async (req, res, next) => {
  try {
    const body   = updateSchema.parse(req.body);
    const user   = req.user as { id: string };
    const member = await getActiveMembership(req);
    const row    = await prisma.gitHubAccount.findFirst({
      where: { id: req.params["id"], orgId: member?.orgId },
    });
    if (!row) { res.status(404).json({ error: "GitHub account not found" }); return; }

    const data: Record<string, unknown> = {};
    if (body.displayName    !== undefined) data["displayName"]    = body.displayName;
    if (body.accountLogin   !== undefined) data["accountLogin"]   = body.accountLogin;
    if (body.accountType    !== undefined) data["accountType"]    = body.accountType;
    if (body.installationId !== undefined) data["installationId"] = body.installationId;
    if (body.isActive       !== undefined) data["isActive"]       = body.isActive;
    if (body.token) {
      data["encryptedCredentials"] = encrypt(JSON.stringify({ token: body.token }));
    }

    const updated = await prisma.gitHubAccount.update({ where: { id: row.id }, data });
    await audit.log({
      orgId:        member!.orgId,
      userId:       user.id,
      action:       "github_account.update",
      resourceType: "GitHubAccount",
      resourceId:   updated.id,
      metadata:     { fields: Object.keys(data), credentialsRotated: !!body.token },
    });
    res.json(shapeForClient(updated));
  } catch (err) { next(err); }
});

router.delete("/:id", requireRole("ADMIN"), async (req, res, next) => {
  try {
    const user = req.user as { id: string };
    const row = await prisma.gitHubAccount.findFirst({
      where: { id: req.params["id"], orgId: req.orgId! },
    });
    if (!row) { res.status(404).json({ error: "GitHub account not found" }); return; }
    await prisma.gitHubAccount.delete({ where: { id: row.id } });
    await audit.log({
      orgId:        req.orgId!,
      userId:       user.id,
      action:       "github_account.delete",
      resourceType: "GitHubAccount",
      resourceId:   row.id,
      metadata:     { accountLogin: row.accountLogin, accountType: row.accountType },
    });
    res.json({ ok: true });
  } catch (err) { next(err); }
});

router.post("/:id/test-connection", async (req, res, next) => {
  try {
    const member = await getActiveMembership(req);
    const row = await prisma.gitHubAccount.findFirst({
      where: { id: req.params["id"], orgId: member?.orgId },
    });
    if (!row) { res.status(404).json({ error: "GitHub account not found" }); return; }
    if (!row.encryptedCredentials && !row.installationId) {
      res.status(400).json({ error: "GitHub account has no auth configured" });
      return;
    }

    const result = await testGitHubConnection({
      accountLogin:   row.accountLogin,
      accountType:    row.accountType as "USER" | "ORGANIZATION",
      installationId: row.installationId,
      encryptedCredentials: row.encryptedCredentials,
    });

    await prisma.gitHubAccount.update({
      where: { id: row.id },
      data:  { lastScanError: result.ok ? null : result.message },
    });

    if (result.ok) res.json(result);
    else res.status(422).json(result);
  } catch (err) { next(err); }
});

router.post("/:id/scan", async (req, res, next) => {
  try {
    const user   = req.user as { id: string };
    const member = await getActiveMembership(req);
    if (!member) { res.status(404).json({ error: "GitHub account not found" }); return; }

    const account = await prisma.gitHubAccount.findFirst({
      where: { id: req.params["id"], orgId: member.orgId },
    });
    if (!account) {
      res.status(404).json({ error: "GitHub account not found" });
      return;
    }
    if (!account.encryptedCredentials && !account.installationId) {
      res.status(400).json({ error: "GitHub account has no auth configured. Set an installation or paste a PAT before scanning." });
      return;
    }
    if (!account.isActive) {
      res.status(400).json({ error: "GitHub account is inactive. Activate it before scanning." });
      return;
    }

    const scanTypes: ScanType[] = ["GITHUB_POSTURE"];
    const result = await triggerScan({
      orgId:      member.orgId,
      targetType: "GITHUB_ACCOUNT",
      targetId:   account.id,
      scanTypes,
    });

    await audit.log({
      orgId:        member.orgId,
      userId:       user.id,
      action:       "github_account.scan",
      resourceType: "GitHubAccount",
      resourceId:   account.id,
      metadata:     { scanJobId: result.scanJobId, accountLogin: account.accountLogin },
    });
    res.status(202).json(result);
  } catch (err) { next(err); }
});

router.post("/test-connection-inline", async (req, res, next) => {
  try {
    const body   = testInlineSchema.parse(req.body);
    const member = await getActiveMembership(req);
    if (!member) { res.status(400).json({ error: "No organization found" }); return; }

    // For inline tests with PAT, encrypt-then-pass-through so we use
    // exactly the same auth code path as a saved row would. For App
    // installation, just pass installationId (no encryption needed —
    // App auth derives the token from the App's private key).
    const result = await testGitHubConnection({
      accountLogin:   body.accountLogin,
      accountType:    body.accountType,
      installationId: body.installationId,
      encryptedCredentials: body.token ? encrypt(JSON.stringify({ token: body.token })) : null,
    });

    if (result.ok) res.json(result);
    else res.status(422).json(result);
  } catch (err) { next(err); }
});

export default router;
