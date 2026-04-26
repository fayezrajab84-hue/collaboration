import { Router, type Request } from "express";
import { z } from "zod";
import { requireAuth } from "../../middleware/requireAuth.js";
import prisma from "../../db.js";
import { getActiveMembership } from "../../services/activeOrgService.js";
import { encrypt, decrypt } from "../../services/encryptionService.js";
import * as audit from "../../services/auditService.js";

const router = Router();
router.use(requireAuth);

async function getOrgId(req: Request): Promise<string | null> {
  const member = await getActiveMembership(req);
  return member?.orgId ?? null;
}

// ── Jira ─────────────────────────────────────────────────────────────────

const jiraSchema = z.object({
  host: z.string().url(),
  email: z.string().email(),
  apiToken: z.string().min(1),
  projectKey: z.string().min(1),
  issueType: z.string().optional().default("Bug"),
});

router.put("/jira", async (req, res, next) => {
  try {
    const body = jiraSchema.parse(req.body);
    const user = req.user as { id: string };
    const orgId = await getOrgId(req);
    if (!orgId) { res.status(400).json({ error: "No organization" }); return; }

    const encryptedData = {
      host: encrypt(body.host),
      email: encrypt(body.email),
      apiToken: encrypt(body.apiToken),
      projectKey: encrypt(body.projectKey),
      issueType: encrypt(body.issueType),
    };

    await prisma.integration.upsert({
      where: { orgId_type: { orgId, type: "JIRA" } },
      create: { orgId, type: "JIRA", encryptedData, isActive: true },
      update: { encryptedData, isActive: true },
    });

    await audit.log({
      orgId, userId: user.id,
      action: "integration.jira.upsert", resourceType: "Integration", resourceId: "JIRA",
      metadata: { projectKey: body.projectKey, issueType: body.issueType },
    });

    res.json({ ok: true, type: "JIRA" });
  } catch (err) { next(err); }
});

router.get("/jira", async (req, res, next) => {
  try {
    const user = req.user as { id: string };
    const orgId = await getOrgId(req);
    const integration = orgId
      ? await prisma.integration.findUnique({ where: { orgId_type: { orgId, type: "JIRA" } } })
      : null;

    if (!integration) { res.json(null); return; }
    const cfg = integration.encryptedData as Record<string, string>;
    res.json({
      type: "JIRA",
      isActive: integration.isActive,
      host: decrypt(cfg["host"] as string),
      email: decrypt(cfg["email"] as string),
      apiToken: "***",
      projectKey: decrypt(cfg["projectKey"] as string),
      issueType: decrypt(cfg["issueType"] as string),
    });
  } catch (err) { next(err); }
});

router.delete("/jira", async (req, res, next) => {
  try {
    const user = req.user as { id: string };
    const orgId = await getOrgId(req);
    if (orgId) {
      const result = await prisma.integration.deleteMany({ where: { orgId, type: "JIRA" } });
      if (result.count > 0) {
        await audit.log({
          orgId, userId: user.id,
          action: "integration.jira.delete", resourceType: "Integration", resourceId: "JIRA",
        });
      }
    }
    res.json({ ok: true });
  } catch (err) { next(err); }
});

// ── Slack ─────────────────────────────────────────────────────────────────

const slackSchema = z.object({
  webhookUrl: z.string().url(),
  channel: z.string().optional(),
});

router.put("/slack", async (req, res, next) => {
  try {
    const body = slackSchema.parse(req.body);
    const user = req.user as { id: string };
    const orgId = await getOrgId(req);
    if (!orgId) { res.status(400).json({ error: "No organization" }); return; }

    const encryptedData = {
      webhookUrl: encrypt(body.webhookUrl),
      channel: body.channel ? encrypt(body.channel) : "",
    };

    await prisma.integration.upsert({
      where: { orgId_type: { orgId, type: "SLACK" } },
      create: { orgId, type: "SLACK", encryptedData, isActive: true },
      update: { encryptedData, isActive: true },
    });

    await audit.log({
      orgId, userId: user.id,
      action: "integration.slack.upsert", resourceType: "Integration", resourceId: "SLACK",
      metadata: { hasChannel: !!body.channel },
    });

    res.json({ ok: true, type: "SLACK" });
  } catch (err) { next(err); }
});

router.get("/slack", async (req, res, next) => {
  try {
    const user = req.user as { id: string };
    const orgId = await getOrgId(req);
    const integration = orgId
      ? await prisma.integration.findUnique({ where: { orgId_type: { orgId, type: "SLACK" } } })
      : null;
    if (!integration) { res.json(null); return; }
    res.json({ type: "SLACK", isActive: integration.isActive, webhookUrl: "***configured***" });
  } catch (err) { next(err); }
});

router.delete("/slack", async (req, res, next) => {
  try {
    const user = req.user as { id: string };
    const orgId = await getOrgId(req);
    if (orgId) {
      const result = await prisma.integration.deleteMany({ where: { orgId, type: "SLACK" } });
      if (result.count > 0) {
        await audit.log({
          orgId, userId: user.id,
          action: "integration.slack.delete", resourceType: "Integration", resourceId: "SLACK",
        });
      }
    }
    res.json({ ok: true });
  } catch (err) { next(err); }
});

// ── Microsoft Teams ───────────────────────────────────────────────────────

const teamsSchema = z.object({ webhookUrl: z.string().url() });

router.put("/teams", async (req, res, next) => {
  try {
    const body = teamsSchema.parse(req.body);
    const user = req.user as { id: string };
    const orgId = await getOrgId(req);
    if (!orgId) { res.status(400).json({ error: "No organization" }); return; }

    await prisma.integration.upsert({
      where: { orgId_type: { orgId, type: "MICROSOFT_TEAMS" } },
      create: { orgId, type: "MICROSOFT_TEAMS", encryptedData: { webhookUrl: encrypt(body.webhookUrl) }, isActive: true },
      update: { encryptedData: { webhookUrl: encrypt(body.webhookUrl) }, isActive: true },
    });

    await audit.log({
      orgId, userId: user.id,
      action: "integration.teams.upsert", resourceType: "Integration", resourceId: "MICROSOFT_TEAMS",
    });

    res.json({ ok: true, type: "MICROSOFT_TEAMS" });
  } catch (err) { next(err); }
});

router.get("/teams", async (req, res, next) => {
  try {
    const user = req.user as { id: string };
    const orgId = await getOrgId(req);
    const integration = orgId
      ? await prisma.integration.findUnique({ where: { orgId_type: { orgId, type: "MICROSOFT_TEAMS" } } })
      : null;
    if (!integration) { res.json(null); return; }
    res.json({ type: "MICROSOFT_TEAMS", isActive: integration.isActive, webhookUrl: "***configured***" });
  } catch (err) { next(err); }
});

router.delete("/teams", async (req, res, next) => {
  try {
    const user = req.user as { id: string };
    const orgId = await getOrgId(req);
    if (orgId) {
      const result = await prisma.integration.deleteMany({ where: { orgId, type: "MICROSOFT_TEAMS" } });
      if (result.count > 0) {
        await audit.log({
          orgId, userId: user.id,
          action: "integration.teams.delete", resourceType: "Integration", resourceId: "MICROSOFT_TEAMS",
        });
      }
    }
    res.json({ ok: true });
  } catch (err) { next(err); }
});

export default router;
