import { Router } from "express";
import { z } from "zod";
import { requireAuth } from "../../middleware/requireAuth.js";
import prisma from "../../db.js";
import { createJiraIssue } from "../../services/jiraService.js";
import { decrypt } from "../../services/encryptionService.js";

const router = Router();
router.use(requireAuth);

const createTicketSchema = z.object({
  findingId: z.string(),
  title: z.string().min(1),
  description: z.string().optional(),
  priority: z.enum(["CRITICAL", "HIGH", "MEDIUM", "LOW"]),
  createJiraIssue: z.boolean().optional().default(false),
});

const updateTicketSchema = z.object({
  status: z.enum(["OPEN", "IN_PROGRESS", "RESOLVED", "CLOSED"]).optional(),
  title: z.string().optional(),
  description: z.string().optional(),
  priority: z.enum(["CRITICAL", "HIGH", "MEDIUM", "LOW"]).optional(),
});

// List tickets
router.get("/", async (req, res, next) => {
  try {
    const user = req.user as { id: string };
    const member = await prisma.organizationMember.findFirst({ where: { userId: user.id } });
    if (!member) { res.json({ data: [], total: 0 }); return; }

    const page = Math.max(1, parseInt(req.query["page"] as string || "1"));
    const limit = Math.min(50, parseInt(req.query["limit"] as string || "25"));
    const skip = (page - 1) * limit;

    const where: Record<string, unknown> = { orgId: member.orgId };
    if (req.query["status"]) where["status"] = req.query["status"];

    const [data, total] = await Promise.all([
      prisma.ticket.findMany({
        where,
        orderBy: { createdAt: "desc" },
        skip,
        take: limit,
        include: { finding: { select: { severity: true, scanType: true, title: true } }, createdBy: { select: { username: true, avatarUrl: true } } },
      }),
      prisma.ticket.count({ where }),
    ]);

    res.json({ data, total, page, limit, totalPages: Math.ceil(total / limit) });
  } catch (err) { next(err); }
});

// Create ticket
router.post("/", async (req, res, next) => {
  try {
    const body = createTicketSchema.parse(req.body);
    const user = req.user as { id: string };
    const member = await prisma.organizationMember.findFirst({ where: { userId: user.id } });
    if (!member) { res.status(400).json({ error: "No organization found" }); return; }

    // Verify finding belongs to org
    const finding = await prisma.finding.findFirst({
      where: { id: body.findingId, orgId: member.orgId },
    });
    if (!finding) { res.status(404).json({ error: "Finding not found" }); return; }

    // Check no existing ticket
    const existingTicket = await prisma.ticket.findUnique({ where: { findingId: body.findingId } });
    if (existingTicket) { res.status(409).json({ error: "Ticket already exists for this finding" }); return; }

    let jiraKey: string | null = null;
    let jiraUrl: string | null = null;

    // Create Jira issue if requested and integration configured
    if (body.createJiraIssue) {
      const integration = await prisma.integration.findUnique({
        where: { orgId_type: { orgId: member.orgId, type: "JIRA" } },
      });
      if (integration?.isActive) {
        const cfg = integration.encryptedData as Record<string, string>;
        const jiraResult = await createJiraIssue({
          host: decrypt(cfg["host"] as string),
          email: decrypt(cfg["email"] as string),
          apiToken: decrypt(cfg["apiToken"] as string),
          projectKey: decrypt(cfg["projectKey"] as string),
          issueType: cfg["issueType"] ? decrypt(cfg["issueType"]) : "Bug",
        }, finding);
        jiraKey = jiraResult?.key ?? null;
        jiraUrl = jiraResult?.url ?? null;
      }
    }

    const ticket = await prisma.ticket.create({
      data: {
        orgId: member.orgId,
        findingId: body.findingId,
        title: body.title,
        description: body.description ?? null,
        priority: body.priority,
        jiraKey,
        jiraUrl,
        createdById: user.id,
      },
      include: { finding: true, createdBy: { select: { username: true, avatarUrl: true } } },
    });

    res.status(201).json(ticket);
  } catch (err) { next(err); }
});

// Get ticket
router.get("/:id", async (req, res, next) => {
  try {
    const user = req.user as { id: string };
    const member = await prisma.organizationMember.findFirst({ where: { userId: user.id } });
    const ticket = await prisma.ticket.findFirst({
      where: { id: req.params["id"], orgId: member?.orgId },
      include: { finding: true, createdBy: { select: { username: true, avatarUrl: true } } },
    });
    if (!ticket) { res.status(404).json({ error: "Ticket not found" }); return; }
    res.json(ticket);
  } catch (err) { next(err); }
});

// Update ticket
router.patch("/:id", async (req, res, next) => {
  try {
    const body = updateTicketSchema.parse(req.body);
    const user = req.user as { id: string };
    const member = await prisma.organizationMember.findFirst({ where: { userId: user.id } });
    const ticket = await prisma.ticket.findFirst({
      where: { id: req.params["id"], orgId: member?.orgId },
    });
    if (!ticket) { res.status(404).json({ error: "Ticket not found" }); return; }

    const updated = await prisma.ticket.update({
      where: { id: ticket.id },
      data: { ...body },
    });
    res.json(updated);
  } catch (err) { next(err); }
});

// Delete ticket
router.delete("/:id", async (req, res, next) => {
  try {
    const user = req.user as { id: string };
    const member = await prisma.organizationMember.findFirst({ where: { userId: user.id } });
    const ticket = await prisma.ticket.findFirst({
      where: { id: req.params["id"], orgId: member?.orgId },
    });
    if (!ticket) { res.status(404).json({ error: "Ticket not found" }); return; }
    await prisma.ticket.delete({ where: { id: ticket.id } });
    res.json({ ok: true });
  } catch (err) { next(err); }
});

export default router;
