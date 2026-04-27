/**
 * /api/applications — Phase 27.5 Application boundary CRUD + component
 * assignment.
 *
 * Routes:
 *   GET    /api/applications                        list + counts (VIEWER+)
 *   POST   /api/applications                        create               (ADMIN+)
 *   GET    /api/applications/:id                    detail + components (VIEWER+)
 *   PATCH  /api/applications/:id                    edit metadata        (ADMIN+)
 *   DELETE /api/applications/:id                    remove (un-assigns)  (ADMIN+)
 *   PATCH  /api/applications/:id/components         bulk assign assets   (ADMIN+)
 *
 * Semantics:
 *   - On DELETE the assets stay; their `applicationId` is set to null via
 *     the schema's onDelete: SetNull cascade. No findings are deleted.
 *   - Components endpoint REPLACES the membership for each kind that's
 *     present in the request. Cross-org IDs are rejected with a 400 that
 *     names the bad IDs.
 *   - Re-correlation fires async after every successful component change
 *     so the operator sees fresh chains within seconds.
 */
import { Router } from "express";
import { z } from "zod";
import { requireAuth } from "../../middleware/requireAuth.js";
import { requireRole } from "../../middleware/requireRole.js";
import prisma from "../../db.js";
import { getActiveMembership } from "../../services/activeOrgService.js";
import * as audit from "../../services/auditService.js";
import {
  ALL_APPLICATION_ENVS,
  ALL_CRITICALITIES,
  assignComponents,
  isApplicationComponentValidationError,
  loadComponentCounts,
  loadComponents,
  loadFindingCounts,
  pickSlug,
} from "../../services/applicationService.js";
import { runCorrelationForOrg } from "../../services/correlation/correlationService.js";
import { logger } from "../../logger.js";

const router = Router();
router.use(requireAuth);

const createSchema = z.object({
  name:        z.string().min(1).max(120),
  slug:        z.string().min(1).max(120).regex(/^[a-z0-9][a-z0-9-]*$/, "slug must be lowercase alnum + dashes").optional(),
  description: z.string().max(2000).optional(),
  environment: z.enum(["DEVELOPMENT", "STAGING", "PRODUCTION"] as const).optional(),
  criticality: z.enum(["CRITICAL", "HIGH", "MEDIUM", "LOW"] as const).optional(),
  owner:       z.string().max(200).optional(),
});

const updateSchema = z.object({
  name:        z.string().min(1).max(120).optional(),
  slug:        z.string().min(1).max(120).regex(/^[a-z0-9][a-z0-9-]*$/).optional(),
  description: z.string().max(2000).nullable().optional(),
  environment: z.enum(["DEVELOPMENT", "STAGING", "PRODUCTION"] as const).optional(),
  criticality: z.enum(["CRITICAL", "HIGH", "MEDIUM", "LOW"] as const).optional(),
  owner:       z.string().max(200).nullable().optional(),
});

const componentsSchema = z.object({
  repositoryIds: z.array(z.string().min(1)).optional(),
  containerIds:  z.array(z.string().min(1)).optional(),
  domainIds:     z.array(z.string().min(1)).optional(),
}).refine(
  (b) => b.repositoryIds || b.containerIds || b.domainIds,
  { message: "at least one of repositoryIds / containerIds / domainIds is required" },
);

// ── List ─────────────────────────────────────────────────────────────

router.get("/", async (req, res, next) => {
  try {
    const member = await getActiveMembership(req);
    if (!member) { res.json([]); return; }

    const apps = await prisma.application.findMany({
      where:   { orgId: member.orgId },
      orderBy: { createdAt: "desc" },
    });

    // For the list view we want per-app component counts + finding counts.
    // Two sequential lookups per app would be N×2 queries; instead group by
    // applicationId across each table once.
    const result = await Promise.all(apps.map(async (a) => {
      const [counts, findingCounts] = await Promise.all([
        loadComponentCounts(a.id, member.orgId),
        loadFindingCounts(a.id, member.orgId),
      ]);
      return { ...a, componentCounts: counts, findingCounts };
    }));

    res.json(result);
  } catch (err) { next(err); }
});

// ── Create — ADMIN+ ──────────────────────────────────────────────────

router.post("/", requireRole("ADMIN"), async (req, res, next) => {
  try {
    const body = createSchema.parse(req.body);
    const user = req.user as { id: string };
    const slug = await pickSlug(req.orgId!, body.name, body.slug);

    const app = await prisma.application.create({
      data: {
        orgId:       req.orgId!,
        name:        body.name,
        slug,
        description: body.description ?? null,
        environment: body.environment ?? "PRODUCTION",
        criticality: body.criticality ?? "MEDIUM",
        owner:       body.owner ?? null,
      },
    });
    await audit.log({
      orgId:        req.orgId!,
      userId:       user.id,
      action:       "application.create",
      resourceType: "Application",
      resourceId:   app.id,
      metadata:     { name: app.name, slug: app.slug, environment: app.environment, criticality: app.criticality },
    });
    res.status(201).json(app);
  } catch (err) { next(err); }
});

// ── Detail ───────────────────────────────────────────────────────────

router.get("/:id", async (req, res, next) => {
  try {
    const member = await getActiveMembership(req);
    if (!member) { res.status(404).json({ error: "Application not found" }); return; }
    const app = await prisma.application.findFirst({
      where: { id: req.params["id"], orgId: member.orgId },
    });
    if (!app) { res.status(404).json({ error: "Application not found" }); return; }
    const [components, componentCounts, findingCounts] = await Promise.all([
      loadComponents(app.id, member.orgId),
      loadComponentCounts(app.id, member.orgId),
      loadFindingCounts(app.id, member.orgId),
    ]);
    res.json({ ...app, components, componentCounts, findingCounts });
  } catch (err) { next(err); }
});

// ── Update metadata — ADMIN+ ──────────────────────────────────────────

router.patch("/:id", requireRole("ADMIN"), async (req, res, next) => {
  try {
    const body = updateSchema.parse(req.body);
    const user = req.user as { id: string };
    const app = await prisma.application.findFirst({
      where: { id: req.params["id"], orgId: req.orgId! },
    });
    if (!app) { res.status(404).json({ error: "Application not found" }); return; }
    const updated = await prisma.application.update({
      where: { id: app.id },
      data: {
        ...(body.name        !== undefined && { name:        body.name }),
        ...(body.slug        !== undefined && { slug:        body.slug }),
        ...(body.description !== undefined && { description: body.description }),
        ...(body.environment !== undefined && { environment: body.environment }),
        ...(body.criticality !== undefined && { criticality: body.criticality }),
        ...(body.owner       !== undefined && { owner:       body.owner }),
      },
    });
    await audit.log({
      orgId:        req.orgId!,
      userId:       user.id,
      action:       "application.update",
      resourceType: "Application",
      resourceId:   app.id,
      metadata:     { name: updated.name, slug: updated.slug, environment: updated.environment, criticality: updated.criticality },
    });
    res.json(updated);
  } catch (err) { next(err); }
});

// ── Delete — ADMIN+ (assets stay; applicationId set to null via cascade) ─

router.delete("/:id", requireRole("ADMIN"), async (req, res, next) => {
  try {
    const user = req.user as { id: string };
    const app = await prisma.application.findFirst({
      where: { id: req.params["id"], orgId: req.orgId! },
    });
    if (!app) { res.status(404).json({ error: "Application not found" }); return; }

    await prisma.application.delete({ where: { id: app.id } });

    await audit.log({
      orgId:        req.orgId!,
      userId:       user.id,
      action:       "application.delete",
      resourceType: "Application",
      resourceId:   app.id,
      metadata:     { name: app.name, slug: app.slug },
    });

    // Re-correlate so chains pointing at this app's components dissolve.
    runCorrelationForOrg(req.orgId!).catch((e) =>
      logger.warn(`[correlation] post-delete refresh failed: ${(e as Error).message}`),
    );
    res.json({ ok: true });
  } catch (err) { next(err); }
});

// ── Bulk component assignment — ADMIN+ ───────────────────────────────

router.patch("/:id/components", requireRole("ADMIN"), async (req, res, next) => {
  try {
    const body = componentsSchema.parse(req.body);
    const user = req.user as { id: string };
    const app = await prisma.application.findFirst({
      where: { id: req.params["id"], orgId: req.orgId! },
    });
    if (!app) { res.status(404).json({ error: "Application not found" }); return; }

    let result;
    try {
      result = await assignComponents(app.id, req.orgId!, body);
    } catch (e) {
      if (isApplicationComponentValidationError(e)) {
        res.status(400).json({ error: e.message, details: e.details });
        return;
      }
      throw e;
    }

    await audit.log({
      orgId:        req.orgId!,
      userId:       user.id,
      action:       "application.components.update",
      resourceType: "Application",
      resourceId:   app.id,
      metadata: {
        name:         app.name,
        repositories: result.repositories.length,
        containers:   result.containers.length,
        domains:      result.domains.length,
      },
    });

    // Fire-and-forget re-correlation so the chains rebuild against the new
    // app boundary without the operator waiting.
    runCorrelationForOrg(req.orgId!).catch((e) =>
      logger.warn(`[correlation] post-components refresh failed: ${(e as Error).message}`),
    );

    res.json(result);
  } catch (err) { next(err); }
});

// Expose enum lists for the UI's pickers (avoids hardcoding in the frontend).
router.get("/_meta/enums", (_req, res) => {
  res.json({
    environments: ALL_APPLICATION_ENVS,
    criticalities: ALL_CRITICALITIES,
  });
});

export default router;
