/**
 * AI provider configuration API.
 *
 *   GET    /api/ai-providers                       — list providers (apiKey redacted)
 *   PUT    /api/ai-providers/:type                 — upsert provider (encrypts apiKey)
 *   DELETE /api/ai-providers/:type                 — remove provider
 *   POST   /api/ai-providers/:type/default         — make this the org default
 *   POST   /api/ai-providers/:type/test            — round-trip test against the live provider
 *
 *   GET    /api/ai-providers/routings              — list per-service routing overrides
 *   PUT    /api/ai-providers/routings/:service     — pin one service to a specific provider
 *   DELETE /api/ai-providers/routings/:service     — clear the override
 *
 *   GET    /api/ai-providers/usage                 — last-30-day AICallLog rollup
 *
 * All mutations are scoped to req.user's org. apiKeys are AES-256-GCM
 * encrypted via encryptionService and never returned to clients.
 */

import { Router } from "express";
import { z } from "zod";
import { AIProviderType, AIServiceName } from "@prisma/client";
import { requireAuth } from "../../middleware/requireAuth.js";
import prisma from "../../db.js";
import { encrypt } from "../../services/encryptionService.js";
import { invokeAI, AIError } from "../../services/aiClient.js";
import * as audit from "../../services/auditService.js";
import { logger } from "../../logger.js";

const router = Router();
router.use(requireAuth);

async function getOrgId(userId: string): Promise<string | null> {
  const member = await prisma.organizationMember.findFirst({ where: { userId } });
  return member?.orgId ?? null;
}

const providerTypeSchema = z.nativeEnum(AIProviderType);
const serviceNameSchema  = z.nativeEnum(AIServiceName);

// ── Providers ────────────────────────────────────────────────────────────────

const upsertProviderSchema = z.object({
  // Required for ANTHROPIC | OPENAI | GEMINI; ignored for OLLAMA.
  apiKey:       z.string().min(1).optional(),
  defaultModel: z.string().min(1),
  baseUrl:      z.string().url().optional(),
  isDefault:    z.boolean().optional(),
});

router.get("/", async (req, res, next) => {
  try {
    const user  = req.user as { id: string };
    const orgId = await getOrgId(user.id);
    if (!orgId) { res.json([]); return; }

    const rows = await prisma.aIProvider.findMany({
      where:   { orgId },
      orderBy: { createdAt: "asc" },
    });

    res.json(rows.map((r) => ({
      id:           r.id,
      type:         r.type,
      defaultModel: r.defaultModel,
      baseUrl:      r.baseUrl,
      isActive:     r.isActive,
      isDefault:    r.isDefault,
      hasApiKey:    Boolean((r.encryptedConfig as { apiKey?: string } | null)?.apiKey),
      createdAt:    r.createdAt,
      updatedAt:    r.updatedAt,
    })));
  } catch (err) { next(err); }
});

router.put("/:type", async (req, res, next) => {
  try {
    const type  = providerTypeSchema.parse(req.params["type"]);
    const body  = upsertProviderSchema.parse(req.body);
    const user  = req.user as { id: string };
    const orgId = await getOrgId(user.id);
    if (!orgId) { res.status(400).json({ error: "No organization" }); return; }

    // Look up existing row first — apiKey is only required on first-time create.
    // On update, the UI sends apiKey:undefined when the user didn't re-enter it
    // (the password field is intentionally blank to avoid re-displaying secrets).
    const existing = await prisma.aIProvider.findUnique({
      where: { orgId_type: { orgId, type } },
    });

    if (type !== AIProviderType.OLLAMA && !body.apiKey && !existing) {
      res.status(422).json({ error: `apiKey required for ${type}` });
      return;
    }
    if (type === AIProviderType.OLLAMA && !body.baseUrl && !existing) {
      res.status(422).json({ error: "baseUrl required for OLLAMA (e.g. http://ollama:11434)" });
      return;
    }

    // Build encryptedConfig:
    //  - new apiKey supplied → encrypt + store
    //  - update with no new key → preserve the existing encrypted blob
    //  - new create with no key (OLLAMA) → empty object
    const encryptedConfig = body.apiKey
      ? { apiKey: encrypt(body.apiKey) }
      : (existing?.encryptedConfig ?? {});

    // If isDefault=true, unset any other defaults for this org first
    if (body.isDefault) {
      await prisma.aIProvider.updateMany({
        where: { orgId, isDefault: true, NOT: { type } },
        data:  { isDefault: false },
      });
    }

    const row = await prisma.aIProvider.upsert({
      where:  { orgId_type: { orgId, type } },
      create: {
        orgId, type,
        encryptedConfig: encryptedConfig as object,
        defaultModel:    body.defaultModel,
        baseUrl:         body.baseUrl,
        isActive:        true,
        isDefault:       body.isDefault ?? false,
      },
      update: {
        encryptedConfig: encryptedConfig as object,
        defaultModel:    body.defaultModel,
        baseUrl:         body.baseUrl,
        isDefault:       body.isDefault ?? undefined,
      },
    });

    await audit.log({
      orgId, userId: user.id,
      action: existing ? "ai_provider.update" : "ai_provider.create",
      resourceType: "AIProvider", resourceId: row.id,
      metadata: {
        type, defaultModel: body.defaultModel,
        keyChanged: !!body.apiKey,
        isDefault:  body.isDefault ?? false,
      },
    });

    res.json({ ok: true, id: row.id, type: row.type });
  } catch (err) { next(err); }
});

router.delete("/:type", async (req, res, next) => {
  try {
    const type  = providerTypeSchema.parse(req.params["type"]);
    const user  = req.user as { id: string };
    const orgId = await getOrgId(user.id);
    if (orgId) {
      const result = await prisma.aIProvider.deleteMany({ where: { orgId, type } });
      if (result.count > 0) {
        await audit.log({
          orgId, userId: user.id,
          action: "ai_provider.delete", resourceType: "AIProvider", resourceId: type,
          metadata: { type },
        });
      }
    }
    res.json({ ok: true });
  } catch (err) { next(err); }
});

router.post("/:type/default", async (req, res, next) => {
  try {
    const type  = providerTypeSchema.parse(req.params["type"]);
    const user  = req.user as { id: string };
    const orgId = await getOrgId(user.id);
    if (!orgId) { res.status(400).json({ error: "No organization" }); return; }

    const target = await prisma.aIProvider.findUnique({
      where: { orgId_type: { orgId, type } },
    });
    if (!target) { res.status(404).json({ error: "Provider not configured" }); return; }

    await prisma.$transaction([
      prisma.aIProvider.updateMany({ where: { orgId, isDefault: true }, data: { isDefault: false } }),
      prisma.aIProvider.update({    where: { id: target.id },           data: { isDefault: true  } }),
    ]);

    await audit.log({
      orgId, userId: user.id,
      action: "ai_provider.set_default", resourceType: "AIProvider", resourceId: target.id,
      metadata: { type },
    });

    res.json({ ok: true });
  } catch (err) { next(err); }
});

router.post("/:type/test", async (req, res, next) => {
  try {
    const type  = providerTypeSchema.parse(req.params["type"]);
    const user  = req.user as { id: string };
    const orgId = await getOrgId(user.id);
    if (!orgId) { res.status(400).json({ error: "No organization" }); return; }

    // Pin this round-trip to the requested provider via a temporary routing
    // override. We use ANALYSE_FINDING as the canonical "general" service —
    // but route it through the chosen provider only for this call.
    const target = await prisma.aIProvider.findUnique({
      where: { orgId_type: { orgId, type } },
    });
    if (!target) { res.status(404).json({ error: "Provider not configured" }); return; }

    // Insert a temp routing → call → delete. Simpler than threading an explicit
    // provider override through invokeAI() for what is a one-off test path.
    const tempRouting = await prisma.aIServiceRouting.upsert({
      where:  { orgId_service: { orgId, service: AIServiceName.ANALYSE_FINDING } },
      create: { orgId, service: AIServiceName.ANALYSE_FINDING, providerId: target.id },
      update: { providerId: target.id, modelOverride: null },
    });
    const hadPriorRouting = tempRouting.createdAt.getTime() !== tempRouting.updatedAt.getTime();

    try {
      const result = await invokeAI({
        service:         AIServiceName.ANALYSE_FINDING,
        orgId,
        system:          "You are a connectivity test. Reply with JSON only.",
        messages:        [{ role: "user", content: 'Reply with {"ok":true} and nothing else.' }],
        schema:          z.object({ ok: z.boolean() }),
        maxOutputTokens: 32,
        timeoutMs:       30_000,
      });
      res.json({
        ok:        true,
        provider:  result.providerType,
        model:     result.model,
        latencyMs: result.usage.latencyMs,
        tokens:    { input: result.usage.inputTokens, output: result.usage.outputTokens },
      });
    } finally {
      // Restore: if we created the routing for this test, drop it. If it
      // already existed before, leave it as the user intended.
      if (!hadPriorRouting) {
        await prisma.aIServiceRouting.deleteMany({
          where: { orgId, service: AIServiceName.ANALYSE_FINDING, providerId: target.id },
        });
      }
    }
  } catch (err) {
    if (err instanceof AIError) {
      logger.warn(`[ai-providers] test failed: ${err.kind} — ${err.message}`);
      res.status(502).json({ ok: false, error: err.kind, message: err.message });
      return;
    }
    next(err);
  }
});

// ── Per-service routing ──────────────────────────────────────────────────────

const upsertRoutingSchema = z.object({
  providerId:    z.string().min(1),
  modelOverride: z.string().min(1).optional(),
});

router.get("/routings", async (req, res, next) => {
  try {
    const user  = req.user as { id: string };
    const orgId = await getOrgId(user.id);
    if (!orgId) { res.json([]); return; }

    const rows = await prisma.aIServiceRouting.findMany({
      where:   { orgId },
      include: { provider: { select: { type: true, defaultModel: true } } },
    });
    res.json(rows.map((r) => ({
      id:            r.id,
      service:       r.service,
      providerId:    r.providerId,
      providerType:  r.provider.type,
      modelOverride: r.modelOverride,
      defaultModel:  r.provider.defaultModel,
    })));
  } catch (err) { next(err); }
});

router.put("/routings/:service", async (req, res, next) => {
  try {
    const service = serviceNameSchema.parse(req.params["service"]);
    const body    = upsertRoutingSchema.parse(req.body);
    const user    = req.user as { id: string };
    const orgId   = await getOrgId(user.id);
    if (!orgId) { res.status(400).json({ error: "No organization" }); return; }

    // Validate the provider belongs to this org
    const provider = await prisma.aIProvider.findUnique({ where: { id: body.providerId } });
    if (!provider || provider.orgId !== orgId) {
      res.status(404).json({ error: "Provider not found in this org" });
      return;
    }

    await prisma.aIServiceRouting.upsert({
      where:  { orgId_service: { orgId, service } },
      create: { orgId, service, providerId: body.providerId, modelOverride: body.modelOverride },
      update: { providerId: body.providerId, modelOverride: body.modelOverride ?? null },
    });
    await audit.log({
      orgId, userId: user.id,
      action: "ai_routing.set", resourceType: "AIServiceRouting", resourceId: service,
      metadata: { service, providerType: provider.type, modelOverride: body.modelOverride ?? null },
    });
    res.json({ ok: true });
  } catch (err) { next(err); }
});

router.delete("/routings/:service", async (req, res, next) => {
  try {
    const service = serviceNameSchema.parse(req.params["service"]);
    const user    = req.user as { id: string };
    const orgId   = await getOrgId(user.id);
    if (orgId) {
      const result = await prisma.aIServiceRouting.deleteMany({ where: { orgId, service } });
      if (result.count > 0) {
        await audit.log({
          orgId, userId: user.id,
          action: "ai_routing.clear", resourceType: "AIServiceRouting", resourceId: service,
          metadata: { service },
        });
      }
    }
    res.json({ ok: true });
  } catch (err) { next(err); }
});

// ── Usage / cost rollup ──────────────────────────────────────────────────────

router.get("/usage", async (req, res, next) => {
  try {
    const user  = req.user as { id: string };
    const orgId = await getOrgId(user.id);
    if (!orgId) { res.json({ totals: null, byService: [], byProvider: [] }); return; }

    const since = new Date(Date.now() - 30 * 24 * 60 * 60 * 1000);

    const [totals, byService, byProvider] = await Promise.all([
      prisma.aICallLog.aggregate({
        where: { orgId, createdAt: { gte: since } },
        _sum:  { inputTokens: true, outputTokens: true, cachedInputTokens: true, costUsd: true },
        _count: true,
      }),
      prisma.aICallLog.groupBy({
        by:    ["service"],
        where: { orgId, createdAt: { gte: since } },
        _sum:  { inputTokens: true, outputTokens: true, costUsd: true },
        _count: true,
      }),
      prisma.aICallLog.groupBy({
        by:    ["providerType", "model"],
        where: { orgId, createdAt: { gte: since } },
        _sum:  { inputTokens: true, outputTokens: true, costUsd: true },
        _count: true,
      }),
    ]);

    res.json({ since, totals, byService, byProvider });
  } catch (err) { next(err); }
});

export default router;
