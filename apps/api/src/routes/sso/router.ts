/**
 * SSO (OIDC) configuration API.
 *
 *   GET    /api/sso         — fetch the org's current config (clientSecret redacted)
 *   PUT    /api/sso         — upsert config (encrypts clientSecret)
 *   DELETE /api/sso         — remove config
 *   POST   /api/sso/test    — validate the issuerUrl by fetching its
 *                             /.well-known/openid-configuration document
 *
 * All endpoints ADMIN+ — SSO config exposes the org to credential takeover
 * (a malicious clientSecret swap → all SSO logins go through attacker IdP).
 *
 * Phase 22 PR 3 Slice A: configuration only. Slice B adds the actual
 * passport-openidconnect strategy that consumes this config at login time.
 */
import { Router } from "express";
import { z } from "zod";
import { Role } from "@prisma/client";
import prisma from "../../db.js";
import { config } from "../../config.js";
import { requireRole } from "../../middleware/requireRole.js";
import { encrypt, decrypt } from "../../services/encryptionService.js";
import * as audit from "../../services/auditService.js";

// The OIDC callback path the auth router serves. Operators must register
// `${API_PUBLIC_URL}${SSO_CALLBACK_PATH}` as a Redirect URI in their IdP
// (Entra app registration → Authentication → Web → Redirect URIs).
const SSO_CALLBACK_PATH = "/auth/sso/callback";

const router = Router();

const VALID_ROLES = ["OWNER", "ADMIN", "SECURITY", "DEVELOPER", "VIEWER"] as const;

const upsertSchema = z.object({
  // OIDC issuer URL — must be HTTPS in production but http://localhost:* allowed
  // for local Keycloak / development. Discovery resolves the rest.
  issuerUrl: z.string().url(),
  clientId:  z.string().min(1).max(500),
  // Optional on update — when undefined, we preserve the existing encrypted value.
  clientSecret: z.string().min(1).max(500).optional(),
  // Lowercase email domains, no @. ["acme.com", "acme.org"]
  allowedEmailDomains: z.array(
    z.string().min(1).max(253).regex(/^[a-z0-9.-]+$/, "lowercase letters, digits, dots, hyphens only"),
  ).max(50),
  // { "groupClaimName": Role } — string keys are arbitrary IdP group names.
  groupRoleMapping: z.record(z.string().min(1).max(200), z.enum(VALID_ROLES)).default({}),
  defaultRole:      z.enum(VALID_ROLES).default("DEVELOPER"),
  isActive:         z.boolean().default(true),
});

const testSchema = z.object({
  issuerUrl: z.string().url(),
});

// ── GET ──────────────────────────────────────────────────────────────────────

router.get("/", requireRole("ADMIN"), async (req, res, next) => {
  try {
    const row = await prisma.ssoConfig.findUnique({
      where: { orgId: req.orgId! },
    });

    // redirectUri is server-derived (API_PUBLIC_URL + callback path) so the
    // UI can display the exact URL the operator must register at their IdP.
    // Returned even when no config exists yet — the operator needs the URL
    // BEFORE saving the BreachLens-side SSO config in order to register it
    // upstream first.
    const redirectUri = `${config.API_PUBLIC_URL}${SSO_CALLBACK_PATH}`;

    if (!row) { res.json({ redirectUri, config: null }); return; }

    res.json({
      redirectUri,
      config: {
        id:                  row.id,
        issuerUrl:           row.issuerUrl,
        clientId:            row.clientId,
        // Never return the plaintext secret — UI shows "***configured***" so
        // the operator knows it's set without exposing the value.
        clientSecretSet:     !!(row.encryptedSecrets as { apiKey?: string } | null),
        allowedEmailDomains: row.allowedEmailDomains,
        groupRoleMapping:    row.groupRoleMapping,
        defaultRole:         row.defaultRole,
        isActive:            row.isActive,
        updatedAt:           row.updatedAt,
      },
    });
  } catch (err) { next(err); }
});

// ── PUT (upsert) ─────────────────────────────────────────────────────────────

router.put("/", requireRole("ADMIN"), async (req, res, next) => {
  try {
    const actor = req.user as { id: string };
    const body  = upsertSchema.parse(req.body);

    // Look up existing — clientSecret is required on first-time create,
    // optional on update (UI sends undefined when the field is left blank).
    const existing = await prisma.ssoConfig.findUnique({
      where: { orgId: req.orgId! },
    });

    if (!body.clientSecret && !existing) {
      res.status(422).json({ error: "clientSecret required when configuring SSO for the first time" });
      return;
    }

    const encryptedSecrets = body.clientSecret
      ? { clientSecret: encrypt(body.clientSecret) }
      : (existing?.encryptedSecrets ?? {});

    const row = await prisma.ssoConfig.upsert({
      where:  { orgId: req.orgId! },
      create: {
        orgId:               req.orgId!,
        issuerUrl:           body.issuerUrl,
        clientId:            body.clientId,
        allowedEmailDomains: body.allowedEmailDomains,
        encryptedSecrets:    encryptedSecrets as object,
        groupRoleMapping:    body.groupRoleMapping as object,
        defaultRole:         body.defaultRole,
        isActive:            body.isActive,
      },
      update: {
        issuerUrl:           body.issuerUrl,
        clientId:            body.clientId,
        allowedEmailDomains: body.allowedEmailDomains,
        encryptedSecrets:    encryptedSecrets as object,
        groupRoleMapping:    body.groupRoleMapping as object,
        defaultRole:         body.defaultRole,
        isActive:            body.isActive,
      },
    });

    await audit.log({
      orgId: req.orgId!, userId: actor.id,
      action: existing ? "sso.update" : "sso.create",
      resourceType: "SsoConfig", resourceId: row.id,
      metadata: {
        issuerUrl:           body.issuerUrl,
        clientId:            body.clientId,
        secretChanged:       !!body.clientSecret,
        allowedEmailDomains: body.allowedEmailDomains,
        defaultRole:         body.defaultRole,
        isActive:            body.isActive,
      },
    });

    res.json({ ok: true, id: row.id });
  } catch (err) { next(err); }
});

// ── DELETE ───────────────────────────────────────────────────────────────────

router.delete("/", requireRole("ADMIN"), async (req, res, next) => {
  try {
    const actor = req.user as { id: string };
    const result = await prisma.ssoConfig.deleteMany({
      where: { orgId: req.orgId! },
    });
    if (result.count > 0) {
      await audit.log({
        orgId: req.orgId!, userId: actor.id,
        action: "sso.delete", resourceType: "SsoConfig", resourceId: req.orgId!,
      });
    }
    res.json({ ok: true });
  } catch (err) { next(err); }
});

// ── POST /test — validate the IdP discovery endpoint ─────────────────────────
// Hits <issuerUrl>/.well-known/openid-configuration and confirms the
// document has the required endpoints (token, authorization, userinfo,
// jwks_uri). Catches typos, unreachable issuers, and non-OIDC URLs before
// the operator commits a config.
//
// Does NOT validate clientId/clientSecret — those only get exercised on
// real login. Surfacing that in Slice B.

const REQUIRED_ENDPOINTS = ["issuer", "authorization_endpoint", "token_endpoint", "jwks_uri"] as const;

router.post("/test", requireRole("ADMIN"), async (req, res, next) => {
  try {
    const body = testSchema.parse(req.body);
    const url  = body.issuerUrl.replace(/\/$/, "") + "/.well-known/openid-configuration";

    const t0 = Date.now();
    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), 5000);
    let resp: Response;
    try {
      resp = await fetch(url, { signal: controller.signal, redirect: "follow" });
    } catch (err) {
      const msg = err instanceof Error
        ? (err.name === "AbortError" ? "timeout (>5s)" : err.message)
        : String(err);
      res.status(502).json({ ok: false, error: "DISCOVERY_UNREACHABLE", message: msg, latencyMs: Date.now() - t0 });
      return;
    } finally {
      clearTimeout(timeout);
    }

    if (!resp.ok) {
      res.status(502).json({
        ok: false, error: "DISCOVERY_BAD_STATUS",
        message: `HTTP ${resp.status} from ${url}`,
        latencyMs: Date.now() - t0,
      });
      return;
    }

    let doc: Record<string, unknown>;
    try {
      doc = await resp.json();
    } catch {
      res.status(502).json({
        ok: false, error: "DISCOVERY_NOT_JSON",
        message: "Response from issuer is not valid JSON — likely not an OIDC endpoint",
        latencyMs: Date.now() - t0,
      });
      return;
    }

    const missing = REQUIRED_ENDPOINTS.filter((k) => !doc[k]);
    if (missing.length > 0) {
      res.status(502).json({
        ok: false, error: "DISCOVERY_INCOMPLETE",
        message: `Missing required OIDC fields: ${missing.join(", ")}`,
        latencyMs: Date.now() - t0,
      });
      return;
    }

    res.json({
      ok:        true,
      latencyMs: Date.now() - t0,
      issuer:                doc["issuer"],
      authorizationEndpoint: doc["authorization_endpoint"],
      tokenEndpoint:         doc["token_endpoint"],
      userinfoEndpoint:      doc["userinfo_endpoint"] ?? null,
      jwksUri:               doc["jwks_uri"],
      // Useful operator-facing breadcrumb — what scopes the IdP claims to
      // support. We'll request `openid email profile groups` regardless.
      scopesSupported:       (doc["scopes_supported"] as string[] | undefined) ?? [],
    });
  } catch (err) { next(err); }
});

export default router;
