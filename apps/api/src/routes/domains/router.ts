import { Router } from "express";
import { z } from "zod";
import axios from "axios";
import { requireAuth } from "../../middleware/requireAuth.js";
import { requireRole } from "../../middleware/requireRole.js";
import prisma from "../../db.js";
import * as audit from "../../services/auditService.js";
import { scoreTarget } from "../../services/riskScoringService.js";
import { config } from "../../config.js";
import { triggerScan } from "../../services/scanService.js";
import { encrypt, decrypt } from "../../services/encryptionService.js";
import * as recording from "../../services/recordingService.js";
import type { ScanType } from "@devsecops/types";

const router = Router();
router.use(requireAuth);

// Accepts:
//   - Standard FQDNs:          example.com, sub.example.com
//   - Bare hostnames:           localhost, dvwa  (internal Docker service names)
//   - Host + port:              localhost:4280, dvwa:80, example.com:8443
//   - IPv4 addresses:           192.168.1.1, 10.0.0.1:8080
const DOMAIN_RE =
  /^(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-\.]*[a-zA-Z0-9])?)(:[0-9]{1,5})?$/;

const createDomainSchema = z.object({
  domain: z.string().min(1).regex(DOMAIN_RE, "Invalid domain or hostname"),
});

const updateDomainSchema = z.object({
  domain: z.string().min(1).regex(DOMAIN_RE, "Invalid domain or hostname").optional(),
});

// List domains
router.get("/", async (req, res, next) => {
  try {
    const user = req.user as { id: string };
    const member = await prisma.organizationMember.findFirst({ where: { userId: user.id } });
    if (!member) { res.json([]); return; }

    const [domains, countRows, authRows, specRows, recordingRows] = await Promise.all([
      prisma.domain.findMany({ where: { orgId: member.orgId }, orderBy: { addedAt: "desc" } }),
      prisma.finding.groupBy({
        by: ["domainId", "severity"],
        where: { orgId: member.orgId, domainId: { not: null }, status: { not: "FALSE_POSITIVE" } },
        _count: { id: true },
      }),
      prisma.domainAuthConfig.findMany({ where: { domain: { orgId: member.orgId } }, select: { domainId: true } }),
      prisma.domainApiSpec.findMany     ({ where: { domain: { orgId: member.orgId } }, select: { domainId: true } }),
      prisma.recordingSession.findMany  ({ where: { orgId: member.orgId, status: "ACTIVE" }, select: { domainId: true, urlCount: true } }),
    ]);

    const countMap: Record<string, Record<string, number>> = {};
    for (const row of countRows) {
      const did = row.domainId!;
      if (!countMap[did]) countMap[did] = {};
      countMap[did][row.severity] = row._count.id;
    }

    const hasAuth = new Set(authRows.map((r) => r.domainId));
    const hasSpec = new Set(specRows.map((r) => r.domainId));
    const activeRec = new Map(recordingRows.map((r) => [r.domainId, r.urlCount] as const));

    const result = domains.map((d) => ({
      ...d,
      findingCounts: {
        CRITICAL: countMap[d.id]?.CRITICAL ?? 0,
        HIGH: countMap[d.id]?.HIGH ?? 0,
        MEDIUM: countMap[d.id]?.MEDIUM ?? 0,
        LOW: countMap[d.id]?.LOW ?? 0,
      },
      hasAuthConfig: hasAuth.has(d.id),
      hasApiSpec:    hasSpec.has(d.id),
      activeRecordingUrls: activeRec.get(d.id) ?? null,
    }));

    res.json(result);
  } catch (err) { next(err); }
});

// Add domain
router.post("/", async (req, res, next) => {
  try {
    const body = createDomainSchema.parse(req.body);
    const user = req.user as { id: string };
    const member = await prisma.organizationMember.findFirst({ where: { userId: user.id } });
    if (!member) { res.status(400).json({ error: "No organization found" }); return; }

    const domain = await prisma.domain.create({
      data: { orgId: member.orgId, domain: body.domain },
    });
    res.status(201).json(domain);
  } catch (err) { next(err); }
});

// Get domain
router.get("/:id", async (req, res, next) => {
  try {
    const user = req.user as { id: string };
    const member = await prisma.organizationMember.findFirst({ where: { userId: user.id } });
    const domain = await prisma.domain.findFirst({
      where: { id: req.params["id"], orgId: member?.orgId },
    });
    if (!domain) { res.status(404).json({ error: "Domain not found" }); return; }
    res.json(domain);
  } catch (err) { next(err); }
});

// Update domain
router.patch("/:id", async (req, res, next) => {
  try {
    const body = updateDomainSchema.parse(req.body);
    const user = req.user as { id: string };
    const member = await prisma.organizationMember.findFirst({ where: { userId: user.id } });
    const domain = await prisma.domain.findFirst({
      where: { id: req.params["id"], orgId: member?.orgId },
    });
    if (!domain) { res.status(404).json({ error: "Domain not found" }); return; }
    const updated = await prisma.domain.update({
      where: { id: domain.id },
      data: { ...(body.domain && { domain: body.domain }) },
    });
    res.json(updated);
  } catch (err) { next(err); }
});

// Delete domain — ADMIN+
router.delete("/:id", requireRole("ADMIN"), async (req, res, next) => {
  try {
    const user = req.user as { id: string };
    const domain = await prisma.domain.findFirst({
      where: { id: req.params["id"], orgId: req.orgId! },
    });
    if (!domain) { res.status(404).json({ error: "Domain not found" }); return; }
    await prisma.domain.delete({ where: { id: domain.id } });
    await audit.log({
      orgId:        req.orgId!,
      userId:       user.id,
      action:       "domain.delete",
      resourceType: "Domain",
      resourceId:   domain.id,
      metadata:     { domain: domain.domain },
    });
    res.json({ ok: true });
  } catch (err) { next(err); }
});

// ── Pentest authorization ─────────────────────────────────────────────────────

router.post("/:id/authorize", async (req, res, next) => {
  try {
    const { confirmed } = z.object({ confirmed: z.literal(true) }).parse(req.body);
    if (!confirmed) { res.status(400).json({ error: "confirmed must be true" }); return; }
    const user = req.user as { id: string };
    const member = await prisma.organizationMember.findFirst({ where: { userId: user.id } });
    const domain = await prisma.domain.findFirst({ where: { id: req.params["id"], orgId: member?.orgId } });
    if (!domain) { res.status(404).json({ error: "Domain not found" }); return; }
    const updated = await prisma.domain.update({
      where: { id: domain.id },
      data: { authorized: true, authorizedAt: new Date(), authorizedById: user.id },
    });
    res.json(updated);
  } catch (err) { next(err); }
});

// ── Recon (Phase 1 — subdomain discovery) ─────────────────────────────────────

/** Returns true when the axios error is a network-level connection failure */
function isConnectionError(err: unknown): boolean {
  const code = (err as NodeJS.ErrnoException & { code?: string }).code;
  return code === "ENOTFOUND" || code === "ECONNREFUSED" || code === "ECONNRESET" || code === "ETIMEDOUT";
}

router.post("/:id/recon", async (req, res, next) => {
  try {
    const user = req.user as { id: string };
    const member = await prisma.organizationMember.findFirst({ where: { userId: user.id } });
    const domain = await prisma.domain.findFirst({ where: { id: req.params["id"], orgId: member?.orgId } });
    if (!domain) { res.status(404).json({ error: "Domain not found" }); return; }

    // Call scanner /recon endpoint synchronously (fast, ~2 min).
    // Prefer the dedicated pentest scanner; fall back to the base scanner.
    const preferredUrl = config.SCANNER_PENTEST_URL ?? config.SCANNER_URL;
    let reconResponse;
    try {
      reconResponse = await axios.post(
        `${preferredUrl}/recon`,
        { org_id: member!.orgId, domain: domain.domain },
        { timeout: 180_000 } // 3 min
      );
    } catch (scannerErr) {
      // If the pentest scanner isn't running, give a clear actionable message
      if (isConnectionError(scannerErr) && config.SCANNER_PENTEST_URL) {
        res.status(503).json({
          error:
            "The pentest scanner is not running. " +
            "Start it with: docker compose --profile pentest up -d scanner-pentest",
        });
        return;
      }
      throw scannerErr; // re-throw anything else (HTTP 4xx/5xx from scanner, timeouts, etc.)
    }

    const subdomains: Array<{
      subdomain: string; isLive: boolean; statusCode?: number; technologies: string[];
    }> = reconResponse.data.subdomains ?? [];

    // Upsert discovered subdomains (preserves existing includedInScan selections)
    await Promise.all(subdomains.map((s) =>
      prisma.subdomainDiscovery.upsert({
        where: { domainId_subdomain: { domainId: domain.id, subdomain: s.subdomain } },
        create: {
          domainId: domain.id,
          subdomain: s.subdomain,
          isLive: s.isLive,
          statusCode: s.statusCode ?? null,
          technologies: s.technologies,
          includedInScan: s.isLive, // default: include live subdomains
        },
        update: {
          isLive: s.isLive,
          statusCode: s.statusCode ?? null,
          technologies: s.technologies,
          discoveredAt: new Date(),
        },
      })
    ));

    const stored = await prisma.subdomainDiscovery.findMany({
      where: { domainId: domain.id },
      orderBy: [{ isLive: "desc" }, { subdomain: "asc" }],
    });
    res.json({ domain: domain.domain, subdomains: stored });
  } catch (err) { next(err); }
});

// ── List / update subdomains ───────────────────────────────────────────────────

router.get("/:id/subdomains", async (req, res, next) => {
  try {
    const user = req.user as { id: string };
    const member = await prisma.organizationMember.findFirst({ where: { userId: user.id } });
    const domain = await prisma.domain.findFirst({ where: { id: req.params["id"], orgId: member?.orgId } });
    if (!domain) { res.status(404).json({ error: "Domain not found" }); return; }
    const subdomains = await prisma.subdomainDiscovery.findMany({
      where: { domainId: domain.id },
      orderBy: [{ isLive: "desc" }, { subdomain: "asc" }],
    });
    res.json(subdomains);
  } catch (err) { next(err); }
});

router.patch("/:id/subdomains/:subId", async (req, res, next) => {
  try {
    const { includedInScan } = z.object({ includedInScan: z.boolean() }).parse(req.body);
    const user = req.user as { id: string };
    const member = await prisma.organizationMember.findFirst({ where: { userId: user.id } });
    const domain = await prisma.domain.findFirst({ where: { id: req.params["id"], orgId: member?.orgId } });
    if (!domain) { res.status(404).json({ error: "Domain not found" }); return; }
    const sub = await prisma.subdomainDiscovery.findFirst({
      where: { id: req.params["subId"], domainId: domain.id },
    });
    if (!sub) { res.status(404).json({ error: "Subdomain not found" }); return; }
    const updated = await prisma.subdomainDiscovery.update({
      where: { id: sub.id },
      data: { includedInScan },
    });
    res.json(updated);
  } catch (err) { next(err); }
});

// ── Full Pentest ───────────────────────────────────────────────────────────────

router.post("/:id/pentest", async (req, res, next) => {
  try {
    const body = z.object({
      depth: z.enum(["STANDARD", "AGGRESSIVE"]).default("STANDARD"),
      authorized: z.literal(true),
    }).parse(req.body);

    const user = req.user as { id: string };
    const member = await prisma.organizationMember.findFirst({ where: { userId: user.id } });
    const domain = await prisma.domain.findFirst({
      where: { id: req.params["id"], orgId: member?.orgId },
      include: { authConfig: true },
    });
    if (!domain) { res.status(404).json({ error: "Domain not found" }); return; }

    // Server-side authorization check
    if (!domain.authorized) {
      res.status(403).json({ error: "Domain not authorized for pentest. Call POST /authorize first." });
      return;
    }

    // Get user-selected subdomains. Strip the root domain itself if it
    // appears — `selectedSubdomains + domain.domain` would otherwise double
    // nuclei/nikto work in the scanner's vuln phase.
    const selectedSubdomainRows = await prisma.subdomainDiscovery.findMany({
      where: { domainId: domain.id, includedInScan: true },
      select: { subdomain: true },
    });
    const rootLower = domain.domain.toLowerCase().trim();
    const selectedSubdomains = selectedSubdomainRows
      .map((s) => s.subdomain)
      .filter((s) => s.toLowerCase().trim() !== rootLower);

    // Update pentestDepth on domain
    await prisma.domain.update({ where: { id: domain.id }, data: { pentestDepth: body.depth } });

    const result = await triggerScan({
      orgId: member!.orgId,
      targetType: "DOMAIN",
      targetId: domain.id,
      scanTypes: ["PENTEST_FULL"] as ScanType[],
      domain: domain.domain,
      selectedSubdomains,
      pentestDepth: body.depth,
      domainAuthConfigId: domain.authConfig?.id,
    });

    res.status(202).json(result);
  } catch (err) { next(err); }
});

// Trigger scan (DAST + Pentest)
router.post("/:id/scan", async (req, res, next) => {
  try {
    const user = req.user as { id: string };
    const member = await prisma.organizationMember.findFirst({ where: { userId: user.id } });
    const domain = await prisma.domain.findFirst({
      where: { id: req.params["id"], orgId: member?.orgId },
      include: { authConfig: true },
    });
    if (!domain) { res.status(404).json({ error: "Domain not found" }); return; }

    const scanTypes: ScanType[] = ["DAST", "PENTEST"];
    const result = await triggerScan({
      orgId: member!.orgId,
      targetType: "DOMAIN",
      targetId: domain.id,
      scanTypes,
      domain: domain.domain,
      domainAuthConfigId: domain.authConfig?.id,
    });
    res.status(202).json(result);
  } catch (err) { next(err); }
});

// ── Auth config ───────────────────────────────────────────────────────────────

const authConfigSchema = z.object({
  authType:         z.enum(["FORM", "HEADER", "COOKIE", "OAUTH2"]).default("FORM"),
  // FORM fields
  loginUrl:         z.string().optional(),
  usernameField:    z.string().default("username"),
  passwordField:    z.string().default("password"),
  username:         z.string().optional(),
  password:         z.string().optional(),
  loggedInPattern:  z.string().default("Logout"),
  loggedOutPattern: z.string().default("login"),
  // HEADER / COOKIE fields
  headerName:       z.string().optional(),
  headerValue:      z.string().optional(),
  // OAuth2 fields
  // Frontend always sends this field (empty string when FORM/HEADER/COOKIE
  // auth is selected). Coerce "" → undefined before URL validation so the
  // non-OAuth2 flow doesn't fail Zod with a 422.
  oauth2TokenUrl:    z.preprocess(
    (v) => (typeof v === "string" && v.trim() === "" ? undefined : v),
    z.string().url().optional(),
  ),
  oauth2ClientId:    z.string().optional(),
  oauth2ClientSecret: z.string().optional(),
  oauth2Scope:       z.string().optional(),
  oauth2GrantType:   z.enum(["client_credentials", "password"]).default("client_credentials"),
});

// GET /api/domains/:id/auth — return config without credentials
router.get("/:id/auth", async (req, res, next) => {
  try {
    const user = req.user as { id: string };
    const member = await prisma.organizationMember.findFirst({ where: { userId: user.id } });
    const domain = await prisma.domain.findFirst({ where: { id: req.params["id"], orgId: member?.orgId } });
    if (!domain) { res.status(404).json({ error: "Domain not found" }); return; }

    const cfg = await prisma.domainAuthConfig.findUnique({ where: { domainId: domain.id } });
    if (!cfg) { res.json(null); return; }

    // Return config without decrypted secrets
    res.json({
      id:               cfg.id,
      authType:         cfg.authType,
      loginUrl:         cfg.loginUrl,
      usernameField:    cfg.usernameField,
      passwordField:    cfg.passwordField,
      loggedInPattern:  cfg.loggedInPattern,
      loggedOutPattern: cfg.loggedOutPattern,
      headerName:       cfg.headerName,
      // OAuth2 non-secret fields
      oauth2TokenUrl:   cfg.oauth2TokenUrl,
      oauth2ClientId:   cfg.oauth2ClientId,
      oauth2Scope:      cfg.oauth2Scope,
      oauth2GrantType:  cfg.oauth2GrantType,
      hasCredentials:   true,  // secrets stored encrypted, not returned
    });
  } catch (err) { next(err); }
});

// PUT /api/domains/:id/auth — create or replace auth config
router.put("/:id/auth", async (req, res, next) => {
  try {
    const body = authConfigSchema.parse(req.body);
    const user = req.user as { id: string };
    const member = await prisma.organizationMember.findFirst({ where: { userId: user.id } });
    const domain = await prisma.domain.findFirst({ where: { id: req.params["id"], orgId: member?.orgId } });
    if (!domain) { res.status(404).json({ error: "Domain not found" }); return; }

    // Build and encrypt the credentials blob (secrets only — never return them)
    let credsPlain: string;
    if (body.authType === "FORM") {
      credsPlain = JSON.stringify({ username: body.username ?? "", password: body.password ?? "" });
    } else if (body.authType === "OAUTH2") {
      credsPlain = JSON.stringify({
        clientSecret: body.oauth2ClientSecret ?? "",
        username:     body.username           ?? "",
        password:     body.password           ?? "",
      });
    } else {
      credsPlain = JSON.stringify({ headerValue: body.headerValue ?? "" });
    }
    const encryptedCreds = encrypt(credsPlain);

    const cfg = await prisma.domainAuthConfig.upsert({
      where:  { domainId: domain.id },
      create: {
        domainId:         domain.id,
        authType:         body.authType,
        loginUrl:         body.loginUrl        ?? null,
        usernameField:    body.usernameField,
        passwordField:    body.passwordField,
        loggedInPattern:  body.loggedInPattern,
        loggedOutPattern: body.loggedOutPattern,
        headerName:       body.headerName      ?? null,
        // OAuth2
        oauth2TokenUrl:   body.oauth2TokenUrl   ?? null,
        oauth2ClientId:   body.oauth2ClientId   ?? null,
        oauth2Scope:      body.oauth2Scope       ?? null,
        oauth2GrantType:  body.oauth2GrantType,
        encryptedCreds,
      },
      update: {
        authType:         body.authType,
        loginUrl:         body.loginUrl        ?? null,
        usernameField:    body.usernameField,
        passwordField:    body.passwordField,
        loggedInPattern:  body.loggedInPattern,
        loggedOutPattern: body.loggedOutPattern,
        headerName:       body.headerName      ?? null,
        // OAuth2
        oauth2TokenUrl:   body.oauth2TokenUrl   ?? null,
        oauth2ClientId:   body.oauth2ClientId   ?? null,
        oauth2Scope:      body.oauth2Scope       ?? null,
        oauth2GrantType:  body.oauth2GrantType,
        encryptedCreds,
      },
    });

    res.json({ id: cfg.id, authType: cfg.authType, hasCredentials: true });
  } catch (err) { next(err); }
});

// DELETE /api/domains/:id/auth — remove auth config
router.delete("/:id/auth", async (req, res, next) => {
  try {
    const user = req.user as { id: string };
    const member = await prisma.organizationMember.findFirst({ where: { userId: user.id } });
    const domain = await prisma.domain.findFirst({ where: { id: req.params["id"], orgId: member?.orgId } });
    if (!domain) { res.status(404).json({ error: "Domain not found" }); return; }

    await prisma.domainAuthConfig.deleteMany({ where: { domainId: domain.id } });
    res.json({ ok: true });
  } catch (err) { next(err); }
});

// POST /api/domains/:id/risk-score
router.post("/:id/risk-score", async (req, res, next) => {
  try {
    const user   = req.user as { id: string };
    const member = await prisma.organizationMember.findFirst({ where: { userId: user.id } });
    const target = await prisma.domain.findFirst({ where: { id: req.params["id"], orgId: member?.orgId } });
    if (!target) { res.status(404).json({ error: "Domain not found" }); return; }
    await scoreTarget("DOMAIN", target.id);
    const updated = await prisma.domain.findUniqueOrThrow({ where: { id: target.id } });
    res.json({ aiRiskScore: updated.aiRiskScore, aiRiskReason: updated.aiRiskReason, aiRiskScoredAt: updated.aiRiskScoredAt });
  } catch (err) { next(err); }
});

// ── OpenAPI / Swagger spec import ────────────────────────────────────────────

const upsertApiSpec = z.object({
  filename: z.string().max(255),
  specJson: z.record(z.unknown()),
});

// GET /domains/:id/apispec
router.get("/:id/apispec", requireAuth, async (req, res, next) => {
  try {
    const user = req.user as { id: string };
    const member = await prisma.organizationMember.findFirst({ where: { userId: user.id } });
    if (!member) { res.status(403).json({ error: "Forbidden" }); return; }

    const spec = await prisma.domainApiSpec.findUnique({ where: { domainId: req.params.id } });
    res.json(spec);
  } catch (err) { next(err); }
});

// PUT /domains/:id/apispec
router.put("/:id/apispec", requireAuth, async (req, res, next) => {
  try {
    const user = req.user as { id: string };
    const member = await prisma.organizationMember.findFirst({ where: { userId: user.id } });
    if (!member) { res.status(403).json({ error: "Forbidden" }); return; }

    const body = upsertApiSpec.parse(req.body);

    // Count endpoints from OpenAPI 3.x or Swagger 2.x spec
    const paths = (body.specJson as Record<string, unknown>)["paths"] as Record<string, Record<string, unknown>> ?? {};
    const methods = ["get","post","put","patch","delete","options","head"];
    let endpoints = 0;
    for (const pathItem of Object.values(paths)) {
      endpoints += methods.filter(m => pathItem[m] !== undefined).length;
    }

    const domainId = req.params["id"]!;
    const spec = await prisma.domainApiSpec.upsert({
      where:  { domainId },
      create: { domainId, filename: body.filename, specJson: body.specJson as object, endpoints },
      update: { filename: body.filename, specJson: body.specJson as object, endpoints },
    });
    res.json(spec);
  } catch (err) { next(err); }
});

// DELETE /domains/:id/apispec
router.delete("/:id/apispec", requireAuth, async (req, res, next) => {
  try {
    const user = req.user as { id: string };
    const member = await prisma.organizationMember.findFirst({ where: { userId: user.id } });
    if (!member) { res.status(403).json({ error: "Forbidden" }); return; }

    await prisma.domainApiSpec.deleteMany({ where: { domainId: req.params.id } });
    res.status(204).send();
  } catch (err) { next(err); }
});

// ── Interactive DAST recording ────────────────────────────────────────────────

// Special path (underscore-prefixed) — never collides with cuid domain ids.
// Streams ZAP's CA cert through the API so the user can install it locally
// without the scanner being directly reachable from the browser.
router.get("/_recording/zap-ca.cer", async (_req, res, next) => {
  try {
    const bytes = await recording.fetchZapCaBytes();
    res.setHeader("Content-Type", "application/x-x509-ca-cert");
    res.setHeader("Content-Disposition", 'attachment; filename="zap-root-ca.cer"');
    res.send(bytes);
  } catch (err) { next(err); }
});

router.post("/:id/recording/start", async (req, res, next) => {
  try {
    const user = req.user as { id: string };
    const member = await prisma.organizationMember.findFirst({ where: { userId: user.id } });
    if (!member) { res.status(403).json({ error: "Forbidden" }); return; }
    const result = await recording.start({
      orgId:    member.orgId,
      domainId: req.params["id"]!,
      userId:   user.id,
    });
    res.json(result);
  } catch (err) {
    const code = (err as Error & { code?: string }).code;
    if (code === "RECORDING_BUSY") { res.status(409).json({ error: (err as Error).message }); return; }
    if (code === "NOT_FOUND")     { res.status(404).json({ error: (err as Error).message }); return; }
    next(err);
  }
});

router.get("/:id/recording/status", async (req, res, next) => {
  try {
    const user = req.user as { id: string };
    const member = await prisma.organizationMember.findFirst({ where: { userId: user.id } });
    if (!member) { res.status(403).json({ error: "Forbidden" }); return; }
    const result = await recording.status(member.orgId, req.params["id"]!);
    res.json(result);  // null when no active session — UI shows "start" state
  } catch (err) { next(err); }
});

router.post("/:id/recording/scan", async (req, res, next) => {
  try {
    const user = req.user as { id: string };
    const member = await prisma.organizationMember.findFirst({ where: { userId: user.id } });
    if (!member) { res.status(403).json({ error: "Forbidden" }); return; }
    const result = await recording.runScan(member.orgId, req.params["id"]!);
    res.status(202).json(result);
  } catch (err) {
    const code = (err as Error & { code?: string }).code;
    if (code === "NO_SESSION") { res.status(409).json({ error: (err as Error).message }); return; }
    next(err);
  }
});

router.post("/:id/recording/promote", async (req, res, next) => {
  try {
    const user = req.user as { id: string };
    const member = await prisma.organizationMember.findFirst({ where: { userId: user.id } });
    if (!member) { res.status(403).json({ error: "Forbidden" }); return; }
    const depth = req.body?.depth === "AGGRESSIVE" ? "AGGRESSIVE" : "STANDARD";
    const result = await recording.promote(member.orgId, req.params["id"]!, { depth });
    res.status(202).json(result);
  } catch (err) {
    const code = (err as Error & { code?: string }).code;
    if (code === "NO_SESSION")      { res.status(409).json({ error: (err as Error).message }); return; }
    if (code === "EMPTY_RECORDING") { res.status(422).json({ error: (err as Error).message }); return; }
    next(err);
  }
});

router.post("/:id/recording/stop", async (req, res, next) => {
  try {
    const user = req.user as { id: string };
    const member = await prisma.organizationMember.findFirst({ where: { userId: user.id } });
    if (!member) { res.status(403).json({ error: "Forbidden" }); return; }
    const result = await recording.stop(member.orgId, req.params["id"]!);
    res.json(result);
  } catch (err) { next(err); }
});

export default router;
