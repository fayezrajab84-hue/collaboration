/**
 * /api/cloud-accounts — Phase 29 Slice A.
 *
 * CRUD over the CloudAccount asset model (CSPM target). Follows the same
 * shape as /api/containers + /api/domains so the web UI can use the
 * same react-query + modal pattern.
 *
 * Slice A only supports AZURE provider; future slices add AWS + GCP by
 * extending validators + routing the test-connection to the relevant
 * provider helper. The route surface stays uniform.
 *
 * Routes:
 *   GET    /                     list (orgId-scoped, with finding counts)
 *   POST   /                     create (with credential encryption)
 *   GET    /:id                  fetch one (encryption blob never returned)
 *   PATCH  /:id                  update display name OR re-paste credentials
 *   DELETE /:id                  ADMIN+ — cascade-deletes scans + findings
 *   POST   /:id/test-connection  validate credentials hit Azure + can read sub
 *   POST   /:id/scan             trigger a CSPM scan (Phase 29 Commit 2)
 */
import { Router } from "express";
import { z } from "zod";
import { requireAuth } from "../../middleware/requireAuth.js";
import { requireRole } from "../../middleware/requireRole.js";
import prisma from "../../db.js";
import { getActiveMembership } from "../../services/activeOrgService.js";
import { encrypt, decrypt } from "../../services/encryptionService.js";
import { testAzureConnection, type AzureCredentials } from "../../services/cloud/azureAuth.js";
import { triggerScan } from "../../services/scanService.js";
import * as audit from "../../services/auditService.js";
import { logger } from "../../logger.js";
import type { ScanType } from "@devsecops/types";

const router = Router();
router.use(requireAuth);

// ── Validators ──────────────────────────────────────────────────────────
//
// Provider-aware: AZURE requires tenantId / azureClientId / subscriptionId
// + clientSecret. AWS / GCP will land their own variants in later slices.
// GUIDs validated loosely (Azure tenant / sub IDs are 8-4-4-4-12 hex);
// we don't assert the SP id is a GUID because some legacy deployments
// use AppId-by-name forms — Azure's token endpoint is the real authority.

const guidSchema = z.string().regex(/^[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}$/i, "must be a GUID");

const azureCreateSchema = z.object({
  provider:       z.literal("AZURE"),
  displayName:    z.string().min(1).max(100),
  tenantId:       guidSchema,
  azureClientId:  z.string().min(1),    // most are GUIDs but allow non-GUID names
  subscriptionId: guidSchema,
  clientSecret:   z.string().min(1),    // the one secret-bearing field; encrypted before persistence
});

const azureUpdateSchema = z.object({
  displayName:    z.string().min(1).max(100).optional(),
  // Re-paste credentials: any of these triggers a re-encryption. Operators
  // who only want to rename leave them off.
  tenantId:       guidSchema.optional(),
  azureClientId:  z.string().min(1).optional(),
  subscriptionId: guidSchema.optional(),
  clientSecret:   z.string().min(1).optional(),
  isActive:       z.boolean().optional(),
});

// Test connection: operator can either point at an existing CloudAccount
// (use stored creds) OR pass a fresh credential set inline (validate
// before save). The inline form is what the "Test connection" button on
// the create modal uses — confirms the SP works before the operator
// commits to creating the account record.
const testConnectionInlineSchema = z.object({
  provider:       z.literal("AZURE"),
  tenantId:       guidSchema,
  azureClientId:  z.string().min(1),
  subscriptionId: guidSchema,
  clientSecret:   z.string().min(1),
});

// ── Helpers ─────────────────────────────────────────────────────────────

/** Strip the encrypted blob before sending to the client. The blob is
 *  per-org-encrypted but still treated as opaque — clients should never
 *  need it. `credentialsConfigured` (derived) tells the UI whether
 *  credentials are present without exposing them. */
type CloudAccountRow = {
  id:                   string;
  orgId:                string;
  provider:             string;
  displayName:          string;
  tenantId:             string | null;
  azureClientId:        string | null;
  subscriptionId:       string | null;
  encryptedCredentials: string | null;
  isActive:             boolean;
  lastScannedAt:        Date | null;
  lastScanError:        string | null;
  addedAt:              Date;
  updatedAt:            Date;
};

function shapeForClient(row: CloudAccountRow) {
  const { encryptedCredentials, ...rest } = row;
  return {
    ...rest,
    credentialsConfigured: encryptedCredentials != null,
  };
}

// ── Routes ──────────────────────────────────────────────────────────────

// GET /api/cloud-accounts — list with finding counts
router.get("/", async (req, res, next) => {
  try {
    const member = await getActiveMembership(req);
    if (!member) { res.json([]); return; }

    const [rows, countRows] = await Promise.all([
      prisma.cloudAccount.findMany({
        where:   { orgId: member.orgId },
        orderBy: { addedAt: "desc" },
      }),
      prisma.finding.groupBy({
        by:    ["cloudAccountId", "severity"],
        where: { orgId: member.orgId, cloudAccountId: { not: null }, status: { not: "FALSE_POSITIVE" } },
        _count: { id: true },
      }),
    ]);

    const countMap: Record<string, Record<string, number>> = {};
    for (const r of countRows) {
      const id = r.cloudAccountId!;
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

// POST /api/cloud-accounts — create
router.post("/", async (req, res, next) => {
  try {
    const body   = azureCreateSchema.parse(req.body);
    const user   = req.user as { id: string };
    const member = await getActiveMembership(req);
    if (!member) { res.status(400).json({ error: "No organization found" }); return; }

    // Encrypt the credential blob via encryptionService — same
    // AES-256-GCM pattern as DomainAuthConfig. We persist the entire
    // credential set as JSON so future provider variants can extend
    // without schema changes (e.g. AWS would store accessKeyId +
    // secretAccessKey under the same field).
    const credBlob = JSON.stringify({ clientSecret: body.clientSecret });
    const encryptedCredentials = encrypt(credBlob);

    try {
      const created = await prisma.cloudAccount.create({
        data: {
          orgId:          member.orgId,
          provider:       body.provider,
          displayName:    body.displayName,
          tenantId:       body.tenantId,
          azureClientId:  body.azureClientId,
          subscriptionId: body.subscriptionId,
          encryptedCredentials,
        },
      });
      await audit.log({
        orgId:        member.orgId,
        userId:       user.id,
        action:       "cloud_account.create",
        resourceType: "CloudAccount",
        resourceId:   created.id,
        metadata:     { provider: body.provider, subscriptionId: body.subscriptionId, displayName: body.displayName },
      });
      res.status(201).json(shapeForClient(created));
    } catch (e: unknown) {
      // Unique constraint on (orgId, provider, subscriptionId) — re-paste
      // attempts on existing accounts get a useful error rather than
      // a 500.
      if (e && typeof e === "object" && (e as { code?: string }).code === "P2002") {
        res.status(409).json({ error: "A cloud account with this subscription already exists in this organisation" });
        return;
      }
      throw e;
    }
  } catch (err) { next(err); }
});

// GET /api/cloud-accounts/:id
router.get("/:id", async (req, res, next) => {
  try {
    const member = await getActiveMembership(req);
    const row = await prisma.cloudAccount.findFirst({
      where: { id: req.params["id"], orgId: member?.orgId },
    });
    if (!row) { res.status(404).json({ error: "Cloud account not found" }); return; }
    res.json(shapeForClient(row));
  } catch (err) { next(err); }
});

// PATCH /api/cloud-accounts/:id — update display name or re-paste creds
router.patch("/:id", async (req, res, next) => {
  try {
    const body   = azureUpdateSchema.parse(req.body);
    const user   = req.user as { id: string };
    const member = await getActiveMembership(req);
    const row    = await prisma.cloudAccount.findFirst({
      where: { id: req.params["id"], orgId: member?.orgId },
    });
    if (!row) { res.status(404).json({ error: "Cloud account not found" }); return; }

    const data: Record<string, unknown> = {};
    if (body.displayName    !== undefined) data["displayName"]    = body.displayName;
    if (body.tenantId       !== undefined) data["tenantId"]       = body.tenantId;
    if (body.azureClientId  !== undefined) data["azureClientId"]  = body.azureClientId;
    if (body.subscriptionId !== undefined) data["subscriptionId"] = body.subscriptionId;
    if (body.isActive       !== undefined) data["isActive"]       = body.isActive;
    // Re-encrypt only when a new clientSecret was passed — don't churn
    // the blob on a rename-only edit (cheaper + keeps audit log focused).
    if (body.clientSecret) {
      data["encryptedCredentials"] = encrypt(JSON.stringify({ clientSecret: body.clientSecret }));
    }

    const updated = await prisma.cloudAccount.update({ where: { id: row.id }, data });
    await audit.log({
      orgId:        member!.orgId,
      userId:       user.id,
      action:       "cloud_account.update",
      resourceType: "CloudAccount",
      resourceId:   updated.id,
      metadata:     { fields: Object.keys(data), credentialsRotated: !!body.clientSecret },
    });
    res.json(shapeForClient(updated));
  } catch (err) { next(err); }
});

// DELETE /api/cloud-accounts/:id — ADMIN+ (cascade removes scans + findings)
router.delete("/:id", requireRole("ADMIN"), async (req, res, next) => {
  try {
    const user = req.user as { id: string };
    const row = await prisma.cloudAccount.findFirst({
      where: { id: req.params["id"], orgId: req.orgId! },
    });
    if (!row) { res.status(404).json({ error: "Cloud account not found" }); return; }
    await prisma.cloudAccount.delete({ where: { id: row.id } });
    await audit.log({
      orgId:        req.orgId!,
      userId:       user.id,
      action:       "cloud_account.delete",
      resourceType: "CloudAccount",
      resourceId:   row.id,
      metadata:     { provider: row.provider, displayName: row.displayName, subscriptionId: row.subscriptionId },
    });
    res.json({ ok: true });
  } catch (err) { next(err); }
});

// POST /api/cloud-accounts/:id/test-connection — validate stored creds
router.post("/:id/test-connection", async (req, res, next) => {
  try {
    const member = await getActiveMembership(req);
    const row = await prisma.cloudAccount.findFirst({
      where: { id: req.params["id"], orgId: member?.orgId },
    });
    if (!row) { res.status(404).json({ error: "Cloud account not found" }); return; }
    if (!row.encryptedCredentials || !row.tenantId || !row.azureClientId || !row.subscriptionId) {
      res.status(400).json({ error: "Cloud account has no credentials configured" });
      return;
    }

    // Decrypt the credential blob → reconstruct AzureCredentials.
    let creds: AzureCredentials;
    try {
      const blob = JSON.parse(decrypt(row.encryptedCredentials)) as { clientSecret: string };
      creds = {
        tenantId:       row.tenantId,
        clientId:       row.azureClientId,
        clientSecret:   blob.clientSecret,
        subscriptionId: row.subscriptionId,
      };
    } catch (e) {
      logger.error(`[cloud-accounts] failed to decrypt credentials for account ${row.id}: ${(e as Error).message}`);
      res.status(500).json({ error: "Failed to decrypt stored credentials" });
      return;
    }

    const result = await testAzureConnection(creds);

    // Persist the test result on the row so the listing UI shows
    // "credentials valid" / "credentials invalid" without re-running
    // the test on every refresh. lastScanError doubles as the test-
    // connection error sink; lastScannedAt remains scan-trigger-only.
    await prisma.cloudAccount.update({
      where: { id: row.id },
      data:  { lastScanError: result.ok ? null : result.message },
    });

    if (result.ok) {
      res.json(result);
    } else {
      // 422 — credential / configuration issue (operator-fixable).
      // Distinct from 500 (our problem) and 401 (auth on BreachLens).
      res.status(422).json(result);
    }
  } catch (err) { next(err); }
});

// POST /api/cloud-accounts/:id/scan — trigger a CSPM scan
//
// Wraps Prowler-Azure (Phase 29 Slice A). The worker decrypts the
// CloudAccount's stored credentials at scan-trigger time and forwards
// them to the scanner over the internal Docker network. DEVELOPER+
// (consistent with /api/containers/:id/scan).
router.post("/:id/scan", async (req, res, next) => {
  try {
    const user   = req.user as { id: string };
    const member = await getActiveMembership(req);
    if (!member) { res.status(404).json({ error: "Cloud account not found" }); return; }

    const account = await prisma.cloudAccount.findFirst({
      where: { id: req.params["id"], orgId: member.orgId },
    });
    if (!account) {
      res.status(404).json({ error: "Cloud account not found" });
      return;
    }
    if (!account.encryptedCredentials || !account.tenantId || !account.azureClientId || !account.subscriptionId) {
      res.status(400).json({ error: "Cloud account has no credentials configured. Add credentials before scanning." });
      return;
    }
    if (!account.isActive) {
      res.status(400).json({ error: "Cloud account is inactive. Activate it before scanning." });
      return;
    }

    const scanTypes: ScanType[] = ["CLOUD"];
    const result = await triggerScan({
      orgId:      member.orgId,
      targetType: "CLOUD_ACCOUNT",
      targetId:   account.id,
      scanTypes,
    });

    await audit.log({
      orgId:        member.orgId,
      userId:       user.id,
      action:       "cloud_account.scan",
      resourceType: "CloudAccount",
      resourceId:   account.id,
      metadata:     { scanJobId: result.scanJobId, provider: account.provider, subscriptionId: account.subscriptionId },
    });
    res.status(202).json(result);
  } catch (err) { next(err); }
});

// POST /api/cloud-accounts/test-connection-inline — validate creds before save
//
// Used by the create modal's "Test" button: operator pastes credentials,
// clicks Test, and sees a green/red signal before committing the row.
// Doesn't persist anything.
router.post("/test-connection-inline", async (req, res, next) => {
  try {
    const body   = testConnectionInlineSchema.parse(req.body);
    const member = await getActiveMembership(req);
    if (!member) { res.status(400).json({ error: "No organization found" }); return; }

    const result = await testAzureConnection({
      tenantId:       body.tenantId,
      clientId:       body.azureClientId,
      clientSecret:   body.clientSecret,
      subscriptionId: body.subscriptionId,
    });

    if (result.ok) {
      res.json(result);
    } else {
      res.status(422).json(result);
    }
  } catch (err) { next(err); }
});

export default router;
