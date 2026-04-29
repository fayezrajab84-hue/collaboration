/**
 * apiTokens router — Phase A4 CI integration.
 *
 * Endpoints:
 *   GET    /api/auth/tokens         — list tokens for active org
 *   POST   /api/auth/tokens         — mint new token (returns plaintext ONCE)
 *   DELETE /api/auth/tokens/:id     — revoke token (soft, preserves audit)
 *   DELETE /api/auth/tokens/:id?hard=1 — hard delete (operator opt-in)
 *
 * Authorization model:
 *   - List: any authenticated member of the org (operators want to see
 *     their own tokens + auditors want to see who has tokens).
 *   - Mint: ADMIN+ — token capability is real attack-surface. Sessions
 *     can mint with whatever scopes they choose; there's no "you can
 *     only mint scopes you have" check because operators with role
 *     ADMIN+ already have all the role-gated capabilities the scopes
 *     map to.
 *   - Revoke / hard-delete: ADMIN+ — same reasoning.
 *
 * Audit trail:
 *   Every mint/revoke/delete writes an audit row so operators investigating
 *   "who created this token that scanned my repo" can answer.
 */
import { Router } from "express";
import { z } from "zod";
import { requireAuth } from "../../middleware/requireAuth.js";
import { requireRole } from "../../middleware/requireRole.js";
import { getActiveMembership } from "../../services/activeOrgService.js";
import {
  createToken, listTokens, revokeToken, deleteToken,
  ALL_SCOPES, isKnownScope, type TokenScope,
} from "../../services/apiTokenService.js";
import * as audit from "../../services/auditService.js";

const router = Router();
router.use(requireAuth);

// ── List ─────────────────────────────────────────────────────────────────

router.get("/", async (req, res, next) => {
  try {
    const member = await getActiveMembership(req);
    if (!member) { res.json({ tokens: [], allScopes: ALL_SCOPES }); return; }
    const tokens = await listTokens(member.orgId);
    res.json({ tokens, allScopes: ALL_SCOPES });
  } catch (err) { next(err); }
});

// ── Mint ─────────────────────────────────────────────────────────────────
//
// Returns the plaintext token in the response body — ONCE. The frontend
// shows a copy-to-clipboard modal; once the operator dismisses it, the
// plaintext is gone forever (only the hash + display prefix persist).

const mintSchema = z.object({
  name:      z.string().trim().min(1).max(120),
  scopes:    z.array(z.string()).min(1).refine(
    (arr) => arr.every(isKnownScope),
    { message: "Unknown scope — must be one of scans:trigger / scans:read / findings:read" },
  ),
  // Operator picks "30 days", "90 days", "never" in the UI; we accept
  // either an ISO date OR null (never expires).
  expiresAt: z.union([z.string().datetime(), z.null()]).optional().default(null),
});

router.post("/", requireRole("ADMIN"), async (req, res, next) => {
  try {
    const body = mintSchema.parse(req.body);
    const member = await getActiveMembership(req);
    if (!member) { res.status(403).json({ error: "No active org" }); return; }
    const user = req.user as { id: string };

    const created = await createToken({
      orgId:       member.orgId,
      createdById: user.id,
      name:        body.name,
      scopes:      body.scopes as TokenScope[],
      expiresAt:   body.expiresAt ? new Date(body.expiresAt) : null,
    });

    await audit.log({
      orgId:        member.orgId,
      userId:       user.id,
      action:       "apiToken.create",
      resourceType: "ApiToken",
      resourceId:   created.id,
      metadata:     { name: body.name, scopes: body.scopes, expiresAt: body.expiresAt },
    });

    // Plaintext returned in `token` — operator MUST copy it now; the
    // server cannot reproduce it. Frontend shows a copy-to-clipboard
    // panel and refuses to close until acknowledged.
    res.status(201).json({
      id:        created.id,
      token:     created.plaintext,
      prefix:    created.prefix,
      message:   "Copy this token now — it will never be shown again.",
    });
  } catch (err) { next(err); }
});

// ── Revoke (soft) ────────────────────────────────────────────────────────

router.delete("/:id", requireRole("ADMIN"), async (req, res, next) => {
  try {
    const member = await getActiveMembership(req);
    if (!member) { res.status(403).json({ error: "No active org" }); return; }
    const user = req.user as { id: string };
    const tokenId = req.params["id"]!;
    const hard = String(req.query["hard"] ?? "") === "1";

    const ok = hard
      ? await deleteToken(member.orgId, tokenId)
      : await revokeToken(member.orgId, tokenId);
    if (!ok) { res.status(404).json({ error: "Token not found" }); return; }

    await audit.log({
      orgId:        member.orgId,
      userId:       user.id,
      action:       hard ? "apiToken.delete" : "apiToken.revoke",
      resourceType: "ApiToken",
      resourceId:   tokenId,
      metadata:     { hard },
    });

    res.json({ ok: true });
  } catch (err) { next(err); }
});

export default router;
