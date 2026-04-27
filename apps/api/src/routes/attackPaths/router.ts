/**
 * /api/attack-paths — Phase 27 Slice C.
 *
 * GET  /api/attack-paths           list (top N by score) for the active org
 * GET  /api/attack-paths/:groupId  detail (one chain, full nodes + edges)
 *
 * Both VIEWER+ — chains are derived from existing findings the user is
 * already allowed to see; no new sensitive data surfaces here.
 */
import { Router } from "express";
import { requireAuth } from "../../middleware/requireAuth.js";
import { getActiveMembership } from "../../services/activeOrgService.js";
import * as audit from "../../services/auditService.js";
import {
  listAttackPaths,
  getAttackPath,
} from "../../services/correlation/attackPathService.js";
import {
  generateSummary,
  getCachedSummary,
} from "../../services/correlation/attackPathSummaryService.js";
import { AIError } from "../../services/aiClient.js";

const router = Router();
router.use(requireAuth);

router.get("/", async (req, res, next) => {
  try {
    const member = await getActiveMembership(req);
    if (!member) { res.json({ paths: [] }); return; }
    const limit = Math.min(Math.max(parseInt(String(req.query["limit"] ?? "50"), 10), 1), 200);
    const paths = await listAttackPaths(member.orgId, limit);
    res.json({ paths });
  } catch (err) { next(err); }
});

router.get("/:groupId", async (req, res, next) => {
  try {
    const member = await getActiveMembership(req);
    if (!member) { res.status(404).json({ error: "Attack path not found" }); return; }
    const path = await getAttackPath(member.orgId, req.params["groupId"]!);
    if (!path) { res.status(404).json({ error: "Attack path not found" }); return; }
    // Include cached summary on the detail response so the UI can render
    // it without a second round-trip. Null when never generated.
    const summary = await getCachedSummary(member.orgId, req.params["groupId"]!);
    res.json({ ...path, summary });
  } catch (err) { next(err); }
});

// POST /api/attack-paths/:groupId/summarise — Phase 27.5.x AI summary.
// VIEWER+ — chains are derived from already-readable findings; the AI call
// just describes them. Audit-logged because every AI call costs money.
// Pass ?force=true to bypass the content-hash cache (regenerate from scratch).
router.post("/:groupId/summarise", async (req, res, next) => {
  try {
    const user   = req.user as { id: string };
    const member = await getActiveMembership(req);
    if (!member) { res.status(404).json({ error: "Attack path not found" }); return; }
    const force = String(req.query["force"] ?? "false") === "true";

    let result;
    try {
      result = await generateSummary(member.orgId, req.params["groupId"]!, { force });
    } catch (err) {
      if (err instanceof AIError) {
        // 503 — provider problem, not a client error. Operator should
        // configure / fix their AI provider and retry.
        res.status(503).json({ error: err.message, code: err.code });
        return;
      }
      throw err;
    }

    if (!result.cached) {
      await audit.log({
        orgId:        member.orgId,
        userId:       user.id,
        action:       "attack_path.summary.generate",
        resourceType: "AttackPathSummary",
        resourceId:   req.params["groupId"]!,
        metadata:     { force, providerType: result.providerType, model: result.model },
      });
    }

    res.json(result);
  } catch (err) { next(err); }
});

export default router;
