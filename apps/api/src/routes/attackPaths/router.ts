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
import {
  listAttackPaths,
  getAttackPath,
} from "../../services/correlation/attackPathService.js";

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
    res.json(path);
  } catch (err) { next(err); }
});

export default router;
