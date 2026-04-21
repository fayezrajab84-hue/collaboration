/**
 * requireRole — gate a route by minimum org role.
 *
 * Loads the current user's membership in their active org and checks that
 * the role is at least the minimum required. Populates `req.orgRole` and
 * `req.orgId` as side effects so downstream handlers can reuse them.
 *
 * Legacy `MEMBER` role is treated as `DEVELOPER` (rank 2).
 *
 *   router.delete("/:id", requireRole("ADMIN"), async (req, res) => { ... });
 */
import type { Request, RequestHandler } from "express";
import prisma from "../db.js";
import { ROLE_RANK, type Role } from "../services/rbac.js";

declare module "express-serve-static-core" {
  interface Request {
    orgId?:   string;
    orgRole?: Role;
  }
}

export function requireRole(minRole: Role): RequestHandler {
  return async (req: Request, res, next) => {
    try {
      if (!req.isAuthenticated || !req.isAuthenticated()) {
        res.status(401).json({ error: "Authentication required" });
        return;
      }
      const user = req.user as { id: string };
      const member = await prisma.organizationMember.findFirst({ where: { userId: user.id } });
      if (!member) {
        res.status(403).json({ error: "No organization membership" });
        return;
      }

      const actualRank = ROLE_RANK[member.role as Role] ?? 0;
      const minRank    = ROLE_RANK[minRole];
      if (actualRank < minRank) {
        res.status(403).json({
          error: `Requires role ${minRole} or higher (you have ${member.role})`,
        });
        return;
      }

      req.orgId   = member.orgId;
      req.orgRole = member.role as Role;
      next();
    } catch (err) {
      next(err);
    }
  };
}
