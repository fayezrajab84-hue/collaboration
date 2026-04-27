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
import { getActiveMembership } from "../services/activeOrgService.js";
import { ROLE_RANK, type Role } from "../services/rbac.js";

declare module "express-serve-static-core" {
  interface Request {
    orgId?:   string;
    orgRole?: Role;
  }
}

/**
 * The membership resolver `requireRole` calls. Defaults to the real
 * `getActiveMembership`; tests inject a stub so they don't need to
 * mock the entire module via vi.mock (which is brittle under ESM).
 */
export type MembershipResolver = (
  req: Request,
) => Promise<{ orgId: string; role: Role } | null>;

/**
 * RequestHandler with metadata — tests introspect the live Express
 * router stack (via `router.stack[i].route.stack[j].handle.__minRole`)
 * to verify the parity contract; without this tag they'd have to parse
 * source files to discover which routes are role-gated.
 */
export type RoleGatedHandler = RequestHandler & { readonly __minRole: Role };

export function requireRole(
  minRole: Role,
  resolveMember: MembershipResolver = getActiveMembership,
): RoleGatedHandler {
  const handler: RequestHandler = async (req: Request, res, next) => {
    try {
      if (!req.isAuthenticated || !req.isAuthenticated()) {
        res.status(401).json({ error: "Authentication required" });
        return;
      }
      const user = req.user as { id: string };
      const member = await resolveMember(req);
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
  // Tag the handler so the parity test can find it via Express's
  // router.stack introspection.
  Object.defineProperty(handler, "__minRole", { value: minRole, enumerable: true });
  return handler as RoleGatedHandler;
}
