import type { Request, RequestHandler } from "express";
import prisma from "../db.js";
import { verifyToken, type VerifiedToken, type TokenScope } from "../services/apiTokenService.js";

// Stash the verified API token on the Request so downstream handlers
// (getActiveMembership, requireScope) can read it without re-verifying.
declare module "express-serve-static-core" {
  interface Request {
    apiToken?: VerifiedToken;
  }
}

/**
 * requireAuth — Phase A4 dual-mode.
 *
 * Two ways a request can be authenticated:
 *   1. Session cookie (passport-github / passport-oidc) — the existing
 *      browser flow. Populated via `req.isAuthenticated()`.
 *   2. `Authorization: Bearer blt_<token>` header — Phase A4 long-lived
 *      bearer tokens for non-interactive callers (CI, CLI, scripts).
 *      The token's creator becomes the `req.user`; the token's org
 *      becomes the active org (overriding session activeOrgId);
 *      `req.apiToken` is set so scope-checking middleware can enforce
 *      capability gates.
 *
 * Bearer takes precedence — if a request sends both a session AND a
 * Bearer header, Bearer wins. This keeps automation deterministic
 * (operators who copy a session from their browser into a CI env var
 * shouldn't accidentally inherit interactive role state).
 */
export const requireAuth: RequestHandler = async (req, res, next) => {
  const authHeader = req.headers.authorization;
  if (authHeader?.startsWith("Bearer ")) {
    const token = authHeader.slice(7).trim();
    const verified = await verifyToken(token);
    if (!verified) {
      res.status(401).json({ error: "Invalid or expired API token" });
      return;
    }
    // Hydrate req.user the same shape passport would. Downstream code
    // reads req.user.id; the User row exists because the FK on
    // ApiToken.createdById is enforced.
    const user = await prisma.user.findUnique({
      where:  { id: verified.createdById },
      select: { id: true, username: true, email: true, avatarUrl: true },
    });
    if (!user) {
      // Owner deleted while their token was still active. Treat as a
      // revocation — operator should mint a new token under a current user.
      res.status(401).json({ error: "Token owner no longer exists" });
      return;
    }
    req.user = user as Express.User;
    req.apiToken = verified;
    next();
    return;
  }

  // Session-cookie auth path — existing browser flow.
  if (req.isAuthenticated()) {
    next();
    return;
  }

  res.status(401).json({ error: "Authentication required" });
};

/**
 * requireScope — gate a route on a specific token scope.
 *
 * Sessions are NOT scope-limited (interactive users have full role-
 * based capability via requireRole). Bearer tokens MUST declare the
 * scope they want to use. Mounted AFTER requireAuth.
 *
 * Behaviour:
 *   - Session auth: passes through unchanged.
 *   - Bearer auth: 403 if the token's scopes[] doesn't contain the
 *     required scope.
 *
 * Routes that handle write operations (POST scans, DELETE findings)
 * should layer requireScope alongside requireRole — the role check is
 * the user-floor, the scope check is the token-cap.
 */
export function requireScope(required: TokenScope): RequestHandler {
  return (req, res, next) => {
    // Sessions bypass scope checks — interactive users have role-based gates.
    if (!req.apiToken) { next(); return; }
    if (req.apiToken.scopes.includes(required)) { next(); return; }
    res.status(403).json({
      error: "API token missing required scope",
      required,
      granted: req.apiToken.scopes,
    });
  };
}

/**
 * Helper for activeOrgService — when the request is Bearer-authed,
 * the active org is fixed by the token (token is org-scoped at mint
 * time). Returns null when not Bearer-authed; activeOrgService falls
 * back to its session-based resolution.
 */
export function getApiTokenOrgId(req: Request): string | null {
  return req.apiToken?.orgId ?? null;
}
