/**
 * Test helpers — shared fixtures for vitest unit + integration tests.
 *
 * Kept in `src/` (not `test/`) so test files can import via relative
 * paths without crossing the rootDir boundary.
 */

import type { Request, Response, NextFunction } from "express";
import type { Role } from "./services/rbac.js";

/**
 * Build a fake Express Request that looks "logged in as <role>".
 *
 * The real auth chain is passport + express-session + Redis; mocking
 * each layer would be brittle. Instead we mimic the post-auth shape:
 * `req.user`, `req.isAuthenticated()`, and the session activeOrgId
 * that getActiveMembership reads.
 *
 * Usage in middleware tests:
 *
 *   const req = mockRequest({ userId: "u1", activeOrgId: "o1" });
 *   const { res, status, json } = mockResponse();
 *   const next = vi.fn();
 *   await requireRole("ADMIN")(req, res, next);
 *   expect(next).toHaveBeenCalled();
 */
export function mockRequest(opts: {
  userId?: string | null;
  activeOrgId?: string | null;
} = {}): Request {
  const { userId = "test-user-id", activeOrgId = "test-org-id" } = opts;
  const req = {
    user:               userId ? { id: userId } : undefined,
    isAuthenticated:    () => Boolean(userId),
    session:            { activeOrgId } as Express.Request["session"],
    query:              {},
    body:               {},
    params:             {},
    headers:            {},
  } as unknown as Request;
  return req;
}

/**
 * mockResponse — vi-spy-backed Express Response stub.
 *
 * Returns the spies directly (`status`, `json`, `redirect`) so tests
 * can assert with `toHaveBeenCalledWith(...)`. We do NOT use getters
 * on the returned object: destructuring `{ status }` from a getter
 * captures the value at destructure time, not the live getter — that
 * burned us once.
 */
export function mockResponse() {
  const status   = vi.fn().mockReturnThis();
  const json     = vi.fn().mockReturnThis();
  const redirect = vi.fn().mockReturnThis();
  const setHeader = vi.fn().mockReturnThis();
  const res = { status, json, redirect, setHeader } as unknown as Response;
  return { res, status, json, redirect };
}

/**
 * One synthetic membership per role — enough to drive every requireRole
 * test without seeding a real DB. Assemble into a "fake membership table"
 * via fixtureMemberships().
 */
export function fixtureMembership(role: Role, orgId = "test-org-id") {
  return {
    userId: `user-${role.toLowerCase()}`,
    orgId,
    role,
  };
}

export function fixtureMemberships() {
  const roles: Role[] = ["OWNER", "ADMIN", "SECURITY", "DEVELOPER", "MEMBER", "VIEWER"];
  return Object.fromEntries(roles.map((r) => [r, fixtureMembership(r)]));
}

/**
 * Used by middleware tests — a real vi spy (so toHaveBeenCalled works)
 * with a `.lastError` getter that returns the first arg if next was
 * called with an Error. Cleaner than reading `next.mock.calls[0][0]`
 * everywhere.
 */
import { vi } from "vitest";

export function mockNext() {
  const fn = vi.fn() as ReturnType<typeof vi.fn> & {
    readonly lastError: unknown;
  };
  Object.defineProperty(fn, "lastError", {
    get() {
      return fn.mock.calls[0]?.[0];
    },
  });
  return fn as ReturnType<typeof vi.fn> & { readonly lastError: unknown };
}
