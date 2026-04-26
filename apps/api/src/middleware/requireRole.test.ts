/**
 * requireRole middleware — the security boundary that gates every
 * org-administration route. A regression here can silently demote
 * ADMIN-only operations (delete repo, change member role, edit SSO
 * config) to be callable by VIEWER, so this test file exhaustively
 * covers every rank/auth combination.
 *
 * Strategy: pass a fake `resolveMember` directly into requireRole
 * (dependency injection). No vi.mock incantations, no module-cache
 * games — just synthetic membership rows fed to the middleware.
 *
 * If you add a new role to the Role enum or change ROLE_RANK, update
 * the matrix table — that's the canonical capability regression check.
 */

import { describe, it, expect } from "vitest";
import { requireRole } from "./requireRole.js";
import type { Role } from "../services/rbac.js";
import {
  mockRequest,
  mockResponse,
  mockNext,
  fixtureMembership,
} from "../test-helpers.js";

// Pre-built resolvers for each scenario — keeps the matrix tests
// noise-free. The resolver returns whatever you set it up to return,
// regardless of the req argument (which the matrix doesn't vary).
const resolverReturning = (member: ReturnType<typeof fixtureMembership> | null) =>
  async () => member;

describe("requireRole — auth boundary", () => {
  it("returns 401 when the request is not authenticated", async () => {
    const req = mockRequest({ userId: null });
    const { res, status, json } = mockResponse();
    const next = mockNext();

    await requireRole("VIEWER", resolverReturning(null))(req, res, next);

    expect(status).toHaveBeenCalledWith(401);
    expect(json).toHaveBeenCalledWith({ error: "Authentication required" });
    expect(next).not.toHaveBeenCalled();
  });

  it("returns 403 with explanatory message when the user has no org membership", async () => {
    const req = mockRequest();
    const { res, status, json } = mockResponse();
    const next = mockNext();

    await requireRole("VIEWER", resolverReturning(null))(req, res, next);

    expect(status).toHaveBeenCalledWith(403);
    expect(json).toHaveBeenCalledWith({ error: "No organization membership" });
    expect(next).not.toHaveBeenCalled();
  });

  it("propagates unexpected errors via next() instead of swallowing them", async () => {
    const boom = new Error("db connection lost");
    const failingResolver = async () => { throw boom; };
    const req = mockRequest();
    const { res } = mockResponse();
    const next = mockNext();

    await requireRole("VIEWER", failingResolver)(req, res, next);

    expect(next.lastError).toBe(boom);
  });
});

describe("requireRole — rank checks (the capability matrix)", () => {
  // Every (actualRole, requiredRole) combination — the matrix that
  // defines BreachLens's RBAC. Each cell asserts whether actualRole
  // can pass through a `requireRole(requiredRole)` gate. This IS the
  // RBAC contract, encoded as a table.
  //
  // Read row-wise: "if you have role X, can you reach a min-Y route?"
  // Read column-wise: "if a route requires Y, which roles can hit it?"

  type MatrixRow = { actual: Role; allowed: Set<Role> };

  const MATRIX: MatrixRow[] = [
    { actual: "OWNER",     allowed: new Set(["OWNER", "ADMIN", "SECURITY", "DEVELOPER", "VIEWER"]) },
    { actual: "ADMIN",     allowed: new Set([         "ADMIN", "SECURITY", "DEVELOPER", "VIEWER"]) },
    { actual: "SECURITY",  allowed: new Set([                  "SECURITY", "DEVELOPER", "VIEWER"]) },
    { actual: "DEVELOPER", allowed: new Set([                              "DEVELOPER", "VIEWER"]) },
    { actual: "MEMBER",    allowed: new Set([                              "DEVELOPER", "VIEWER"]) }, // legacy alias
    { actual: "VIEWER",    allowed: new Set([                                           "VIEWER"]) },
  ];

  const ALL_ROLES: Role[] = ["OWNER", "ADMIN", "SECURITY", "DEVELOPER", "VIEWER"];

  for (const row of MATRIX) {
    describe(`actor with role=${row.actual}`, () => {
      for (const required of ALL_ROLES) {
        const shouldPass = row.allowed.has(required);

        it(
          `${shouldPass ? "passes" : "rejects"} requireRole("${required}")`,
          async () => {
            const req = mockRequest();
            const { res, status, json } = mockResponse();
            const next = mockNext();

            await requireRole(
              required,
              resolverReturning(fixtureMembership(row.actual)),
            )(req, res, next);

            if (shouldPass) {
              // Passed gate: next() called with no error, side effects populated
              expect(next).toHaveBeenCalledWith();
              expect(req.orgRole).toBe(row.actual);
              expect(req.orgId).toBe("test-org-id");
              expect(status).not.toHaveBeenCalled();
            } else {
              // Rejected: 403 with explanatory message
              expect(status).toHaveBeenCalledWith(403);
              expect(json).toHaveBeenCalledWith({
                error: `Requires role ${required} or higher (you have ${row.actual})`,
              });
              expect(next).not.toHaveBeenCalled();
            }
          },
        );
      }
    });
  }
});

describe("requireRole — side effects on success", () => {
  it("populates req.orgId and req.orgRole for downstream handlers", async () => {
    const req = mockRequest();
    const { res } = mockResponse();
    const next = mockNext();

    await requireRole(
      "ADMIN",
      resolverReturning(fixtureMembership("OWNER", "the-org")),
    )(req, res, next);

    expect(req.orgId).toBe("the-org");
    expect(req.orgRole).toBe("OWNER");
  });
});
