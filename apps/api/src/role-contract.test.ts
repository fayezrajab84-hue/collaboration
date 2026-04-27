/**
 * Backend parity test — verifies every actual `requireRole(X)` call site
 * in the routers matches the canonical role contract in
 * packages/types/src/roleContract.ts.
 *
 * Strategy: import each router, walk its Express stack, and for each
 * route find the requireRole-marked handler (tagged with `__minRole`).
 * Build a {method+path → minRole} map of what the live app actually
 * enforces, then diff against the contract.
 *
 * Two assertions:
 *   1. Every live route with requireRole has a contract entry with
 *      matching minRole — catches "added a new requireRole but forgot
 *      to document it" and "changed the role in code but not contract"
 *   2. Every contract entry with .api maps to a live route — catches
 *      "removed a requireRole but contract still claims it exists"
 *
 * Sister test: apps/web/src/role-contract.test.ts (frontend Can parity).
 */

import { describe, it, expect } from "vitest";
import type { Router } from "express";
import { ROLE_CONTRACT, contractByApi } from "@devsecops/types";
import type { Role } from "./services/rbac.js";

import reposRouter         from "./routes/repos/router.js";
import containersRouter    from "./routes/containers/router.js";
import domainsRouter       from "./routes/domains/router.js";
import findingsRouter      from "./routes/findings/router.js";
import ticketsRouter       from "./routes/tickets/router.js";
import scansRouter         from "./routes/scans/router.js";
import integrationsRouter  from "./routes/integrations/router.js";
import chatRouter          from "./routes/chat/router.js";
import reportsRouter       from "./routes/reports/router.js";
import suppressionsRouter  from "./routes/suppressions/router.js";
import aiProvidersRouter   from "./routes/aiProviders/router.js";
import adminRouter         from "./routes/admin/router.js";
import policiesRouter      from "./routes/policies/router.js";
import auditRouter         from "./routes/audit/router.js";
import membersRouter       from "./routes/members/router.js";
import ssoRouter           from "./routes/sso/router.js";
import sbomRouter          from "./routes/sbom/router.js";
import complianceRouter    from "./routes/compliance/router.js";

// Mount paths must match app.ts. If you add a new router, add it here AND
// in app.ts AND in the contract — the second assertion below will yell
// if the contract has a route this map can't find.
const ROUTERS: Record<string, Router> = {
  "/api/repos":        reposRouter,
  "/api/containers":   containersRouter,
  "/api/domains":      domainsRouter,
  "/api/findings":     findingsRouter,
  "/api/tickets":      ticketsRouter,
  "/api/scans":        scansRouter,
  "/api/integrations": integrationsRouter,
  "/api/chat":         chatRouter,
  "/api/reports":      reportsRouter,
  "/api/suppressions": suppressionsRouter,
  "/api/ai-providers": aiProvidersRouter,
  "/api/admin":        adminRouter,
  "/api/policies":     policiesRouter,
  "/api/audit":        auditRouter,
  "/api/members":      membersRouter,
  "/api/sso":          ssoRouter,
  "/api/sbom":         sbomRouter,
  "/api/compliance":   complianceRouter,
};

interface LiveGate {
  method: string;
  path: string;
  minRole: Role;
}

/**
 * Walk an Express router and emit one entry per role-gated route.
 *
 * Express layer shapes:
 *   - layer.route          → defined route, has .path and .methods
 *   - layer.route.stack[i] → individual middleware in the route chain
 *   - layer.route.stack[i].handle → the function (may have __minRole tag)
 *
 * `router.use(requireRole("ADMIN"))` — router-level use — would attach
 * to a layer with no .route, applying to all routes; we handle that
 * by capturing it as a "default" minRole and applying it to every
 * subsequent route in the same router.
 */
function walkRouter(mount: string, router: Router): LiveGate[] {
  const out: LiveGate[] = [];
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  const stack = (router as unknown as { stack: any[] }).stack ?? [];

  // Track router-level requireRole use() (applies to all subsequent routes)
  let routerWideMinRole: Role | undefined;

  for (const layer of stack) {
    if (!layer.route) {
      // Router-level middleware — check if it's a requireRole
      const handler = layer.handle;
      if (handler && typeof handler === "function" && "__minRole" in handler) {
        routerWideMinRole = handler.__minRole as Role;
      }
      continue;
    }

    const methods = Object.keys(layer.route.methods).filter((m) => layer.route.methods[m]);
    const subPath = layer.route.path === "/" ? "" : layer.route.path;
    const fullPath = mount + subPath;

    // Find route-level requireRole if any
    let routeMinRole: Role | undefined;
    for (const sub of layer.route.stack ?? []) {
      const h = sub.handle;
      if (h && typeof h === "function" && "__minRole" in h) {
        routeMinRole = h.__minRole as Role;
        break;
      }
    }

    const effectiveMinRole = routeMinRole ?? routerWideMinRole;
    if (!effectiveMinRole) continue;

    for (const method of methods) {
      out.push({ method: method.toUpperCase(), path: fullPath, minRole: effectiveMinRole });
    }
  }

  return out;
}

function listAllLiveGates(): LiveGate[] {
  return Object.entries(ROUTERS).flatMap(([mount, r]) => walkRouter(mount, r));
}

describe("role contract — backend parity", () => {
  it("every requireRole site has a matching contract entry with the same minRole", () => {
    const live = listAllLiveGates();
    const errors: string[] = [];

    for (const gate of live) {
      const key = `${gate.method} ${gate.path}`;
      const entry = contractByApi.get(key);

      if (!entry) {
        errors.push(
          `MISSING CONTRACT ENTRY: ${key} requires ${gate.minRole} in code but ` +
          `has no entry in packages/types/src/roleContract.ts`,
        );
        continue;
      }

      if (entry.minRole !== gate.minRole) {
        errors.push(
          `ROLE MISMATCH: ${key} — code requires ${gate.minRole}, ` +
          `contract says ${entry.minRole} (entry id: "${entry.id}")`,
        );
      }
    }

    expect(errors, errors.join("\n")).toEqual([]);
  });

  it("every contract api entry corresponds to a live route", () => {
    const liveKeys = new Set(listAllLiveGates().map((g) => `${g.method} ${g.path}`));
    const errors: string[] = [];

    for (const action of ROLE_CONTRACT) {
      if (!action.api) continue;
      const key = `${action.api.method} ${action.api.path}`;
      if (!liveKeys.has(key)) {
        errors.push(
          `ORPHAN CONTRACT ENTRY: "${action.id}" claims ${key} requires ` +
          `${action.minRole} but no live route uses requireRole(${action.minRole}) on that path`,
        );
      }
    }

    expect(errors, errors.join("\n")).toEqual([]);
  });

  it("emits a non-empty live-gate list (sanity check)", () => {
    // Defensive — if router introspection silently returns nothing, the
    // two parity assertions above would both pass vacuously.
    expect(listAllLiveGates().length).toBeGreaterThan(0);
  });
});
