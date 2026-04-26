/**
 * rbac.ts — pure-function tests for the role hierarchy.
 *
 * These guard against ROLE_RANK regressions (e.g. someone reorders
 * the map and accidentally promotes VIEWER above DEVELOPER). The
 * middleware tests in requireRole.test.ts depend on this contract
 * being correct.
 */

import { describe, it, expect } from "vitest";
import { ROLE_RANK, roleAtLeast, hasAnyRole, type Role } from "./rbac.js";

describe("ROLE_RANK — hierarchy invariants", () => {
  it("orders OWNER > ADMIN > SECURITY > DEVELOPER > VIEWER", () => {
    expect(ROLE_RANK.OWNER).toBeGreaterThan(ROLE_RANK.ADMIN);
    expect(ROLE_RANK.ADMIN).toBeGreaterThan(ROLE_RANK.SECURITY);
    expect(ROLE_RANK.SECURITY).toBeGreaterThan(ROLE_RANK.DEVELOPER);
    expect(ROLE_RANK.DEVELOPER).toBeGreaterThan(ROLE_RANK.VIEWER);
  });

  it("treats MEMBER (legacy) at the same rank as DEVELOPER", () => {
    // Pre-Phase-22 enum value. Anything that grants DEVELOPER must also
    // grant MEMBER and vice versa — otherwise legacy users silently
    // lose access on upgrade.
    expect(ROLE_RANK.MEMBER).toBe(ROLE_RANK.DEVELOPER);
  });

  it("has a positive non-zero rank for every Role", () => {
    // A missing entry would default to 0 in `roleAtLeast`, silently
    // denying access — better to fail loudly here.
    const allRoles: Role[] = ["OWNER", "ADMIN", "SECURITY", "DEVELOPER", "MEMBER", "VIEWER"];
    for (const r of allRoles) {
      expect(ROLE_RANK[r]).toBeGreaterThan(0);
    }
  });
});

describe("roleAtLeast()", () => {
  it("returns false for null/undefined input", () => {
    expect(roleAtLeast(null,      "VIEWER")).toBe(false);
    expect(roleAtLeast(undefined, "VIEWER")).toBe(false);
  });

  it("is true when the role's rank meets or exceeds the minimum", () => {
    expect(roleAtLeast("ADMIN",     "SECURITY")).toBe(true);  // 4 >= 3
    expect(roleAtLeast("ADMIN",     "ADMIN")).toBe(true);     // 4 >= 4 (equal)
    expect(roleAtLeast("OWNER",     "VIEWER")).toBe(true);    // 5 >= 1
  });

  it("is false when the role's rank is below the minimum", () => {
    expect(roleAtLeast("VIEWER",    "DEVELOPER")).toBe(false); // 1 < 2
    expect(roleAtLeast("DEVELOPER", "ADMIN")).toBe(false);     // 2 < 4
    expect(roleAtLeast("SECURITY",  "OWNER")).toBe(false);     // 3 < 5
  });

  it("treats MEMBER and DEVELOPER as interchangeable", () => {
    expect(roleAtLeast("MEMBER",    "DEVELOPER")).toBe(true);
    expect(roleAtLeast("DEVELOPER", "MEMBER")).toBe(true);
  });
});

describe("hasAnyRole()", () => {
  it("returns true if the role is in the allowlist", () => {
    expect(hasAnyRole("ADMIN", ["OWNER", "ADMIN"])).toBe(true);
  });

  it("returns false if the role is not in the allowlist", () => {
    expect(hasAnyRole("DEVELOPER", ["OWNER", "ADMIN"])).toBe(false);
  });

  it("treats MEMBER as DEVELOPER for allowlist matching", () => {
    // Same legacy invariant as ROLE_RANK — anything that whitelists
    // DEVELOPER implicitly whitelists MEMBER.
    expect(hasAnyRole("MEMBER", ["DEVELOPER"])).toBe(true);
  });

  it("returns false for null/undefined input", () => {
    expect(hasAnyRole(null,      ["VIEWER"])).toBe(false);
    expect(hasAnyRole(undefined, ["VIEWER"])).toBe(false);
  });
});
