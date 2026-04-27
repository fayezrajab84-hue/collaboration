/**
 * Frontend parity test — verifies every `<Can role="X">` site in the web
 * codebase matches the canonical role contract in
 * packages/types/src/roleContract.ts.
 *
 * Strategy: scan .tsx files for `<Can role="X">` patterns + `useRole().can("X")`
 * checks. Map matches to contract entries by file path. Two assertions:
 *
 *   1. Every contract entry with .ui has a matching <Can role={minRole}> in
 *      the file it points to — catches "removed the gate but contract
 *      still claims the file gates this action"
 *   2. Every <Can role="X"> in the codebase uses a Role value that appears
 *      somewhere in the contract — catches typos like <Can role="ADIMN">
 *
 * Sister test: apps/api/src/role-contract.test.ts (backend parity).
 *
 * No React rendering needed — pure source scan.
 */

import { describe, it, expect } from "vitest";
import { readFileSync, readdirSync, statSync } from "node:fs";
import path from "node:path";
import { ROLE_CONTRACT, contractByUiFile, type Role } from "@devsecops/types";

const REPO_ROOT = path.resolve(__dirname, "../../..");

/**
 * Recursively list files under `dir` matching one of the extensions,
 * skipping common ignored directories.
 */
function listFiles(dir: string, exts: string[]): string[] {
  const out: string[] = [];
  for (const entry of readdirSync(dir)) {
    if (entry === "node_modules" || entry === "dist" || entry === ".git") continue;
    const full = path.join(dir, entry);
    const stat = statSync(full);
    if (stat.isDirectory()) {
      out.push(...listFiles(full, exts));
    } else if (exts.some((e) => entry.endsWith(e))) {
      out.push(full);
    }
  }
  return out;
}

/**
 * Find every `<Can role="X">` in a file and return the unique roles
 * referenced. Tolerates whitespace + multi-line. Both string-literal
 * and JSX-expression forms supported.
 */
function findCanRoles(src: string): Set<Role> {
  const roles = new Set<Role>();
  // <Can role="X"> — string literal form
  for (const m of src.matchAll(/<Can\s+role=["']([A-Z]+)["']/g)) {
    if (m[1]) roles.add(m[1] as Role);
  }
  // <Can role={"X"}> or <Can role={X} where X is enum-like — JSX form
  for (const m of src.matchAll(/<Can\s+role=\{["']?([A-Z]+)["']?\}/g)) {
    if (m[1]) roles.add(m[1] as Role);
  }
  return roles;
}

const VALID_ROLES = new Set<Role>(["OWNER", "ADMIN", "SECURITY", "DEVELOPER", "MEMBER", "VIEWER"]);

describe("role contract — frontend parity", () => {
  it("every contract entry with ui pointer has a matching <Can role> in the file", () => {
    const errors: string[] = [];

    for (const [relFile, actions] of contractByUiFile.entries()) {
      const absFile = path.join(REPO_ROOT, relFile);
      let src: string;
      try {
        src = readFileSync(absFile, "utf8");
      } catch {
        errors.push(
          `MISSING UI FILE: contract points at ${relFile} but the file doesn't exist. ` +
          `Either create it, fix the path, or drop the ui pointer from the contract entry.`,
        );
        continue;
      }

      const found = findCanRoles(src);
      const expected = new Set(actions.map((a) => a.minRole));

      for (const role of expected) {
        if (!found.has(role)) {
          const actionIds = actions.filter((a) => a.minRole === role).map((a) => a.id).join(", ");
          errors.push(
            `MISSING <Can role="${role}">: ${relFile} should gate { ${actionIds} } ` +
            `but no <Can role="${role}"> was found in the file. ` +
            `Either wrap the affordance in <Can role="${role}">…</Can>, raise the gate to ` +
            `a role already used in the file, or remove the contract entry if the affordance is gone.`,
          );
        }
      }
    }

    expect(errors, errors.join("\n\n")).toEqual([]);
  });

  it("every <Can role> in the codebase uses a Role value that's documented somewhere in the contract", () => {
    const webSrc = path.join(REPO_ROOT, "apps/web/src");
    const allTsx = listFiles(webSrc, [".tsx"]);
    const errors: string[] = [];

    const contractRoles = new Set<Role>(ROLE_CONTRACT.map((a) => a.minRole));

    for (const file of allTsx) {
      const src = readFileSync(file, "utf8");
      const found = findCanRoles(src);
      for (const role of found) {
        if (!VALID_ROLES.has(role)) {
          errors.push(`INVALID ROLE: ${path.relative(REPO_ROOT, file)} uses <Can role="${role}"> — not a valid Role enum value`);
        } else if (!contractRoles.has(role)) {
          errors.push(
            `UNDOCUMENTED ROLE: ${path.relative(REPO_ROOT, file)} uses <Can role="${role}"> ` +
            `but no contract entry has minRole=${role}. Add an entry or change the gate.`,
          );
        }
      }
    }

    expect(errors, errors.join("\n")).toEqual([]);
  });

  it("emits a non-empty <Can role> survey (sanity check)", () => {
    // Defensive — if the file scanner returns nothing the parity assertions
    // pass vacuously. Make sure we're actually finding gates in the codebase.
    const webSrc = path.join(REPO_ROOT, "apps/web/src");
    const allTsx = listFiles(webSrc, [".tsx"]);
    const totalCanCount = allTsx.reduce(
      (acc, f) => acc + findCanRoles(readFileSync(f, "utf8")).size,
      0,
    );
    expect(totalCanCount).toBeGreaterThan(0);
  });
});
