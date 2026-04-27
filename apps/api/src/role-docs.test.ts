/**
 * RBAC docs drift test — asserts every entry in the role contract is
 * documented in docs/rbac.md.
 *
 * Mechanism: each documented capability has a hidden marker comment
 * `<!-- contract:<id> -->` next to it. This test reads the doc and
 * checks every contract entry's id appears as such a marker.
 *
 * Catches "added a new role-gated action to the contract but forgot
 * to document it for end users".
 *
 * Sister tests:
 *   - apps/api/src/role-contract.test.ts (contract ↔ backend code)
 *   - apps/web/src/role-contract.test.ts (contract ↔ frontend code)
 */

import { describe, it, expect } from "vitest";
import { readFileSync } from "node:fs";
import path from "node:path";
import { ROLE_CONTRACT } from "@devsecops/types";

const DOC_PATH = path.resolve(__dirname, "../../../docs/rbac.md");

describe("rbac docs drift", () => {
  const doc = readFileSync(DOC_PATH, "utf8");

  it("every contract entry has a `<!-- contract:<id> -->` marker in docs/rbac.md", () => {
    const errors: string[] = [];

    for (const action of ROLE_CONTRACT) {
      const marker = `<!-- contract:${action.id} -->`;
      if (!doc.includes(marker)) {
        errors.push(
          `MISSING DOC ENTRY: contract id "${action.id}" (minRole=${action.minRole}, ` +
          `"${action.description}") not found in docs/rbac.md. Add a bullet under the ` +
          `${action.minRole} section with the marker: ${marker}`,
        );
      }
    }

    expect(errors, errors.join("\n\n")).toEqual([]);
  });

  it("every `<!-- contract:<id> -->` marker in the docs corresponds to a real contract entry", () => {
    const validIds = new Set(ROLE_CONTRACT.map((a) => a.id));
    const errors: string[] = [];

    for (const m of doc.matchAll(/<!--\s*contract:([a-z0-9-]+)\s*-->/g)) {
      const id = m[1];
      if (!id || !validIds.has(id)) {
        errors.push(
          `STALE DOC MARKER: docs/rbac.md references "<!-- contract:${id} -->" ` +
          `but that id doesn't exist in roleContract.ts (was an action removed without ` +
          `cleaning up the doc?)`,
        );
      }
    }

    expect(errors, errors.join("\n")).toEqual([]);
  });
});
