/**
 * Role contract — single source of truth for which BreachLens actions
 * require which minimum role.
 *
 * Both the backend (`requireRole(X)` middleware) and the frontend
 * (`<Can role="X">` wrappers) should match this contract. The
 * `role-contract.test.ts` files in apps/api and apps/web verify that
 * every actual call site agrees.
 *
 * Contract is the *floor* — UI may show buttons to a HIGHER role than
 * required. It must not show buttons to a LOWER role than the API
 * enforces.
 *
 * Adding a new role-gated action:
 *
 *   1. Add an entry below with id / description / minRole / api / ui
 *   2. In the route handler: `requireRole("MIN_ROLE")` matching the contract
 *   3. In the UI: `<Can role="MIN_ROLE">…</Can>` around the affordance
 *   4. Re-run tests — they confirm both sides agree
 */

import type { Role } from "./enums.js";

export interface RoleProtectedAction {
  /** Stable identifier — referenced by tests. kebab-case. */
  id: string;
  /** Human description of what this action does. */
  description: string;
  /** Minimum role required to perform the action. */
  minRole: Role;
  /** Backend route that enforces it via requireRole(). Optional for UI-only gates. */
  api?: { method: "GET" | "POST" | "PUT" | "PATCH" | "DELETE"; path: string };
  /** Frontend file that wraps the affordance with <Can>. Optional for headless API endpoints. */
  ui?: { file: string; affordance: string };
}

/**
 * Every role-gated action in BreachLens. Keep in sync with:
 *   - backend: apps/api/src/routes/(every router) requireRole calls
 *   - frontend: apps/web/src/(pages|components) <Can role> wrappers
 *
 * Tests in apps/api and apps/web fail loudly if a `requireRole(X)` or
 * `<Can role={X}>` call site doesn't have a matching entry here.
 */
export const ROLE_CONTRACT: readonly RoleProtectedAction[] = [
  // ── ADMIN tier — org administration, destructive / privacy-sensitive ──

  {
    id:          "view-admin-queues",
    description: "List BullMQ queues + counters (Bull-Board summary)",
    minRole:     "ADMIN",
    api:         { method: "GET", path: "/api/admin/queues" },
  },
  {
    id:          "view-failed-jobs",
    description: "Inspect failed jobs in a specific BullMQ queue",
    minRole:     "ADMIN",
    api:         { method: "GET", path: "/api/admin/queues/:name/failed" },
  },
  {
    id:          "retry-failed-job",
    description: "Re-queue a failed BullMQ job",
    minRole:     "ADMIN",
    api:         { method: "POST", path: "/api/admin/queues/:name/jobs/:jobId/retry" },
  },
  {
    id:          "delete-failed-job",
    description: "Permanently remove a failed BullMQ job from the queue",
    minRole:     "ADMIN",
    api:         { method: "DELETE", path: "/api/admin/queues/:name/jobs/:jobId" },
  },
  {
    id:          "view-audit-log",
    description: "Read the org's audit event stream",
    minRole:     "ADMIN",
    api:         { method: "GET", path: "/api/audit" },
    // ui: TODO Phase 22.7 — AuditLogTab is currently visible to all roles; API 403s on click
  },
  {
    id:          "export-audit-csv",
    description: "Download the audit log as CSV (RFC 4180)",
    minRole:     "ADMIN",
    api:         { method: "GET", path: "/api/audit/export.csv" },
    // ui: TODO Phase 22.7 — Export button currently visible to all roles; API 403s on click
  },
  {
    id:          "delete-repo",
    description: "Remove a repo from the org (cascades all findings)",
    minRole:     "ADMIN",
    api:         { method: "DELETE", path: "/api/repos/:id" },
    ui:          { file: "apps/web/src/pages/RepositoriesPage.tsx", affordance: "Delete row action" },
  },
  {
    id:          "delete-container",
    description: "Remove a container from the org (cascades all findings)",
    minRole:     "ADMIN",
    api:         { method: "DELETE", path: "/api/containers/:id" },
    ui:          { file: "apps/web/src/pages/ContainersPage.tsx", affordance: "Delete row action" },
  },
  {
    id:          "delete-domain",
    description: "Remove a domain from the org (cascades all findings)",
    minRole:     "ADMIN",
    api:         { method: "DELETE", path: "/api/domains/:id" },
    // ui: TODO Phase 22.7 — Delete button currently visible to all roles; API 403s on click
  },
  {
    id:          "change-member-role",
    description: "Change another member's role within the org",
    minRole:     "ADMIN",
    api:         { method: "PATCH", path: "/api/members/:userId" },
    ui:          { file: "apps/web/src/components/settings/TeamTab.tsx", affordance: "Role dropdown" },
  },
  {
    id:          "remove-member",
    description: "Remove a member from the org",
    minRole:     "ADMIN",
    api:         { method: "DELETE", path: "/api/members/:userId" },
    ui:          { file: "apps/web/src/components/settings/TeamTab.tsx", affordance: "Remove member button" },
  },
  {
    id:          "list-invitations",
    description: "List pending invitations for the org",
    minRole:     "ADMIN",
    api:         { method: "GET", path: "/api/members/invitations" },
    ui:          { file: "apps/web/src/components/settings/TeamTab.tsx", affordance: "Pending invitations list" },
  },
  {
    id:          "create-invitation",
    description: "Invite a GitHub user to the org",
    minRole:     "ADMIN",
    api:         { method: "POST", path: "/api/members/invitations" },
    ui:          { file: "apps/web/src/components/settings/TeamTab.tsx", affordance: "Invite member form" },
  },
  {
    id:          "revoke-invitation",
    description: "Revoke a pending invitation",
    minRole:     "ADMIN",
    api:         { method: "DELETE", path: "/api/members/invitations/:id" },
    ui:          { file: "apps/web/src/components/settings/TeamTab.tsx", affordance: "Revoke invitation button" },
  },
  {
    id:          "create-policy",
    description: "Create a policy (PR-check enforcement rules)",
    minRole:     "ADMIN",
    api:         { method: "POST", path: "/api/policies" },
    // ui: TODO Phase 22.7 — Create policy button currently visible to all roles; API 403s on click
  },
  {
    id:          "update-policy",
    description: "Edit a policy",
    minRole:     "ADMIN",
    api:         { method: "PUT", path: "/api/policies/:id" },
    // ui: TODO Phase 22.7 — Save edits visible to all roles; API 403s on click
  },
  {
    id:          "delete-policy",
    description: "Delete a policy",
    minRole:     "ADMIN",
    api:         { method: "DELETE", path: "/api/policies/:id" },
    // ui: TODO Phase 22.7 — Delete button visible to all roles; API 403s on click
  },
  {
    id:          "view-sso-config",
    description: "Read the org's SSO configuration",
    minRole:     "ADMIN",
    api:         { method: "GET", path: "/api/sso" },
    // ui: TODO Phase 22.7 — SSO tab currently visible to all roles; API 403s on click
  },
  {
    id:          "save-sso-config",
    description: "Create or update the org's SSO configuration",
    minRole:     "ADMIN",
    api:         { method: "PUT", path: "/api/sso" },
    // ui: TODO Phase 22.7 — Save button visible to all roles; API 403s on click
  },
  {
    id:          "delete-sso-config",
    description: "Remove the org's SSO configuration",
    minRole:     "ADMIN",
    api:         { method: "DELETE", path: "/api/sso" },
    // ui: TODO Phase 22.7 — Remove button visible to all roles; API 403s on click
  },
  {
    id:          "test-sso-discovery",
    description: "Probe IdP discovery URL to validate connectivity + scopes",
    minRole:     "ADMIN",
    api:         { method: "POST", path: "/api/sso/test" },
    // ui: TODO Phase 22.7 — Test connection visible to all roles; API 403s on click
  },

  // ── SECURITY tier — finding triage / risk acceptance ──

  {
    id:          "bulk-update-findings",
    description: "Change status of many findings at once",
    minRole:     "SECURITY",
    api:         { method: "POST", path: "/api/findings/bulk" },
    // ui: TODO Phase 22.7 — Bulk toolbar visible to all roles; API 403s on click
  },
  {
    id:          "bulk-create-tickets",
    description: "Create internal tickets for many findings at once",
    minRole:     "SECURITY",
    api:         { method: "POST", path: "/api/findings/bulk-tickets" },
    // ui: TODO Phase 22.7 — Bulk tickets toolbar visible to all roles; API 403s on click
  },
  {
    id:          "update-finding-status",
    description: "Change a single finding's status (FIXED, FALSE_POSITIVE, etc.)",
    minRole:     "SECURITY",
    api:         { method: "PATCH", path: "/api/findings/:id" },
    ui:          { file: "apps/web/src/components/FindingDetailDrawer.tsx", affordance: "Status dropdown" },
  },
  {
    id:          "update-subfinding-status",
    description: "Change status of a sub-finding within a multi-instance result",
    minRole:     "SECURITY",
    api:         { method: "PATCH", path: "/api/findings/:id/sub/:index" },
    ui:          { file: "apps/web/src/components/FindingDetailDrawer.tsx", affordance: "Per-instance status menu" },
  },
  {
    id:          "create-suppression",
    description: "Create an accepted-risk record",
    minRole:     "SECURITY",
    api:         { method: "POST", path: "/api/suppressions" },
    ui:          { file: "apps/web/src/components/FindingDetailDrawer.tsx", affordance: "Accept risk button" },
  },
  {
    id:          "revoke-suppression",
    description: "Revoke an accepted-risk record",
    minRole:     "SECURITY",
    api:         { method: "DELETE", path: "/api/suppressions/:id" },
    // ui: SuppressionsTab.tsx doesn't exist yet — revoke is via FindingDetailDrawer; gate TBD with Phase 22.7
  },

  // ── DEVELOPER tier — UI-only gates ──
  // Backend deliberately doesn't enforce DEVELOPER on these — see
  // CLAUDE.md "DEVELOPER+ — implicit" section. The UI gates them so
  // VIEWERs don't see add/trigger affordances they can't meaningfully
  // use; the API stays permissive for layered-defense reasons (the
  // destructive ops still hit ADMIN gates).

  {
    id:          "add-repo",
    description: "Add a new repository to the org",
    minRole:     "DEVELOPER",
    ui:          { file: "apps/web/src/pages/RepositoriesPage.tsx", affordance: "Add repository button" },
  },
  {
    id:          "trigger-repo-scan",
    description: "Kick off a scan job on a repo",
    minRole:     "DEVELOPER",
    ui:          { file: "apps/web/src/pages/RepositoriesPage.tsx", affordance: "Scan button row action" },
  },
  {
    id:          "add-container",
    description: "Add a new container image to the org",
    minRole:     "DEVELOPER",
    ui:          { file: "apps/web/src/pages/ContainersPage.tsx", affordance: "Add container button" },
  },
  {
    id:          "trigger-container-scan",
    description: "Kick off a scan job on a container image",
    minRole:     "DEVELOPER",
    ui:          { file: "apps/web/src/pages/ContainersPage.tsx", affordance: "Scan button row action" },
  },
];

// ── Lookup helpers — used by the parity tests ──────────────────────────

/**
 * Index by api method+path for the backend test:
 *   contractByApi.get("DELETE /api/repos/:id")?.minRole === "ADMIN"
 */
export const contractByApi: ReadonlyMap<string, RoleProtectedAction> = new Map(
  ROLE_CONTRACT
    .filter((a) => a.api)
    .map((a) => [`${a.api!.method} ${a.api!.path}`, a]),
);

/**
 * Index by ui.file for the frontend test:
 *   contractByUiFile.get("apps/web/src/pages/RepositoriesPage.tsx") → [add-repo, trigger-repo-scan, delete-repo]
 */
export const contractByUiFile: ReadonlyMap<string, readonly RoleProtectedAction[]> = (() => {
  const out = new Map<string, RoleProtectedAction[]>();
  for (const a of ROLE_CONTRACT) {
    if (!a.ui) continue;
    const list = out.get(a.ui.file) ?? [];
    list.push(a);
    out.set(a.ui.file, list);
  }
  return out;
})();
