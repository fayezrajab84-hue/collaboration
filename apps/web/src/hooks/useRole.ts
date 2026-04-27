/**
 * useRole — returns the current user's role in their ACTIVE org (the one
 * the org switcher selected, or the deterministic fallback) and a
 * `can(min)` helper for gating UI elements.
 */
import { useAuth } from "./useAuth";

export type Role = "OWNER" | "ADMIN" | "SECURITY" | "DEVELOPER" | "VIEWER" | "MEMBER";

const RANK: Record<Role, number> = {
  OWNER:     5,
  ADMIN:     4,
  SECURITY:  3,
  DEVELOPER: 2,
  MEMBER:    2,
  VIEWER:    1,
};

export function useRole() {
  const { user } = useAuth();

  // Pick the membership that matches the server-resolved activeOrgId.
  // Falls back to orgs[0] for the (rare, transient) case where /auth/me
  // hasn't returned activeOrgId yet — better than rendering as VIEWER
  // and flickering buttons in/out on the next render.
  const activeOrg =
    user?.orgs?.find((o) => o.id === user.activeOrgId) ?? user?.orgs?.[0];
  const role = (activeOrg?.role as Role | undefined) ?? null;

  function can(min: Role): boolean {
    if (!role) return false;
    return (RANK[role] ?? 0) >= RANK[min];
  }

  return { role, can };
}
