/**
 * useRole — returns the current user's role in their active org and a
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
  const role = (user?.orgs?.[0]?.role as Role | undefined) ?? null;

  function can(min: Role): boolean {
    if (!role) return false;
    return (RANK[role] ?? 0) >= RANK[min];
  }

  return { role, can };
}
