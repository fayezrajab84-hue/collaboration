/**
 * RBAC — role hierarchy and permission helpers.
 *
 * Mirror of packages/types/src/enums.ts ROLE_RANK, kept here to avoid the api
 * package importing TS source from the types package when running under tsx.
 */

export type Role = "OWNER" | "ADMIN" | "SECURITY" | "DEVELOPER" | "VIEWER" | "MEMBER";

// Higher = more permissions. MEMBER is legacy and treated as DEVELOPER.
export const ROLE_RANK: Record<Role, number> = {
  OWNER:     5,
  ADMIN:     4,
  SECURITY:  3,
  DEVELOPER: 2,
  MEMBER:    2,
  VIEWER:    1,
};

export function roleAtLeast(role: Role | null | undefined, min: Role): boolean {
  if (!role) return false;
  return (ROLE_RANK[role] ?? 0) >= ROLE_RANK[min];
}

export function hasAnyRole(role: Role | null | undefined, allowed: Role[]): boolean {
  if (!role) return false;
  return allowed.includes(role) || (role === "MEMBER" && allowed.includes("DEVELOPER"));
}
