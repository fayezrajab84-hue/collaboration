/**
 * <Can role="ADMIN">…</Can> — render children only when current user's role
 * meets the minimum. Use to hide buttons/menus the user cannot use.
 */
import type { ReactNode } from "react";
import { useRole, type Role } from "../hooks/useRole";

export default function Can({
  role,
  fallback = null,
  children,
}: {
  role:      Role;
  fallback?: ReactNode;
  children:  ReactNode;
}) {
  const { can } = useRole();
  return <>{can(role) ? children : fallback}</>;
}
