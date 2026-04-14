import { NavLink, Outlet, useNavigate } from "react-router-dom";
import {
  LayoutDashboard, GitBranch, Box, Globe, ShieldAlert,
  Ticket, Settings, LogOut, Shield,
} from "lucide-react";
import { useAuth } from "../hooks/useAuth";
import { authApi } from "../lib/api";
import { cn } from "../lib/utils";

const NAV_ITEMS = [
  { to: "/dashboard",    label: "Dashboard",     icon: LayoutDashboard },
  { to: "/repositories", label: "Repositories",  icon: GitBranch },
  { to: "/containers",   label: "Containers",    icon: Box },
  { to: "/domains",      label: "Domains",       icon: Globe },
  { to: "/findings",     label: "Findings",      icon: ShieldAlert },
  { to: "/tickets",      label: "Tickets",       icon: Ticket },
  { to: "/settings",     label: "Settings",      icon: Settings },
];

export default function Layout() {
  const { user } = useAuth();
  const navigate = useNavigate();

  async function handleLogout() {
    await authApi.logout();
    navigate("/login");
  }

  return (
    <div className="flex h-screen overflow-hidden bg-gray-950">
      {/* Sidebar */}
      <aside className="flex w-56 flex-shrink-0 flex-col border-r border-gray-800 bg-gray-900">
        {/* Logo */}
        <div className="flex h-16 items-center gap-2.5 border-b border-gray-800 px-4">
          <Shield className="h-6 w-6 text-indigo-400" />
          <span className="text-sm font-bold tracking-tight text-white">DevSecOps</span>
        </div>

        {/* Nav */}
        <nav className="flex-1 overflow-y-auto py-4">
          {NAV_ITEMS.map(({ to, label, icon: Icon }) => (
            <NavLink
              key={to}
              to={to}
              className={({ isActive }) =>
                cn(
                  "flex items-center gap-3 px-4 py-2.5 text-sm font-medium transition-colors",
                  isActive
                    ? "bg-indigo-900/40 text-indigo-300"
                    : "text-gray-400 hover:bg-gray-800 hover:text-gray-100"
                )
              }
            >
              <Icon className="h-4 w-4 flex-shrink-0" />
              {label}
            </NavLink>
          ))}
        </nav>

        {/* User footer */}
        <div className="border-t border-gray-800 p-3">
          <div className="flex items-center gap-2.5 rounded-lg p-2">
            {user?.avatarUrl ? (
              <img src={user.avatarUrl} alt={user.username} className="h-7 w-7 rounded-full" />
            ) : (
              <div className="flex h-7 w-7 items-center justify-center rounded-full bg-indigo-700 text-xs font-bold text-white">
                {user?.username?.[0]?.toUpperCase() ?? "?"}
              </div>
            )}
            <span className="flex-1 truncate text-xs text-gray-300">{user?.username}</span>
            <button
              onClick={handleLogout}
              className="text-gray-500 hover:text-gray-300"
              title="Sign out"
            >
              <LogOut className="h-4 w-4" />
            </button>
          </div>
        </div>
      </aside>

      {/* Main content */}
      <main className="flex-1 overflow-y-auto">
        <Outlet />
      </main>
    </div>
  );
}
