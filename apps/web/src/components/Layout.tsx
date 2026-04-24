import { NavLink, Outlet, useNavigate } from "react-router-dom";
import {
  Gauge, FolderGit2, Container, Network, Bug,
  Workflow, Settings, LogOut, Radar, BrainCircuit, FileBarChart, Layers,
} from "lucide-react";
import { useAuth } from "../hooks/useAuth";
import { authApi } from "../lib/api";
import { cn } from "../lib/utils";

const NAV_ITEMS = [
  { to: "/dashboard",    label: "Dashboard",     icon: Gauge },
  { to: "/repositories", label: "Repositories",  icon: FolderGit2 },
  { to: "/containers",   label: "Containers",    icon: Container },
  { to: "/domains",      label: "Domains",       icon: Network },
  { to: "/scans",        label: "Scans",         icon: Radar },
  { to: "/findings",     label: "Findings",      icon: Bug },
  { to: "/tickets",      label: "Tickets",       icon: Workflow },
  { to: "/chat",         label: "AI Chat",       icon: BrainCircuit },
  { to: "/report",       label: "Security Report", icon: FileBarChart },
  { to: "/settings",     label: "Settings",      icon: Settings },
];

/**
 * BreachLens brand logo.
 *
 * Concept:
 *   • Indigo shield silhouette           → protection
 *   • White aperture "eye" with rays     → lens / detection
 *   • White lightning bolt through eye   → fast breach detection
 */
function BreachLensLogo({ className = "" }: { className?: string }) {
  return (
    <svg
      viewBox="0 0 24 24"
      className={className}
      fill="none"
      xmlns="http://www.w3.org/2000/svg"
      aria-label="BreachLens logo"
    >
      {/* Shield body — filled indigo with a lighter outline */}
      <path
        d="M 4 3.5 H 20 V 12 C 20 18 16 21 12 22.8 C 8 21 4 18 4 12 Z"
        fill="#4f46e5"
        stroke="#a5b4fc"
        strokeWidth="0.9"
        strokeLinejoin="round"
      />

      {/* Central aperture "eye" — white circle */}
      <circle cx="12" cy="11" r="4.2" fill="#ffffff" />

      {/* Six short radial rays around the eye (shutter hint) */}
      <g stroke="#e0e7ff" strokeWidth="0.9" strokeLinecap="round">
        <line x1="12"    y1="5.3"  x2="12"    y2="6.6"  />
        <line x1="12"    y1="15.4" x2="12"    y2="16.7" />
        <line x1="6.3"   y1="11"   x2="7.6"   y2="11"   />
        <line x1="16.4"  y1="11"   x2="17.7"  y2="11"   />
        <line x1="7.7"   y1="6.7"  x2="8.65"  y2="7.65" />
        <line x1="15.35" y1="14.35" x2="16.3" y2="15.3" />
      </g>

      {/* Lightning bolt — white, centered on the eye */}
      <path
        d="M 13.1 6.2 L 9.3 11.7 L 11.9 11.7 L 10.6 16.7 L 14.9 10.4 L 12.3 10.4 Z"
        fill="#ffffff"
        stroke="#4f46e5"
        strokeWidth="0.35"
        strokeLinejoin="round"
      />
    </svg>
  );
}

const ADMIN_ROLES = new Set(["OWNER", "ADMIN"]);

export default function Layout() {
  const { user } = useAuth();
  const navigate = useNavigate();

  // Show admin-only nav items when any org membership has OWNER/ADMIN role.
  const isAdmin = !!user?.orgs?.some((o) => ADMIN_ROLES.has(o.role));
  const navItems = isAdmin
    ? [...NAV_ITEMS, { to: "/admin/queues", label: "Queues", icon: Layers }]
    : NAV_ITEMS;

  async function handleLogout() {
    await authApi.logout();
    navigate("/login");
  }

  return (
    <div className="flex h-screen overflow-hidden bg-gray-950">
      {/* ── Sidebar ────────────────────────────────────────────────────────── */}
      <aside className="flex w-64 flex-shrink-0 flex-col border-r border-gray-800 bg-gray-900">

        {/* Brand / Logo */}
        <div className="flex h-[72px] items-center gap-3 border-b border-gray-800 px-5">
          <BreachLensLogo className="h-9 w-9 flex-shrink-0" />
          <div className="flex flex-col leading-tight">
            <span className="text-base font-extrabold tracking-wide text-white">
              BreachLens
            </span>
            <span className="text-[10px] font-medium tracking-widest text-indigo-400 uppercase">
              DevSecOps
            </span>
          </div>
        </div>

        {/* Nav */}
        <nav className="flex-1 overflow-y-auto py-3">
          {navItems.map(({ to, label, icon: Icon }) => (
            <NavLink
              key={to}
              to={to}
              className={({ isActive }) =>
                cn(
                  "flex items-center gap-3 px-5 py-3 text-[15px] font-medium transition-colors",
                  isActive
                    ? "bg-indigo-900/50 text-indigo-300 border-r-2 border-indigo-500"
                    : "text-gray-400 hover:bg-gray-800 hover:text-gray-100"
                )
              }
            >
              <Icon className="h-[18px] w-[18px] flex-shrink-0" />
              {label}
            </NavLink>
          ))}
        </nav>

        {/* User footer */}
        <div className="border-t border-gray-800 p-3">
          <div className="flex items-center gap-3 rounded-lg px-2 py-2">
            {user?.avatarUrl ? (
              <img
                src={user.avatarUrl}
                alt={user.username}
                className="h-8 w-8 rounded-full ring-1 ring-indigo-700"
              />
            ) : (
              <div className="flex h-8 w-8 items-center justify-center rounded-full bg-indigo-700 text-sm font-bold text-white">
                {user?.username?.[0]?.toUpperCase() ?? "?"}
              </div>
            )}
            <span className="flex-1 truncate text-sm text-gray-300">{user?.username}</span>
            <button
              onClick={handleLogout}
              className="text-gray-500 hover:text-gray-200 transition-colors"
              title="Sign out"
            >
              <LogOut className="h-4 w-4" />
            </button>
          </div>
        </div>
      </aside>

      {/* ── Main content ───────────────────────────────────────────────────── */}
      <main className="flex-1 overflow-y-auto">
        <Outlet />
      </main>
    </div>
  );
}
