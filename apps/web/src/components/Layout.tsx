import { NavLink, Outlet, useNavigate } from "react-router-dom";
import {
  LayoutDashboard, GitBranch, Box, Globe, ShieldAlert,
  Ticket, Settings, LogOut, Activity, MessageSquare, FileText,
} from "lucide-react";
import { useAuth } from "../hooks/useAuth";
import { authApi } from "../lib/api";
import { cn } from "../lib/utils";

const NAV_ITEMS = [
  { to: "/dashboard",    label: "Dashboard",     icon: LayoutDashboard },
  { to: "/repositories", label: "Repositories",  icon: GitBranch },
  { to: "/containers",   label: "Containers",    icon: Box },
  { to: "/domains",      label: "Domains",       icon: Globe },
  { to: "/scans",        label: "Scan History",  icon: Activity },
  { to: "/findings",     label: "Findings",      icon: ShieldAlert },
  { to: "/tickets",      label: "Tickets",       icon: Ticket },
  { to: "/chat",         label: "AI Chat",       icon: MessageSquare },
  { to: "/report",       label: "Security Report", icon: FileText },
  { to: "/settings",     label: "Settings",      icon: Settings },
];

/** BreachLens brand logo — optical lens aperture + security scope reticle */
function BreachLensLogo({ className = "" }: { className?: string }) {
  return (
    <svg
      viewBox="0 0 36 36"
      className={className}
      fill="none"
      xmlns="http://www.w3.org/2000/svg"
      aria-label="BreachLens logo"
    >
      <defs>
        {/* Subtle glow for the focal point */}
        <filter id="bl-glow" x="-50%" y="-50%" width="200%" height="200%">
          <feGaussianBlur stdDeviation="1.1" result="blur" />
          <feMerge>
            <feMergeNode in="blur" />
            <feMergeNode in="SourceGraphic" />
          </feMerge>
        </filter>
        {/* Glass-like radial gradient for lens body */}
        <radialGradient id="bl-glass" cx="38%" cy="32%" r="70%">
          <stop offset="0%" stopColor="#818cf8" stopOpacity="0.22" />
          <stop offset="100%" stopColor="#3730a3" stopOpacity="0.06" />
        </radialGradient>
      </defs>

      {/* ── Outer lens body ───────────────────────────────────────────────── */}
      <circle cx="18" cy="18" r="15.5" stroke="#6366f1" strokeWidth="1.4" fill="url(#bl-glass)" />

      {/* ── Aperture ring (iris mechanism boundary) ───────────────────────── */}
      <circle cx="18" cy="18" r="9.5" stroke="#4f46e5" strokeWidth="0.7" fill="none" opacity="0.55" />

      {/* ── 6 aperture blades — arcs on the iris ring at 60° spacing ─────── */}
      {/*   Each blade is ~40° wide; gaps fall at 0°,60°,120°,180°,240°,300°  */}
      {/*   Blade coords computed for r=9.5, center=(18,18)                    */}
      {/* Blade 1 — 10°→50° */}
      <path d="M 27.36 19.65 A 9.5 9.5 0 0 1 24.11 25.28" stroke="#818cf8" strokeWidth="2.1" strokeLinecap="round" opacity="0.65" />
      {/* Blade 2 — 70°→110° */}
      <path d="M 21.25 26.93 A 9.5 9.5 0 0 1 14.75 26.93" stroke="#818cf8" strokeWidth="2.1" strokeLinecap="round" opacity="0.65" />
      {/* Blade 3 — 130°→170° */}
      <path d="M 11.89 25.28 A 9.5 9.5 0 0 1  8.64 19.65" stroke="#818cf8" strokeWidth="2.1" strokeLinecap="round" opacity="0.65" />
      {/* Blade 4 — 190°→230° */}
      <path d="M  8.64 16.35 A 9.5 9.5 0 0 1 11.89 10.72" stroke="#818cf8" strokeWidth="2.1" strokeLinecap="round" opacity="0.65" />
      {/* Blade 5 — 250°→290° */}
      <path d="M 14.75  9.07 A 9.5 9.5 0 0 1 21.25  9.07" stroke="#818cf8" strokeWidth="2.1" strokeLinecap="round" opacity="0.65" />
      {/* Blade 6 — 310°→350° */}
      <path d="M 24.11 10.72 A 9.5 9.5 0 0 1 27.36 16.35" stroke="#818cf8" strokeWidth="2.1" strokeLinecap="round" opacity="0.65" />

      {/* ── Scope crosshair — 4 segments with center gap ─────────────────── */}
      <line x1="18" y1="3"    x2="18" y2="13.5" stroke="#6366f1" strokeWidth="1.1" strokeLinecap="round" opacity="0.8" />
      <line x1="18" y1="22.5" x2="18" y2="33"   stroke="#6366f1" strokeWidth="1.1" strokeLinecap="round" opacity="0.8" />
      <line x1="3"  y1="18"   x2="13.5" y2="18" stroke="#6366f1" strokeWidth="1.1" strokeLinecap="round" opacity="0.8" />
      <line x1="22.5" y1="18" x2="33"   y2="18" stroke="#6366f1" strokeWidth="1.1" strokeLinecap="round" opacity="0.8" />

      {/* ── Central focal point with glow ─────────────────────────────────── */}
      <g filter="url(#bl-glow)">
        <circle cx="18" cy="18" r="3.6" fill="#3730a3" stroke="#6366f1" strokeWidth="0.8" />
        <circle cx="18" cy="18" r="1.9" fill="#6366f1" />
      </g>
      {/* Lens glint highlight */}
      <circle cx="19.2" cy="16.8" r="0.75" fill="#c7d2fe" opacity="0.72" />
    </svg>
  );
}

export default function Layout() {
  const { user } = useAuth();
  const navigate = useNavigate();

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
          {NAV_ITEMS.map(({ to, label, icon: Icon }) => (
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
