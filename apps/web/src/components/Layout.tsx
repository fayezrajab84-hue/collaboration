import { useEffect, useMemo, useRef, useState } from "react";
import { NavLink, Outlet, useLocation, useNavigate } from "react-router-dom";
import {
  Gauge, FolderGit2, Container, Network, Bug,
  Workflow, Settings, LogOut, Radar, BrainCircuit, FileBarChart, Layers,
  Building2, ChevronsUpDown, Check, BookOpenCheck, GitGraph, Boxes,
  ChevronDown, ChevronRight, Activity, Package, Cloud,
} from "lucide-react";
import { useQueryClient } from "@tanstack/react-query";
import { useAuth } from "../hooks/useAuth";
import { authApi } from "../lib/api";
import { cn } from "../lib/utils";

// Top-level nav. The "Assets" group is rendered separately below — it gets
// its own collapsible chevron pattern so the sidebar stays scannable as the
// asset-type list grows (we picked up Runtime in Phase 28; future slices
// may add more).
type LinkItem = { to: string; label: string; icon: typeof Gauge };

// Order mirrors the operator's setup flow: define the Application boundary
// first, then walk down the deployment stack — Domain (the front door) →
// Container (what answers requests) → Repository (the source) → Cloud
// (CSPM, the underlying infra) → Runtime (live monitoring once
// everything is deployed).
const ASSET_ITEMS: LinkItem[] = [
  { to: "/applications",    label: "Applications",   icon: Boxes      },
  { to: "/domains",         label: "Domains",        icon: Network    },
  { to: "/containers",      label: "Containers",     icon: Container  },
  { to: "/repositories",    label: "Repositories",   icon: FolderGit2 },
  { to: "/cloud-accounts",  label: "Cloud",          icon: Cloud      },
  { to: "/runtime",         label: "Runtime",        icon: Activity   },
];

const NAV_ITEMS_TOP: LinkItem[] = [
  { to: "/dashboard",    label: "Dashboard",     icon: Gauge      },
];

const NAV_ITEMS_BOTTOM: LinkItem[] = [
  { to: "/scans",        label: "Scans",         icon: Radar         },
  { to: "/findings",     label: "Findings",      icon: Bug           },
  { to: "/attack-paths", label: "Attack Paths",  icon: GitGraph      },
  { to: "/tickets",      label: "Tickets",       icon: Workflow      },
  { to: "/chat",         label: "AI Chat",       icon: BrainCircuit  },
  { to: "/report",       label: "Security Report", icon: FileBarChart },
  { to: "/compliance",   label: "Compliance",    icon: BookOpenCheck },
  { to: "/settings",     label: "Settings",      icon: Settings      },
];

// Persist the Assets-expander state across navigations. Without this,
// the group collapses every time the user clicks one of its children
// because the sidebar component doesn't unmount but the local state
// often gets reset on hot reloads / login state changes.
const ASSETS_EXPANDED_KEY = "breachlens.sidebar.assets-expanded";

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

/**
 * OrgSwitcher — shows the active org in the sidebar; opens a dropdown of
 * all the user's memberships when they have more than one. Switching
 * persists to `session.activeOrgId` server-side, then we invalidate every
 * query because every list is org-scoped (findings, scans, repos, etc).
 *
 * Hidden entirely when the user has exactly one org — that's the common
 * single-tenant case and an unclickable "switcher" reads as broken.
 */
function OrgSwitcher({
  orgs,
  activeOrgId,
}: {
  orgs: NonNullable<ReturnType<typeof useAuth>["user"]>["orgs"];
  activeOrgId: string | null;
}) {
  const [open, setOpen] = useState(false);
  const ref = useRef<HTMLDivElement>(null);
  const queryClient = useQueryClient();

  useEffect(() => {
    if (!open) return;
    function handler(e: MouseEvent) {
      if (ref.current && !ref.current.contains(e.target as Node)) setOpen(false);
    }
    document.addEventListener("mousedown", handler);
    return () => document.removeEventListener("mousedown", handler);
  }, [open]);

  const active = orgs.find((o) => o.id === activeOrgId) ?? orgs[0];
  if (!active) return null;
  if (orgs.length < 2) {
    // Single-org case — just label, no dropdown affordance.
    return (
      <div className="flex items-center gap-2 px-3 py-2 text-xs text-gray-400">
        <Building2 className="h-3.5 w-3.5 flex-shrink-0 text-indigo-400" />
        <span className="truncate">{active.name}</span>
      </div>
    );
  }

  async function handleSwitch(orgId: string) {
    setOpen(false);
    if (orgId === activeOrgId) return;
    await authApi.switchOrg(orgId);
    // Every org-scoped list (findings, scans, repos, etc) needs to refetch
    // with the new active org. Easiest correct option: blow the entire
    // cache rather than try to enumerate which queryKeys touch org data.
    await queryClient.invalidateQueries();
  }

  return (
    <div ref={ref} className="relative">
      <button
        type="button"
        onClick={() => setOpen((v) => !v)}
        className="flex w-full items-center gap-2 rounded-lg px-3 py-2 text-left transition-colors hover:bg-gray-800"
      >
        <Building2 className="h-3.5 w-3.5 flex-shrink-0 text-indigo-400" />
        <span className="flex-1 truncate text-xs font-medium text-gray-200">
          {active.name}
        </span>
        <ChevronsUpDown className="h-3.5 w-3.5 flex-shrink-0 text-gray-500" />
      </button>
      {open && (
        <div className="absolute bottom-full left-0 right-0 mb-1 overflow-hidden rounded-lg border border-indigo-900/40 bg-gray-900 shadow-xl shadow-black/50">
          <div className="px-3 py-2 text-[10px] font-semibold uppercase tracking-wider text-gray-500">
            Switch organization
          </div>
          {orgs.map((o) => {
            const isActive = o.id === activeOrgId;
            return (
              <button
                key={o.id}
                type="button"
                onClick={() => handleSwitch(o.id)}
                className={cn(
                  "flex w-full items-center gap-2 px-3 py-2 text-left text-xs transition-colors",
                  isActive
                    ? "bg-indigo-950/40 text-indigo-200"
                    : "text-gray-300 hover:bg-gray-800",
                )}
              >
                <span className="flex-1 truncate">
                  <span className="font-medium">{o.name}</span>
                  <span className="ml-2 text-[10px] uppercase tracking-wide text-gray-500">
                    {o.role}
                  </span>
                </span>
                {isActive && <Check className="h-3.5 w-3.5 flex-shrink-0 text-indigo-400" />}
              </button>
            );
          })}
        </div>
      )}
    </div>
  );
}

function NavLinkRow({ to, label, icon: Icon }: LinkItem) {
  return (
    <NavLink
      to={to}
      className={({ isActive }) =>
        cn(
          "flex items-center gap-3 px-5 py-3 text-[15px] font-medium transition-colors",
          isActive
            ? "bg-indigo-900/50 text-indigo-300 border-r-2 border-indigo-500"
            : "text-gray-400 hover:bg-gray-800 hover:text-gray-100",
        )
      }
    >
      <Icon className="h-[18px] w-[18px] flex-shrink-0" />
      {label}
    </NavLink>
  );
}

/**
 * AssetsGroup — collapsible sidebar section grouping the four asset types
 * (Applications, Repositories, Containers, Domains, Runtime). Auto-opens
 * when any child is the current route so the active item is always
 * visible; otherwise honours the persisted preference.
 */
function AssetsGroup() {
  const location = useLocation();
  const isAssetActive = useMemo(
    () => ASSET_ITEMS.some((item) => location.pathname.startsWith(item.to)),
    [location.pathname],
  );

  const [open, setOpen] = useState<boolean>(() => {
    if (typeof window === "undefined") return true;
    const stored = window.localStorage.getItem(ASSETS_EXPANDED_KEY);
    if (stored === "0") return false;
    return true;
  });

  // Auto-open when a child becomes active (e.g. user clicks an attack path
  // that deep-links into /containers/...). Don't *close* on inactive — we
  // respect the user's last toggle for the "viewed once, collapsed" case.
  useEffect(() => {
    if (isAssetActive) setOpen(true);
  }, [isAssetActive]);

  function toggle() {
    setOpen((prev) => {
      const next = !prev;
      try { window.localStorage.setItem(ASSETS_EXPANDED_KEY, next ? "1" : "0"); } catch { /* localStorage may be blocked */ }
      return next;
    });
  }

  return (
    <div>
      <button
        type="button"
        onClick={toggle}
        aria-expanded={open}
        className={cn(
          "flex w-full items-center gap-3 px-5 py-3 text-[15px] font-medium transition-colors",
          isAssetActive
            ? "text-indigo-300"
            : "text-gray-400 hover:bg-gray-800 hover:text-gray-100",
        )}
      >
        <Package className="h-[18px] w-[18px] flex-shrink-0" />
        <span className="flex-1 text-left">Assets</span>
        {open
          ? <ChevronDown className="h-4 w-4 flex-shrink-0 text-gray-500" />
          : <ChevronRight className="h-4 w-4 flex-shrink-0 text-gray-500" />
        }
      </button>
      {open && (
        <div className="bg-gray-950/40">
          {ASSET_ITEMS.map((item) => (
            <NavLink
              key={item.to}
              to={item.to}
              className={({ isActive }) =>
                cn(
                  "flex items-center gap-3 py-2.5 pl-12 pr-5 text-sm transition-colors",
                  isActive
                    ? "bg-indigo-900/50 text-indigo-300 border-r-2 border-indigo-500"
                    : "text-gray-400 hover:bg-gray-800 hover:text-gray-100",
                )
              }
            >
              <item.icon className="h-[15px] w-[15px] flex-shrink-0" />
              {item.label}
            </NavLink>
          ))}
        </div>
      )}
    </div>
  );
}

export default function Layout() {
  const { user } = useAuth();
  const navigate = useNavigate();

  // Show admin-only nav items when any org membership has OWNER/ADMIN role.
  const isAdmin = !!user?.orgs?.some((o) => ADMIN_ROLES.has(o.role));
  const bottomItems: LinkItem[] = isAdmin
    ? [...NAV_ITEMS_BOTTOM, { to: "/admin/queues", label: "Queues", icon: Layers }]
    : NAV_ITEMS_BOTTOM;

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
          {NAV_ITEMS_TOP.map((item) => <NavLinkRow key={item.to} {...item} />)}
          <AssetsGroup />
          {bottomItems.map((item) => <NavLinkRow key={item.to} {...item} />)}
        </nav>

        {/* Org switcher — single label for solo-org users, dropdown for 2+ */}
        {user?.orgs && user.orgs.length > 0 && (
          <div className="border-t border-gray-800 px-3 pt-3">
            <OrgSwitcher orgs={user.orgs} activeOrgId={user.activeOrgId} />
          </div>
        )}

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
