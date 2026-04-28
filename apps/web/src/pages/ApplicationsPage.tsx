/**
 * /applications — Phase 27.5 Application boundary list + detail.
 *
 * List view: every Application in the org with component counts +
 * severity rollup. Click any row to open the detail page for membership
 * management.
 *
 * Detail view: metadata header + three Components tabs (Repositories /
 * Containers / Domains). Each tab shows current members with quick remove,
 * and an "Add" modal that lists every UNASSIGNED asset of that kind in the
 * org with checkboxes.
 *
 * Honest UI:
 *  - Empty state explains "what is an Application" + the procurement-aligned
 *    reason to create one (correlation only fires within an app boundary)
 *  - Component-add modal calls out that an asset can only belong to ONE app
 *    at a time (assigning here un-assigns from any prior app)
 *  - Criticality + environment carry distinct visual axes; no overlap
 */
import { useState } from "react";
import { Link, useParams, useNavigate } from "react-router-dom";
import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import FindingCountBadges from "../components/FindingCountBadges";
import {
  Plus, Pencil, Trash2, X, Boxes, GitBranch, Container as ContainerIcon, Network, Layers,
  AlertTriangle, ChevronRight, Activity, AlertCircle, Link2, Link2Off,
} from "lucide-react";
import {
  applicationsApi, reposApi, containersApi, domainsApi, runtimeApi,
  type ApplicationDetail,
} from "../lib/api";
import { formatRelative } from "../lib/utils";
import type { WorkloadAgent, AgentStatus } from "@devsecops/types";
import Can from "../components/Can";
import { useToast } from "../hooks/useToast";
import type { Application, ApplicationEnv, Criticality } from "@devsecops/types";

const ENV_LABELS: Record<ApplicationEnv, string> = {
  DEVELOPMENT: "Dev",
  STAGING:     "Staging",
  PRODUCTION:  "Prod",
};

const ENV_COLORS: Record<ApplicationEnv, string> = {
  DEVELOPMENT: "border-gray-700 bg-gray-800/50 text-gray-300",
  STAGING:     "border-amber-800 bg-amber-950/30 text-amber-300",
  PRODUCTION:  "border-emerald-800 bg-emerald-950/30 text-emerald-300",
};

const CRIT_COLORS: Record<Criticality, string> = {
  CRITICAL: "border-red-800 bg-red-950/30 text-red-300",
  HIGH:     "border-orange-800 bg-orange-950/30 text-orange-300",
  MEDIUM:   "border-indigo-800 bg-indigo-950/30 text-indigo-300",
  LOW:      "border-gray-700 bg-gray-800/50 text-gray-400",
};

// ── Top-level routing ─────────────────────────────────────────────────────

export default function ApplicationsPage() {
  const params = useParams<{ id?: string }>();
  if (params.id) return <ApplicationDetailView applicationId={params.id} />;
  return <ApplicationsList />;
}

// ── List view ─────────────────────────────────────────────────────────────

function ApplicationsList() {
  const { data: apps, isLoading } = useQuery({
    queryKey: ["applications"],
    queryFn:  applicationsApi.list,
  });
  const [showCreate, setShowCreate] = useState(false);

  return (
    <div className="p-6">
      <div className="mb-4 flex items-center justify-between">
        <div className="flex items-center gap-3">
          <Layers className="h-6 w-6 text-indigo-400" />
          <h1 className="text-3xl font-bold text-white">Applications</h1>
        </div>
        <Can role="ADMIN">
          <button
            onClick={() => setShowCreate(true)}
            className="flex items-center gap-2 rounded-lg bg-indigo-700 px-4 py-2 text-sm font-medium text-white hover:bg-indigo-600"
          >
            <Plus className="h-4 w-4" /> Create Application
          </button>
        </Can>
      </div>
      <p className="mb-6 text-sm text-gray-500">
        Group related repositories, containers, and domains into a single Application.
        The correlation engine scopes attack-path chains to one Application at a time —
        unrelated apps that happen to share a base-image CVE no longer collapse into one
        misleading mega-chain.
      </p>

      {isLoading ? (
        <div className="text-gray-500">Loading…</div>
      ) : (apps ?? []).length === 0 ? (
        <EmptyState onCreate={() => setShowCreate(true)} />
      ) : (
        <div className="overflow-hidden rounded-lg border border-gray-800">
          <table className="w-full text-sm">
            <thead className="border-b border-gray-800 bg-gray-900">
              <tr className="text-left text-xs text-gray-500">
                <th className="px-4 py-3 font-medium">Name</th>
                <th className="px-4 py-3 font-medium">Environment</th>
                <th className="px-4 py-3 font-medium">Criticality</th>
                <th className="px-4 py-3 font-medium">Components</th>
                <th className="px-4 py-3 font-medium">Open findings</th>
                <th className="px-4 py-3 font-medium">Owner</th>
                <th className="px-4 py-3 font-medium" />
              </tr>
            </thead>
            <tbody className="divide-y divide-gray-800 bg-gray-900/50">
              {apps!.map((a) => <AppRow key={a.id} app={a} />)}
            </tbody>
          </table>
        </div>
      )}

      {showCreate && <CreateOrEditModal onClose={() => setShowCreate(false)} />}
    </div>
  );
}

function AppRow({ app }: { app: Application }) {
  const total = (app.componentCounts?.repositories ?? 0)
              + (app.componentCounts?.containers ?? 0)
              + (app.componentCounts?.domains ?? 0);
  return (
    <tr className="hover:bg-gray-800/40">
      <td className="px-4 py-3">
        <Link to={`/applications/${app.id}`} className="font-medium text-white hover:text-indigo-300">
          {app.name}
        </Link>
        <div className="text-xs text-gray-500 font-mono">{app.slug}</div>
      </td>
      <td className="px-4 py-3">
        <Pill className={ENV_COLORS[app.environment]}>{ENV_LABELS[app.environment]}</Pill>
      </td>
      <td className="px-4 py-3">
        <Pill className={CRIT_COLORS[app.criticality]}>{app.criticality}</Pill>
      </td>
      <td className="px-4 py-3 text-gray-300">
        {total === 0 ? <span className="text-gray-600">none yet</span> : (
          <span title={`${app.componentCounts?.repositories ?? 0} repos · ${app.componentCounts?.containers ?? 0} containers · ${app.componentCounts?.domains ?? 0} domains`}>
            {total} {total === 1 ? "asset" : "assets"}
          </span>
        )}
      </td>
      <td className="px-4 py-3">
        {/*
          UX pattern #5 — one axis per colour channel. Previously rendered
          severity counts as raw `text-red-400 / text-orange-400` inline
          spans, which competed with the SEVERITY_PILL standard everywhere
          else (DashboardPage, FindingsPage). Replaced with the canonical
          FindingCountBadges component so all 4 severities show up as
          consistent muted-background pills with severity-tinted text.
        */}
        <FindingCountBadges counts={app.findingCounts} />
      </td>
      <td className="px-4 py-3 text-xs text-gray-500">{app.owner ?? "—"}</td>
      <td className="px-4 py-3 text-right">
        <Link to={`/applications/${app.id}`} className="inline-flex items-center text-gray-500 hover:text-indigo-400">
          <ChevronRight className="h-4 w-4" />
        </Link>
      </td>
    </tr>
  );
}

function Pill({ className, children }: { className: string; children: React.ReactNode }) {
  return <span className={`inline-flex items-center rounded-full border px-2 py-0.5 text-[10px] font-medium ${className}`}>{children}</span>;
}

function EmptyState({ onCreate }: { onCreate: () => void }) {
  return (
    <div className="rounded-xl border border-gray-800 bg-gray-900/40 p-8 text-center">
      <Boxes className="mx-auto mb-3 h-8 w-8 text-indigo-500" />
      <h3 className="text-base font-semibold text-white">No applications yet</h3>
      <p className="mx-auto mt-2 max-w-md text-sm text-gray-500">
        An Application is a logical group of related assets — typically one product or service
        that consists of source code (repos), runtime artifacts (containers), and public surfaces
        (domains).
      </p>
      <p className="mx-auto mt-2 max-w-md text-sm text-gray-500">
        Without an Application, BreachLens can scan your assets but won't correlate findings
        across them into attack chains. Create your first Application below to enable correlation.
      </p>
      <Can role="ADMIN" fallback={
        <p className="mt-4 text-xs text-gray-600">Ask an admin to create the first Application for your org.</p>
      }>
        <button
          onClick={onCreate}
          className="mt-5 inline-flex items-center gap-2 rounded-lg bg-indigo-700 px-4 py-2 text-sm font-medium text-white hover:bg-indigo-600"
        >
          <Plus className="h-4 w-4" /> Create your first Application
        </button>
      </Can>
    </div>
  );
}

// ── Create / Edit modal ──────────────────────────────────────────────────

function CreateOrEditModal({ existing, onClose }: { existing?: Application; onClose: () => void }) {
  const qc = useQueryClient();
  const { toast } = useToast();
  const navigate = useNavigate();
  const [name, setName]       = useState(existing?.name ?? "");
  const [env, setEnv]         = useState<ApplicationEnv>(existing?.environment ?? "PRODUCTION");
  const [crit, setCrit]       = useState<Criticality>(existing?.criticality ?? "MEDIUM");
  const [owner, setOwner]     = useState(existing?.owner ?? "");
  const [desc, setDesc]       = useState(existing?.description ?? "");

  const save = useMutation({
    mutationFn: () => existing
      ? applicationsApi.update(existing.id, {
          name, environment: env, criticality: crit,
          owner: owner.trim() || null,
          description: desc.trim() || null,
        })
      : applicationsApi.create({
          name, environment: env, criticality: crit,
          owner: owner.trim() || undefined,
          description: desc.trim() || undefined,
        }),
    onSuccess: (app) => {
      qc.invalidateQueries({ queryKey: ["applications"] });
      qc.invalidateQueries({ queryKey: ["application", app.id] });
      toast.success(existing ? "Application updated" : "Application created");
      if (existing) onClose();
      else navigate(`/applications/${app.id}`);
    },
    onError: (err: Error) => toast.error(err.message || "Failed to save"),
  });

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/60">
      <div className="w-full max-w-lg rounded-xl border border-gray-700 bg-gray-900 p-6 shadow-2xl">
        <div className="mb-4 flex items-center justify-between">
          <h2 className="text-base font-semibold text-white">
            {existing ? "Edit Application" : "Create Application"}
          </h2>
          <button onClick={onClose} className="text-gray-500 hover:text-gray-200"><X className="h-4 w-4" /></button>
        </div>
        <div className="space-y-3">
          <Field label="Name (required)">
            <input
              className="w-full rounded bg-gray-800 px-3 py-2 text-sm text-gray-200 placeholder-gray-500 focus:outline-none focus:ring-1 focus:ring-indigo-500"
              value={name}
              onChange={(e) => setName(e.target.value)}
              placeholder="e.g. ACME Customer Portal"
              autoFocus
            />
          </Field>
          <div className="grid grid-cols-2 gap-3">
            <Field label="Environment">
              <select
                className="w-full rounded bg-gray-800 px-3 py-2 text-sm text-gray-200 focus:outline-none focus:ring-1 focus:ring-indigo-500"
                value={env}
                onChange={(e) => setEnv(e.target.value as ApplicationEnv)}
              >
                <option value="DEVELOPMENT">Development</option>
                <option value="STAGING">Staging</option>
                <option value="PRODUCTION">Production</option>
              </select>
            </Field>
            <Field label="Criticality">
              <select
                className="w-full rounded bg-gray-800 px-3 py-2 text-sm text-gray-200 focus:outline-none focus:ring-1 focus:ring-indigo-500"
                value={crit}
                onChange={(e) => setCrit(e.target.value as Criticality)}
              >
                <option value="CRITICAL">Critical</option>
                <option value="HIGH">High</option>
                <option value="MEDIUM">Medium</option>
                <option value="LOW">Low</option>
              </select>
            </Field>
          </div>
          <Field label="Owner (optional — team / contact / channel)">
            <input
              className="w-full rounded bg-gray-800 px-3 py-2 text-sm text-gray-200 placeholder-gray-500 focus:outline-none focus:ring-1 focus:ring-indigo-500"
              value={owner}
              onChange={(e) => setOwner(e.target.value)}
              placeholder="security-team@acme.com or #app-portal"
            />
          </Field>
          <Field label="Description (optional)">
            <textarea
              className="w-full rounded bg-gray-800 px-3 py-2 text-sm text-gray-200 placeholder-gray-500 focus:outline-none focus:ring-1 focus:ring-indigo-500"
              rows={3}
              value={desc}
              onChange={(e) => setDesc(e.target.value)}
            />
          </Field>
        </div>
        <div className="mt-4 flex justify-end gap-2">
          <button onClick={onClose} className="rounded px-3 py-1.5 text-sm text-gray-400 hover:text-gray-200">Cancel</button>
          <button
            onClick={() => save.mutate()}
            disabled={!name.trim() || save.isPending}
            className="rounded bg-indigo-700 px-4 py-1.5 text-sm font-medium text-white hover:bg-indigo-600 disabled:opacity-50"
          >
            {save.isPending ? "Saving…" : existing ? "Save changes" : "Create"}
          </button>
        </div>
      </div>
    </div>
  );
}

function Field({ label, children }: { label: string; children: React.ReactNode }) {
  return (
    <div>
      <label className="mb-1 block text-xs font-medium text-gray-400">{label}</label>
      {children}
    </div>
  );
}

// ── Detail view ───────────────────────────────────────────────────────────

function ApplicationDetailView({ applicationId }: { applicationId: string }) {
  const qc = useQueryClient();
  const { toast } = useToast();
  const navigate = useNavigate();
  const [showEdit, setShowEdit] = useState(false);
  const [tab, setTab] = useState<"repositories" | "containers" | "domains" | "runtime">("repositories");

  const { data, isLoading, error } = useQuery({
    queryKey: ["application", applicationId],
    queryFn:  () => applicationsApi.get(applicationId),
  });

  // Runtime agents are linked to Containers (not directly to Applications),
  // so the "Runtime" tab is the SET of agents whose linkedContainerId
  // belongs to one of this application's containers. Pull all agents and
  // filter client-side — the org typically has 1-50 agents, well below
  // any concern about wire size.
  const { data: allAgents } = useQuery({
    queryKey: ["runtime-agents"],
    queryFn:  runtimeApi.list,
    refetchInterval: 30_000,
  });
  const containerIdSet = new Set((data?.components.containers ?? []).map((c) => c.id));
  const appAgents = (allAgents ?? []).filter(
    (a) => a.linkedContainerId !== null && containerIdSet.has(a.linkedContainerId),
  );

  const remove = useMutation({
    mutationFn: () => applicationsApi.remove(applicationId),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ["applications"] });
      toast.success("Application deleted; assets stay in the org un-assigned");
      navigate("/applications");
    },
    onError: (err: Error) => toast.error(err.message || "Failed to delete"),
  });

  if (isLoading) return <div className="p-6 text-gray-500">Loading…</div>;
  if (error || !data) {
    return (
      <div className="p-6">
        <Link to="/applications" className="text-sm text-gray-500 hover:text-gray-300">← All applications</Link>
        <p className="mt-3 text-base text-gray-300">Application not found.</p>
      </div>
    );
  }

  return (
    <div className="p-6">
      <Link to="/applications" className="mb-3 inline-block text-sm text-gray-500 hover:text-gray-300">
        ← All applications
      </Link>

      <div className="mb-5 flex items-start justify-between gap-4">
        <div>
          <div className="flex items-center gap-3">
            <h1 className="text-2xl font-bold text-white">{data.name}</h1>
            <Pill className={ENV_COLORS[data.environment]}>{ENV_LABELS[data.environment]}</Pill>
            <Pill className={CRIT_COLORS[data.criticality]}>{data.criticality}</Pill>
          </div>
          <p className="mt-1 font-mono text-xs text-gray-500">{data.slug}</p>
          {data.owner && <p className="mt-2 text-xs text-gray-500">Owner: {data.owner}</p>}
          {data.description && <p className="mt-2 text-sm text-gray-400 max-w-2xl">{data.description}</p>}
        </div>
        <Can role="ADMIN">
          <div className="flex items-center gap-2">
            <button
              onClick={() => setShowEdit(true)}
              className="inline-flex items-center gap-1 rounded border border-gray-700 bg-gray-800 px-3 py-1.5 text-xs text-gray-300 hover:bg-gray-700"
            >
              <Pencil className="h-3 w-3" /> Edit
            </button>
            <button
              onClick={() => {
                if (confirm(`Delete "${data.name}"? Assets stay; their applicationId is cleared.`)) remove.mutate();
              }}
              className="inline-flex items-center gap-1 rounded border border-red-800 bg-red-950/30 px-3 py-1.5 text-xs text-red-400 hover:bg-red-900/40"
            >
              <Trash2 className="h-3 w-3" /> Delete
            </button>
          </div>
        </Can>
      </div>

      {/* Component tabs */}
      <div className="mb-4 flex gap-1 border-b border-gray-800">
        <TabButton active={tab === "repositories"} onClick={() => setTab("repositories")}
          icon={GitBranch} label="Repositories" count={data.components.repositories.length} />
        <TabButton active={tab === "containers"} onClick={() => setTab("containers")}
          icon={ContainerIcon} label="Containers" count={data.components.containers.length} />
        <TabButton active={tab === "domains"} onClick={() => setTab("domains")}
          icon={Network} label="Domains" count={data.components.domains.length} />
        <TabButton active={tab === "runtime"} onClick={() => setTab("runtime")}
          icon={Activity} label="Runtime" count={appAgents.length} />
      </div>

      {tab === "runtime"
        ? <RuntimeTab agents={appAgents} containers={data.components.containers} />
        : <ComponentsTab kind={tab} application={data} />
      }

      {showEdit && <CreateOrEditModal existing={data} onClose={() => setShowEdit(false)} />}
    </div>
  );
}

// ── Runtime tab ──────────────────────────────────────────────────────────
//
// Agents linked to any container in this application, derived client-side
// from runtimeApi.list() ∩ application.components.containers. Read-only
// here — operator manages the actual link from /runtime, not from inside
// an Application.

function AgentStatusDot({ status }: { status: AgentStatus }) {
  const cls =
    status === "HEALTHY" ? "bg-emerald-400"
    : status === "STALE" ? "bg-amber-400"
    : status === "OFFLINE" ? "bg-red-400"
    : "bg-gray-500";
  return <span className={`inline-block h-1.5 w-1.5 rounded-full ${cls}`} />;
}

function RuntimeTab({ agents, containers }: {
  agents:     WorkloadAgent[];
  containers: ApplicationDetail["components"]["containers"];
}) {
  const containerImageRef = new Map(containers.map((c) => [c.id, c.imageRef]));

  if (containers.length === 0) {
    return (
      <div className="rounded-lg border border-gray-800 bg-gray-900/40 p-6 text-center text-sm text-gray-500">
        Add a container to this application before linking runtime agents.
      </div>
    );
  }
  if (agents.length === 0) {
    return (
      <div className="space-y-3">
        <p className="text-sm text-gray-500">
          No runtime agents are monitoring this application's containers yet.
        </p>
        <div className="rounded-lg border border-gray-800 bg-gray-900/40 p-6 text-sm text-gray-400">
          <p className="mb-2 flex items-center gap-2 text-gray-300">
            <AlertCircle className="h-4 w-4 text-amber-400" />
            <span>Runtime agents are linked through containers, not directly.</span>
          </p>
          <p className="mb-3 text-xs text-gray-500">
            Install Wazuh on the host running one of this application's
            {containers.length === 1 ? " container" : ` ${containers.length} containers`},
            then go to <Link to="/runtime" className="text-indigo-400 hover:text-indigo-300">Runtime</Link>{" "}
            and link the agent to the container.
          </p>
          <ul className="space-y-1 font-mono text-xs text-gray-300">
            {containers.map((c) => (
              <li key={c.id} className="flex items-center gap-2">
                <ContainerIcon className="h-3 w-3 text-gray-500" />
                {c.imageRef}
              </li>
            ))}
          </ul>
        </div>
      </div>
    );
  }

  return (
    <div>
      <p className="mb-3 text-sm text-gray-500">
        {agents.length} runtime agent{agents.length === 1 ? "" : "s"} linked to this
        application's containers. Findings from these agents flow into the correlation
        engine via the runtimeBridge.
      </p>
      <div className="overflow-hidden rounded-lg border border-gray-800">
        <table className="w-full text-sm">
          <thead className="border-b border-gray-800 bg-gray-900">
            <tr className="text-left text-xs text-gray-500">
              <th className="px-4 py-2.5 font-medium">Agent</th>
              <th className="px-4 py-2.5 font-medium">Status</th>
              <th className="px-4 py-2.5 font-medium">Container</th>
              <th className="px-4 py-2.5 font-medium">Findings</th>
              <th className="px-4 py-2.5 font-medium">Last Alert</th>
            </tr>
          </thead>
          <tbody className="divide-y divide-gray-800 bg-gray-900/40">
            {agents.map((a) => (
              <tr key={a.id} className="hover:bg-gray-800/40">
                <td className="px-4 py-2.5">
                  <div className="font-medium text-gray-200">{a.wazuhAgentName}</div>
                  <div className="font-mono text-[10px] text-gray-500">
                    ID {a.wazuhAgentId}
                    {a.agentVersion && <span className="ml-2">v{a.agentVersion}</span>}
                  </div>
                </td>
                <td className="px-4 py-2.5">
                  <span className="inline-flex items-center gap-1.5 text-xs text-gray-300">
                    <AgentStatusDot status={a.status} />
                    {a.status}
                  </span>
                </td>
                <td className="px-4 py-2.5 font-mono text-xs text-gray-300">
                  {a.linkedContainerId
                    ? containerImageRef.get(a.linkedContainerId) ?? a.linkedContainerImageRef ?? "—"
                    : <span className="italic text-gray-600">unlinked</span>
                  }
                </td>
                <td className="px-4 py-2.5 text-gray-300">{a.runtimeFindingCount ?? 0}</td>
                <td className="px-4 py-2.5 text-xs text-gray-400">
                  {a.lastAlertAt ? formatRelative(a.lastAlertAt) : "Never"}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
      <p className="mt-3 text-xs text-gray-600">
        Manage agent ↔ container links from the{" "}
        <Link to="/runtime" className="text-indigo-400 hover:text-indigo-300">Runtime</Link> page.
      </p>
    </div>
  );
}

function TabButton({ active, onClick, icon: Icon, label, count }: {
  active: boolean; onClick: () => void; icon: React.ComponentType<{ className?: string }>;
  label: string; count: number;
}) {
  return (
    <button
      onClick={onClick}
      className={`flex items-center gap-2 px-4 py-2 text-sm font-medium transition-colors border-b-2 -mb-px ${
        active ? "border-indigo-500 text-white" : "border-transparent text-gray-500 hover:text-gray-300"
      }`}
    >
      <Icon className="h-4 w-4" />
      {label}
      <span className="rounded bg-gray-800 px-1.5 py-0.5 text-[10px] text-gray-400">{count}</span>
    </button>
  );
}

// ── Components tab ────────────────────────────────────────────────────────

type ComponentKind = "repositories" | "containers" | "domains";

function ComponentsTab({ kind, application }: { kind: ComponentKind; application: ApplicationDetail }) {
  const [showAdd, setShowAdd] = useState(false);
  const items = application.components[kind];
  const labelMap = { repositories: "Repository", containers: "Container", domains: "Domain" };

  return (
    <div>
      <div className="mb-3 flex items-center justify-between">
        <p className="text-sm text-gray-500">
          {items.length === 0
            ? `No ${kind} assigned yet — findings on unassigned ${kind} won't be correlated into chains.`
            : `${items.length} ${labelMap[kind]}${items.length === 1 ? "" : "s"} assigned to this application.`}
        </p>
        <Can role="ADMIN">
          <button
            onClick={() => setShowAdd(true)}
            className="inline-flex items-center gap-1 rounded bg-indigo-700 px-3 py-1.5 text-xs font-medium text-white hover:bg-indigo-600"
          >
            <Plus className="h-3 w-3" /> Add {labelMap[kind]}
          </button>
        </Can>
      </div>

      {items.length === 0 ? (
        <div className="rounded-lg border border-gray-800 bg-gray-900/40 p-6 text-center text-sm text-gray-500">
          No {kind} assigned to this application.
        </div>
      ) : (
        <ul className="space-y-1">
          {items.map((item) => {
            const label = "fullName" in item ? item.fullName
                        : "imageRef" in item ? item.imageRef
                        : item.domain;
            return (
              <li key={item.id} className="flex items-center justify-between rounded border border-gray-800 bg-gray-900/40 px-4 py-2 text-sm">
                <span className="font-mono text-gray-200">{label}</span>
                <Can role="ADMIN">
                  <RemoveComponentButton applicationId={application.id} kind={kind} item={item} application={application} />
                </Can>
              </li>
            );
          })}
        </ul>
      )}

      {showAdd && (
        <AddComponentsModal
          applicationId={application.id}
          kind={kind}
          existingIds={items.map((i) => i.id)}
          onClose={() => setShowAdd(false)}
        />
      )}
    </div>
  );
}

function RemoveComponentButton({ applicationId, kind, item, application }: {
  applicationId: string; kind: ComponentKind; item: { id: string };
  application: ApplicationDetail;
}) {
  const qc = useQueryClient();
  const { toast } = useToast();
  const remove = useMutation({
    mutationFn: () => {
      const allIds = (application.components[kind] as Array<{ id: string }>).map((i) => i.id);
      const next = allIds.filter((id) => id !== item.id);
      const payload = kind === "repositories" ? { repositoryIds: next }
                     : kind === "containers" ? { containerIds:  next }
                     :                          { domainIds:     next };
      return applicationsApi.assignComponents(applicationId, payload);
    },
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ["application", applicationId] });
      qc.invalidateQueries({ queryKey: ["applications"] });
      toast.success("Removed from application");
    },
    onError: (err: Error) => toast.error(err.message || "Failed to remove"),
  });
  return (
    <button
      onClick={() => remove.mutate()}
      disabled={remove.isPending}
      className="rounded p-1 text-gray-600 hover:text-red-400 disabled:opacity-50"
      title="Remove from application"
    >
      <X className="h-3.5 w-3.5" />
    </button>
  );
}

function AddComponentsModal({ applicationId, kind, existingIds, onClose }: {
  applicationId: string;
  kind: ComponentKind;
  existingIds: string[];
  onClose: () => void;
}) {
  const qc = useQueryClient();
  const { toast } = useToast();
  const [selected, setSelected] = useState<string[]>([]);

  const { data: candidates, isLoading } = useQuery({
    queryKey: ["candidates", kind],
    queryFn:  () => kind === "repositories" ? reposApi.list().then((rs) => rs.map((r) => ({ id: r.id, label: r.fullName, applicationId: r.applicationId })))
                  : kind === "containers"  ? containersApi.list().then((cs) => cs.map((c) => ({ id: c.id, label: c.imageRef, applicationId: c.applicationId })))
                  :                          domainsApi.list().then((ds) => ds.map((d) => ({ id: d.id, label: d.domain, applicationId: d.applicationId }))),
  });

  const submit = useMutation({
    mutationFn: () => {
      const payload = kind === "repositories" ? { repositoryIds: [...existingIds, ...selected] }
                     : kind === "containers" ? { containerIds:  [...existingIds, ...selected] }
                     :                          { domainIds:     [...existingIds, ...selected] };
      return applicationsApi.assignComponents(applicationId, payload);
    },
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ["application", applicationId] });
      qc.invalidateQueries({ queryKey: ["applications"] });
      qc.invalidateQueries({ queryKey: [kind] });
      toast.success(`Added ${selected.length} ${kind} to this application`);
      onClose();
    },
    onError: (err: Error) => toast.error(err.message || "Failed to assign"),
  });

  const eligible = (candidates ?? []).filter((c) => !existingIds.includes(c.id));
  const labelMap = { repositories: "Repositories", containers: "Containers", domains: "Domains" };

  const toggle = (id: string) =>
    setSelected((prev) => prev.includes(id) ? prev.filter((x) => x !== id) : [...prev, id]);

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/60">
      <div className="max-h-[80vh] w-full max-w-lg overflow-y-auto rounded-xl border border-gray-700 bg-gray-900 p-6 shadow-2xl">
        <div className="mb-4 flex items-center justify-between">
          <h2 className="text-base font-semibold text-white">Add {labelMap[kind]}</h2>
          <button onClick={onClose} className="text-gray-500 hover:text-gray-200"><X className="h-4 w-4" /></button>
        </div>
        <p className="mb-3 text-xs text-gray-500">
          Select assets to add to this application. An asset can only belong to one application
          at a time — assigning here will move it from any prior application.
        </p>
        <div className="mb-2 flex items-center gap-2 text-[11px] text-amber-400">
          <AlertTriangle className="h-3 w-3" /> Already-assigned assets are flagged in the list.
        </div>

        {isLoading ? <div className="text-xs text-gray-500">Loading candidates…</div>
          : eligible.length === 0 ? <div className="rounded border border-gray-800 bg-gray-900/50 p-4 text-center text-xs text-gray-500">
              No eligible {kind} found in this org.
            </div>
          : (
          <ul className="max-h-80 space-y-0.5 overflow-y-auto rounded border border-gray-800 bg-gray-900/40 p-1">
            {eligible.map((c) => {
              const isSelected = selected.includes(c.id);
              const isInOtherApp = Boolean(c.applicationId);
              return (
                <li key={c.id}>
                  <label className={`flex cursor-pointer items-center gap-2 rounded px-2 py-1 text-xs transition-colors ${
                    isSelected ? "bg-indigo-500/10 text-indigo-200" : "text-gray-300 hover:bg-gray-800"
                  }`}>
                    <input type="checkbox" checked={isSelected} onChange={() => toggle(c.id)}
                      className="h-3 w-3 rounded border-gray-600 bg-gray-700 accent-indigo-500" />
                    <span className="flex-1 truncate font-mono">{c.label}</span>
                    {isInOtherApp && <span className="rounded bg-amber-950/30 px-1.5 py-0.5 text-[10px] text-amber-400">in another app</span>}
                  </label>
                </li>
              );
            })}
          </ul>
        )}

        <div className="mt-4 flex justify-end gap-2">
          <button onClick={onClose} className="rounded px-3 py-1.5 text-sm text-gray-400 hover:text-gray-200">Cancel</button>
          <button
            onClick={() => submit.mutate()}
            disabled={selected.length === 0 || submit.isPending}
            className="rounded bg-indigo-700 px-4 py-1.5 text-sm font-medium text-white hover:bg-indigo-600 disabled:opacity-50"
          >
            {submit.isPending ? "Adding…" : `Add ${selected.length}`}
          </button>
        </div>
      </div>
    </div>
  );
}
