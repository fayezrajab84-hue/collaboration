import { useState } from "react";
import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import { Settings, Github, ShieldCheck } from "lucide-react";
import { integrationsApi, aiProvidersApi } from "../lib/api";
import { useAuth } from "../hooks/useAuth";
import { useToast } from "../hooks/useToast";
import AIProvidersTab from "../components/settings/AIProvidersTab";
import PoliciesTab from "../components/settings/PoliciesTab";
import AuditLogTab from "../components/settings/AuditLogTab";
import TeamTab from "../components/settings/TeamTab";

type Tab = "github" | "team" | "ai" | "policies" | "jira" | "slack" | "teams" | "audit";

function SaveButton({ isPending, saved }: { isPending: boolean; saved: boolean }) {
  return (
    <button
      type="submit"
      disabled={isPending}
      className="rounded bg-indigo-700 px-4 py-2 text-sm font-medium text-white hover:bg-indigo-600 disabled:opacity-50"
    >
      {isPending ? "Saving…" : saved ? "Saved!" : "Save"}
    </button>
  );
}

function DeleteButton({ onClick, isPending }: { onClick: () => void; isPending: boolean }) {
  return (
    <button
      type="button"
      onClick={onClick}
      disabled={isPending}
      className="rounded border border-red-800 px-4 py-2 text-sm text-red-400 hover:bg-red-900/30 disabled:opacity-50"
    >
      {isPending ? "Removing…" : "Remove"}
    </button>
  );
}

function GitHubTab() {
  const { user } = useAuth();
  return (
    <div className="space-y-6">
      <div>
        <h2 className="text-base font-semibold text-white">GitHub Account</h2>
        <p className="mt-1 text-sm text-gray-400">Connected via GitHub OAuth.</p>
      </div>
      <div className="rounded-lg border border-gray-700 bg-gray-800/50 p-4 flex items-center gap-4">
        {user?.avatarUrl && (
          <img src={user.avatarUrl} alt={user.username} className="h-12 w-12 rounded-full" />
        )}
        <div>
          <p className="font-medium text-gray-100">{user?.username ?? "—"}</p>
          <p className="text-sm text-gray-400">{user?.email ?? "No email"}</p>
        </div>
        <Github className="ml-auto h-5 w-5 text-gray-500" />
      </div>
      <p className="text-xs text-gray-600">
        To disconnect, revoke access in your{" "}
        <a
          href="https://github.com/settings/applications"
          target="_blank"
          rel="noreferrer"
          className="text-indigo-400 hover:underline"
        >
          GitHub Applications settings
        </a>
        .
      </p>
    </div>
  );
}

function JiraTab() {
  const qc = useQueryClient();
  const { toast } = useToast();
  const [saved, setSaved] = useState(false);

  const { data: existing } = useQuery({
    queryKey: ["integrations", "jira"],
    queryFn: integrationsApi.getJira,
  });

  const [form, setForm] = useState({
    host: "",
    email: "",
    apiToken: "",
    projectKey: "",
    issueType: "Bug",
  });

  const save = useMutation({
    mutationFn: () => integrationsApi.saveJira(form),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ["integrations", "jira"] });
      setSaved(true);
      setTimeout(() => setSaved(false), 3000);
      toast.success("Jira integration saved");
    },
    onError: (err: Error) => toast.error(err.message || "Failed to save Jira integration"),
  });

  const remove = useMutation({
    mutationFn: integrationsApi.deleteJira,
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ["integrations", "jira"] });
      toast.info("Jira integration removed");
    },
    onError: (err: Error) => toast.error(err.message || "Failed to remove integration"),
  });

  const field = (label: string, key: keyof typeof form, type = "text", placeholder = "") => (
    <div>
      <label className="mb-1.5 block text-sm font-medium text-gray-300">{label}</label>
      <input
        type={type}
        value={form[key]}
        placeholder={placeholder}
        onChange={(e) => setForm((f) => ({ ...f, [key]: e.target.value }))}
        className="w-full rounded bg-gray-800 px-3 py-2 text-sm text-gray-200 placeholder-gray-600 focus:outline-none focus:ring-1 focus:ring-indigo-500"
      />
    </div>
  );

  return (
    <div className="space-y-6">
      <div className="flex items-start justify-between">
        <div>
          <h2 className="text-base font-semibold text-white">Jira Integration</h2>
          <p className="mt-1 text-sm text-gray-400">
            Automatically create Jira issues for security findings.
          </p>
        </div>
        {existing && (
          <span className="rounded-full bg-teal-900/40 border border-teal-800/40 px-2.5 py-0.5 text-xs text-teal-300">
            Connected
          </span>
        )}
      </div>

      {existing && (
        <div className="rounded-lg border border-gray-700 bg-gray-800/50 p-3 text-sm text-gray-300">
          <span className="font-medium">{(existing as unknown as Record<string, string>)["host"]}</span> · Project:{" "}
          <span className="font-medium">{(existing as unknown as Record<string, string>)["projectKey"]}</span> · {(existing as unknown as Record<string, string>)["email"]}
        </div>
      )}

      <form
        onSubmit={(e) => {
          e.preventDefault();
          save.mutate();
        }}
        className="space-y-4"
      >
        {field("Jira Host URL", "host", "url", "https://yourcompany.atlassian.net")}
        {field("Account Email", "email", "email", "you@company.com")}
        {field("API Token", "apiToken", "password", "••••••••")}
        <div className="grid grid-cols-2 gap-4">
          {field("Project Key", "projectKey", "text", "SEC")}
          <div>
            <label className="mb-1.5 block text-sm font-medium text-gray-300">Issue Type</label>
            <select
              value={form.issueType}
              onChange={(e) => setForm((f) => ({ ...f, issueType: e.target.value }))}
              className="w-full rounded bg-gray-800 px-3 py-2 text-sm text-gray-200 focus:outline-none focus:ring-1 focus:ring-indigo-500"
            >
              <option>Bug</option>
              <option>Task</option>
              <option>Story</option>
              <option>Vulnerability</option>
            </select>
          </div>
        </div>
        <div className="flex items-center gap-3 pt-1">
          <SaveButton isPending={save.isPending} saved={saved} />
          {existing && <DeleteButton onClick={() => remove.mutate()} isPending={remove.isPending} />}
        </div>
        {save.error && (
          <p className="text-xs text-red-400">{(save.error as Error).message}</p>
        )}
      </form>
    </div>
  );
}

function SlackTab() {
  const qc = useQueryClient();
  const { toast } = useToast();
  const [saved, setSaved] = useState(false);
  const [webhookUrl, setWebhookUrl] = useState("");
  const [channel, setChannel] = useState("");

  const { data: existing } = useQuery({
    queryKey: ["integrations", "slack"],
    queryFn: integrationsApi.getSlack,
  });

  const save = useMutation({
    mutationFn: () => integrationsApi.saveSlack({ webhookUrl, channel: channel || undefined }),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ["integrations", "slack"] });
      setSaved(true);
      setTimeout(() => setSaved(false), 3000);
      toast.success("Slack integration saved");
    },
    onError: (err: Error) => toast.error(err.message || "Failed to save Slack integration"),
  });

  const remove = useMutation({
    mutationFn: integrationsApi.deleteSlack,
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ["integrations", "slack"] });
      toast.info("Slack integration removed");
    },
    onError: (err: Error) => toast.error(err.message || "Failed to remove integration"),
  });

  return (
    <div className="space-y-6">
      <div className="flex items-start justify-between">
        <div>
          <h2 className="text-base font-semibold text-white">Slack Integration</h2>
          <p className="mt-1 text-sm text-gray-400">
            Receive alerts in Slack for new CRITICAL and HIGH findings.
          </p>
        </div>
        {existing && (
          <span className="rounded-full bg-teal-900/40 border border-teal-800/40 px-2.5 py-0.5 text-xs text-teal-300">
            Connected
          </span>
        )}
      </div>

      {existing && (
        <div className="rounded-lg border border-gray-700 bg-gray-800/50 p-3 text-sm text-gray-300">
          Incoming webhook configured.
        </div>
      )}

      <p className="text-xs text-gray-500">
        Create an incoming webhook at{" "}
        <span className="text-gray-400">api.slack.com/apps</span> and paste the URL below.
      </p>

      <form
        onSubmit={(e) => {
          e.preventDefault();
          save.mutate();
        }}
        className="space-y-4"
      >
        <div>
          <label className="mb-1.5 block text-sm font-medium text-gray-300">Webhook URL</label>
          <input
            type="url"
            value={webhookUrl}
            onChange={(e) => setWebhookUrl(e.target.value)}
            placeholder="https://hooks.slack.com/services/T.../B.../..."
            className="w-full rounded bg-gray-800 px-3 py-2 text-sm text-gray-200 placeholder-gray-600 focus:outline-none focus:ring-1 focus:ring-indigo-500"
          />
        </div>
        <div>
          <label className="mb-1.5 block text-sm font-medium text-gray-300">
            Channel <span className="text-gray-600">(optional)</span>
          </label>
          <input
            type="text"
            value={channel}
            onChange={(e) => setChannel(e.target.value)}
            placeholder="#security-alerts"
            className="w-full rounded bg-gray-800 px-3 py-2 text-sm text-gray-200 placeholder-gray-600 focus:outline-none focus:ring-1 focus:ring-indigo-500"
          />
        </div>
        <div className="flex items-center gap-3 pt-1">
          <SaveButton isPending={save.isPending} saved={saved} />
          {existing && <DeleteButton onClick={() => remove.mutate()} isPending={remove.isPending} />}
        </div>
        {save.error && (
          <p className="text-xs text-red-400">{(save.error as Error).message}</p>
        )}
      </form>
    </div>
  );
}

function TeamsTab() {
  const qc = useQueryClient();
  const { toast } = useToast();
  const [saved, setSaved] = useState(false);
  const [webhookUrl, setWebhookUrl] = useState("");

  const { data: existing } = useQuery({
    queryKey: ["integrations", "teams"],
    queryFn: integrationsApi.getTeams,
  });

  const save = useMutation({
    mutationFn: () => integrationsApi.saveTeams({ webhookUrl }),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ["integrations", "teams"] });
      setSaved(true);
      setTimeout(() => setSaved(false), 3000);
      toast.success("Teams integration saved");
    },
    onError: (err: Error) => toast.error(err.message || "Failed to save Teams integration"),
  });

  const remove = useMutation({
    mutationFn: integrationsApi.deleteTeams,
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ["integrations", "teams"] });
      toast.info("Teams integration removed");
    },
    onError: (err: Error) => toast.error(err.message || "Failed to remove integration"),
  });

  return (
    <div className="space-y-6">
      <div className="flex items-start justify-between">
        <div>
          <h2 className="text-base font-semibold text-white">Microsoft Teams Integration</h2>
          <p className="mt-1 text-sm text-gray-400">
            Receive alerts in Microsoft Teams for new CRITICAL and HIGH findings.
          </p>
        </div>
        {existing && (
          <span className="rounded-full bg-teal-900/40 border border-teal-800/40 px-2.5 py-0.5 text-xs text-teal-300">
            Connected
          </span>
        )}
      </div>

      {existing && (
        <div className="rounded-lg border border-gray-700 bg-gray-800/50 p-3 text-sm text-gray-300">
          Incoming webhook configured.
        </div>
      )}

      <p className="text-xs text-gray-500">
        Add an "Incoming Webhook" connector to a Teams channel and paste the URL below.
      </p>

      <form
        onSubmit={(e) => {
          e.preventDefault();
          save.mutate();
        }}
        className="space-y-4"
      >
        <div>
          <label className="mb-1.5 block text-sm font-medium text-gray-300">Webhook URL</label>
          <input
            type="url"
            value={webhookUrl}
            onChange={(e) => setWebhookUrl(e.target.value)}
            placeholder="https://company.webhook.office.com/webhookb2/..."
            className="w-full rounded bg-gray-800 px-3 py-2 text-sm text-gray-200 placeholder-gray-600 focus:outline-none focus:ring-1 focus:ring-indigo-500"
          />
        </div>
        <div className="flex items-center gap-3 pt-1">
          <SaveButton isPending={save.isPending} saved={saved} />
          {existing && <DeleteButton onClick={() => remove.mutate()} isPending={remove.isPending} />}
        </div>
        {save.error && (
          <p className="text-xs text-red-400">{(save.error as Error).message}</p>
        )}
      </form>
    </div>
  );
}

const TABS: { id: Tab; label: string }[] = [
  { id: "github",   label: "GitHub" },
  { id: "team",     label: "Team" },
  { id: "ai",       label: "AI Providers" },
  { id: "policies", label: "Policies" },
  { id: "jira",     label: "Jira" },
  { id: "slack",  label: "Slack" },
  { id: "teams",  label: "Microsoft Teams" },
  { id: "audit",  label: "Audit Log" },
];

export default function SettingsPage() {
  const [activeTab, setActiveTab] = useState<Tab>("github");

  // Fetch all integration statuses at the page level so tab nav can show
  // connected indicators without the user having to open each tab first.
  const { data: jiraData }      = useQuery({ queryKey: ["integrations", "jira"],  queryFn: integrationsApi.getJira,  retry: false });
  const { data: slackData }     = useQuery({ queryKey: ["integrations", "slack"], queryFn: integrationsApi.getSlack, retry: false });
  const { data: teamsData }     = useQuery({ queryKey: ["integrations", "teams"], queryFn: integrationsApi.getTeams, retry: false });
  const { data: aiProviders = [] } = useQuery({ queryKey: ["ai-providers"], queryFn: aiProvidersApi.list, retry: false });

  const connected: Record<Tab, boolean> = {
    github:   true,   // GitHub is always connected (OAuth session)
    team:     false,  // No "connected" dot — always present
    ai:       aiProviders.length > 0,
    policies: false,  // No "connected" dot for policies
    jira:     !!jiraData,
    slack:    !!slackData,
    teams:    !!teamsData,
    audit:    false,  // No "connected" dot — read-only view
  };

  return (
    <div className="p-6">
      <div className="mb-6 flex items-center gap-3">
        <Settings className="h-5 w-5 text-gray-400" />
        <h1 className="text-3xl font-bold text-white">Settings</h1>
      </div>

      <div className="flex gap-6">
        {/* Sidebar tabs */}
        <nav className="w-44 shrink-0 space-y-1">
          {TABS.map(({ id, label }) => (
            <button
              key={id}
              onClick={() => setActiveTab(id)}
              className={`flex w-full items-center justify-between rounded-lg px-3 py-2 text-left text-sm font-medium transition-colors ${
                activeTab === id
                  ? "bg-indigo-700/20 text-indigo-300"
                  : "text-gray-400 hover:bg-gray-800 hover:text-gray-200"
              }`}
            >
              <span>{label}</span>
              {connected[id] && (
                <span
                  className="h-2 w-2 rounded-full bg-teal-500 shrink-0"
                  title="Connected"
                />
              )}
            </button>
          ))}
        </nav>

        {/* Content panel */}
        <div className="flex-1 rounded-xl border border-gray-800 bg-gray-900 p-6">
          <div className="mb-4 flex items-center gap-2 rounded-lg border border-gray-800 bg-gray-900/40 px-3 py-2">
            <ShieldCheck className="h-3.5 w-3.5 text-indigo-400 shrink-0" />
            <p className="text-xs text-gray-400">
              All credentials are encrypted at rest using AES-256-GCM before storage.
            </p>
          </div>

          {activeTab === "github"   && <GitHubTab />}
          {activeTab === "team"     && <TeamTab />}
          {activeTab === "ai"       && <AIProvidersTab />}
          {activeTab === "policies" && <PoliciesTab />}
          {activeTab === "jira"     && <JiraTab />}
          {activeTab === "slack"  && <SlackTab />}
          {activeTab === "teams"  && <TeamsTab />}
          {activeTab === "audit"  && <AuditLogTab />}
        </div>
      </div>
    </div>
  );
}
