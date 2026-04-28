/**
 * RuntimePage — Phase 28 Slice B.
 *
 * Operator-facing UI for the Wazuh runtime ingestion. Tabs:
 *   • Agents  — table of WorkloadAgent rows with status, linked container,
 *               and per-row actions (link, unlink, delete). "Refresh from
 *               Wazuh" calls /runtime/agents/discover so newly-enrolled
 *               agents appear without a container restart.
 *   • Install — copy-paste install snippets for Linux / Windows / Docker
 *               so an operator can enrol a workload without leaving the UI.
 *
 * The "linked container" edge is what makes runtimeBridge correlate this
 * workload's RUNTIME findings with CONTAINER findings. Without it, the
 * agent's alerts still ingest but they stay isolated from the existing
 * attack-chain graph.
 */
import { useState } from "react";
import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import {
  Activity, RefreshCcw, Trash2, Link2, Link2Off, X, AlertCircle,
  Copy, Check, Shield, RotateCw, KeyRound,
} from "lucide-react";

// ── OS brand icons ───────────────────────────────────────────────────────
//
// Lucide doesn't ship logo glyphs, and pulling in react-icons just for
// three SVGs would balloon the bundle. These are simplified silhouettes
// derived from the public-domain marks — recognisable enough to read
// "Linux / Windows / Docker" at a glance, not pixel-perfect brand
// reproductions. All use currentColor so they inherit the parent's
// text colour for theming.

function LinuxIcon({ className = "" }: { className?: string }) {
  // Tux — single-colour silhouette (currentColor) with two eye cutouts
  // and a small beak notch. Earlier two-tone version (yellow beak + dark
  // belly) read as "weird purple blob" at 16px; this is monochromatic so
  // the parent's text-white setting carries cleanly through.
  //
  // Eye + beak holes are achieved with `fill-rule="evenodd"` + a single
  // compound path so the silhouette stays one element and inherits the
  // parent colour without inner-fill colour leaks.
  return (
    <svg viewBox="0 0 24 24" className={className} aria-label="Linux" fill="currentColor">
      <path
        fillRule="evenodd"
        clipRule="evenodd"
        d="M12 2c-2.4 0-4.3 2.2-4.3 5 0 1.1.3 2.2.8 3-.6.7-1.2 1.5-1.7 2.4-1 1.7-1.8 3.3-1.8 4.7 0 .9.3 1.6.8 2 .5.4 1.2.6 1.9.6h8.6c.7 0 1.4-.2 1.9-.6.5-.4.8-1.1.8-2 0-1.4-.8-3-1.8-4.7-.5-.9-1.1-1.7-1.7-2.4.5-.8.8-1.9.8-3 0-2.8-1.9-5-4.3-5zm-1.6 4.6a.7.85 0 1 0 0 1.7.7.85 0 0 0 0-1.7zm3.2 0a.7.85 0 1 0 0 1.7.7.85 0 0 0 0-1.7zM12 9.4l-1 1.2h2L12 9.4z"
      />
    </svg>
  );
}

function WindowsIcon({ className = "" }: { className?: string }) {
  // Windows — 4-pane logo
  return (
    <svg viewBox="0 0 24 24" fill="currentColor" className={className} aria-label="Windows">
      <path d="M3 5.4 11 4.3v7.4H3V5.4Zm0 7.3h8v7.4l-8-1.1v-6.3Zm9-8.7L21 2.7v9H12V4Zm0 8.7h9V21l-9-1.3v-7Z" />
    </svg>
  );
}

function DockerIcon({ className = "" }: { className?: string }) {
  // Docker whale — container stack with whale silhouette above
  return (
    <svg viewBox="0 0 24 24" fill="currentColor" className={className} aria-label="Docker">
      <path d="M22 9.4c-.2-.1-1-.5-2.1-.4-.1-.7-.5-1.4-1.1-1.9l-.3-.2-.2.3c-.4.5-.6 1.4-.5 2.2.1.3.2.6.3.9-1.5.6-3 .6-3.4.6H1.5l-.1.4c-.2 1.5.1 3 1 4.1 1 1.1 2.6 1.7 4.7 1.7 4.5 0 7.9-2 9.5-5.7.6 0 2 0 2.7-1.3.1-.1.3-.4.4-.7l.1-.1-.1-.1.3-.4-.3.6Zm-18 .1h2v2H4v-2Zm2.5 0h2v2h-2v-2Zm2.5 0h2v2H9v-2Zm2.5 0h2v2h-2v-2Zm0-2.5h2v2h-2v-2Zm-2.5 0h2v2H9v-2Zm-2.5 0h2v2h-2v-2Zm0-2.5h2v2h-2v-2Zm5 5h2v2h-2v-2Zm0-2.5h2v2h-2v-2Z" />
    </svg>
  );
}
import { runtimeApi, containersApi } from "../lib/api";
import Can from "../components/Can";
import { useToast } from "../hooks/useToast";
import { formatRelative } from "../lib/utils";
import type { WorkloadAgent, AgentStatus, Container } from "@devsecops/types";

// ── Status pill (matches the brand pattern from SeverityBadge) ───────────

function AgentStatusPill({ status }: { status: AgentStatus }) {
  const styles: Record<AgentStatus, string> = {
    HEALTHY: "bg-emerald-950/50 text-emerald-300 border-emerald-800/50",
    STALE:   "bg-amber-950/40 text-amber-300 border-amber-800/40",
    OFFLINE: "bg-red-950/40 text-red-300 border-red-800/40",
    UNKNOWN: "bg-gray-800 text-gray-400 border-gray-700",
  };
  return (
    <span
      className={`inline-flex items-center gap-1.5 rounded-full border px-2 py-0.5 text-xs font-medium ${styles[status]}`}
    >
      <span
        className={`h-1.5 w-1.5 rounded-full ${
          status === "HEALTHY" ? "bg-emerald-400"
          : status === "STALE" ? "bg-amber-400"
          : status === "OFFLINE" ? "bg-red-400"
          : "bg-gray-500"
        }`}
      />
      {status}
    </span>
  );
}

// ── Container picker for the "Link to container" modal ───────────────────

function LinkContainerModal({
  agent, containers, onClose,
}: {
  agent:      WorkloadAgent;
  containers: Container[];
  onClose:    () => void;
}) {
  const [selected, setSelected] = useState<string | null>(agent.linkedContainerId);
  const qc = useQueryClient();
  const { toast } = useToast();

  const update = useMutation({
    mutationFn: () => runtimeApi.link(agent.id, selected),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ["runtime-agents"] });
      qc.invalidateQueries({ queryKey: ["attack-paths"] });
      toast.success(selected ? "Agent linked to container" : "Agent unlinked");
      onClose();
    },
    onError: (err: Error) => toast.error(err.message || "Failed to update link"),
  });

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/60">
      <div className="w-full max-w-lg rounded-xl border border-gray-700 bg-gray-900 p-6 shadow-2xl">
        <div className="mb-4 flex items-center justify-between">
          <div>
            <h2 className="text-base font-semibold text-white">Link to container</h2>
            <p className="mt-1 text-xs text-gray-400">
              Agent <span className="font-mono text-gray-300">{agent.wazuhAgentName}</span>
              {" "}( ID {agent.wazuhAgentId} )
            </p>
          </div>
          <button onClick={onClose} className="text-gray-500 hover:text-gray-200">
            <X className="h-4 w-4" />
          </button>
        </div>

        <p className="mb-3 text-xs text-gray-400">
          Linking an agent to a container is what lets the correlation engine
          bridge runtime alerts with image-CVE findings on the same workload.
        </p>

        <div className="max-h-80 overflow-y-auto rounded-lg border border-gray-800">
          <button
            type="button"
            onClick={() => setSelected(null)}
            className={`flex w-full items-center justify-between px-3 py-2.5 text-left text-sm border-b border-gray-800 ${
              selected === null ? "bg-indigo-950/40 text-indigo-200" : "text-gray-400 hover:bg-gray-800"
            }`}
          >
            <span className="italic">No container (unlink)</span>
            {selected === null && <Check className="h-4 w-4" />}
          </button>
          {containers.length === 0 && (
            <p className="px-3 py-3 text-xs text-gray-500">
              No containers in this organisation. Add one on the Containers page first.
            </p>
          )}
          {containers.map((c) => (
            <button
              key={c.id}
              type="button"
              onClick={() => setSelected(c.id)}
              className={`flex w-full items-center justify-between px-3 py-2.5 text-left text-sm ${
                selected === c.id ? "bg-indigo-950/40 text-indigo-200" : "text-gray-300 hover:bg-gray-800"
              }`}
            >
              <span className="font-mono">{c.imageRef}</span>
              {selected === c.id && <Check className="h-4 w-4" />}
            </button>
          ))}
        </div>

        <div className="mt-5 flex justify-end gap-2">
          <button
            onClick={onClose}
            className="rounded px-3 py-1.5 text-sm text-gray-400 hover:text-gray-200"
          >
            Cancel
          </button>
          <button
            onClick={() => update.mutate()}
            disabled={update.isPending}
            className="rounded bg-indigo-700 px-4 py-1.5 text-sm font-medium text-white hover:bg-indigo-600 disabled:opacity-50"
          >
            {update.isPending ? "Saving…" : "Save"}
          </button>
        </div>
      </div>
    </div>
  );
}

// ── Install tab ──────────────────────────────────────────────────────────
//
// Hard-coded against the wazuh manager IP we deployed. We keep the IP
// inline rather than threading it through an env var because the install
// snippets the operator copies have to be self-contained — bouncing
// through a settings panel just to configure the manager URL would be
// hostile.
const WAZUH_MANAGER_IP = "20.205.154.88";

// One uniform palette for every code block, regardless of shell.
// We tried a per-shell palette (PS-navy for powershell, slate for bash)
// to lean into terminal-recognition cues, but the navy block read as a
// jarring full-bleed colour patch against the rest of the indigo-quiet
// page. Operators clock the shell from the filename + the hostname-bar
// section header anyway — the body colour was earning its keep mostly
// for novelty. Going back to one neutral dark slate reads calmer and
// keeps brand-indigo as the only loud accent on the page.
//
// The `shell` prop is kept for forward-compatibility (e.g. if we ever
// add syntax highlighting that varies per shell), but currently has no
// visual effect.
function CodeBlock({ code, label }: {
  code:   string;
  label:  string;
  shell?: "bash" | "powershell";
}) {
  const [copied, setCopied] = useState(false);
  function copy() {
    navigator.clipboard.writeText(code).then(() => {
      setCopied(true);
      setTimeout(() => setCopied(false), 1500);
    });
  }

  return (
    <div className="overflow-hidden rounded-lg border border-gray-800 bg-black shadow-sm shadow-black/40">
      <div className="flex items-center justify-between border-b border-gray-800 bg-gray-950 px-3 py-2">
        <span className="font-mono text-[11px] font-medium tracking-tight text-gray-300">
          {label}
        </span>
        <button
          onClick={copy}
          className="flex items-center gap-1.5 rounded px-2 py-1 text-xs text-gray-300 hover:opacity-80"
        >
          {copied ? <Check className="h-3 w-3 text-emerald-400" /> : <Copy className="h-3 w-3" />}
          {copied ? "Copied" : "Copy"}
        </button>
      </div>
      <pre className="overflow-x-auto px-4 py-3 text-xs leading-relaxed text-gray-100">
        <code>{code}</code>
      </pre>
    </div>
  );
}

function InstallTab() {
  const linuxScript = `# 1) Add the Wazuh repository
curl -s https://packages.wazuh.com/key/GPG-KEY-WAZUH | sudo gpg --no-default-keyring --keyring gnupg-ring:/usr/share/keyrings/wazuh.gpg --import
sudo chmod 644 /usr/share/keyrings/wazuh.gpg
echo "deb [signed-by=/usr/share/keyrings/wazuh.gpg] https://packages.wazuh.com/4.x/apt/ stable main" | sudo tee /etc/apt/sources.list.d/wazuh.list

# 2) Install the agent (matches your manager version 4.13.x)
sudo apt-get update
sudo WAZUH_MANAGER='${WAZUH_MANAGER_IP}' apt-get install -y wazuh-agent=4.13.1-1

# 3) (Only if your manager requires authd password enrollment — see token block above)
# echo '<your-registration-password>' | sudo tee /var/ossec/etc/authd.pass
# sudo chmod 640 /var/ossec/etc/authd.pass

# 4) Enable + start
sudo systemctl daemon-reload
sudo systemctl enable wazuh-agent
sudo systemctl start wazuh-agent

# 5) Verify it's enrolled (look for "Active" against your hostname)
sudo /var/ossec/bin/agent_control -l`;

  const windowsScript = `# Run as Administrator in PowerShell. Manager IP is hard-coded for this org.
# If your manager requires a password, append:
#   WAZUH_REGISTRATION_PASSWORD="<your-token>"
# to the msiexec arguments below.

Invoke-WebRequest -Uri https://packages.wazuh.com/4.x/windows/wazuh-agent-4.13.1-1.msi \`
  -OutFile $env:tmp\\wazuh-agent.msi
msiexec.exe /i $env:tmp\\wazuh-agent.msi /q \`
  WAZUH_MANAGER="${WAZUH_MANAGER_IP}" \`
  WAZUH_REGISTRATION_SERVER="${WAZUH_MANAGER_IP}"
Net Start WazuhSvc`;

  const dockerScript = `# Sidecar pattern — run a wazuh-agent container alongside your workload,
# sharing PID + network namespaces so it can monitor the workload's
# processes and ports.
#
# If your manager requires a password, add: -e WAZUH_REGISTRATION_PASSWORD='<token>'

docker run -d --name wazuh-agent \\
  --pid=container:<your-workload-container-name> \\
  --network=container:<your-workload-container-name> \\
  -e WAZUH_MANAGER='${WAZUH_MANAGER_IP}' \\
  -e WAZUH_AGENT_NAME='<friendly-hostname>' \\
  --restart unless-stopped \\
  wazuh/wazuh-agent:4.13.1`;

  const inContainerScript = `# In-container install — run when you can't add a sidecar (e.g. you're
# debugging the existing image). Apply inside a running container, then
# bake into the image once you're happy.

apt-get update && apt-get install -y curl gnupg
curl -s https://packages.wazuh.com/key/GPG-KEY-WAZUH | gpg --no-default-keyring --keyring gnupg-ring:/usr/share/keyrings/wazuh.gpg --import
chmod 644 /usr/share/keyrings/wazuh.gpg
echo "deb [signed-by=/usr/share/keyrings/wazuh.gpg] https://packages.wazuh.com/4.x/apt/ stable main" > /etc/apt/sources.list.d/wazuh.list
apt-get update
WAZUH_MANAGER='${WAZUH_MANAGER_IP}' apt-get install -y wazuh-agent=4.13.1-1

# Start in the foreground (containers don't have systemd):
/var/ossec/bin/wazuh-control start`;

  return (
    <div className="space-y-6">
      <div className="rounded-lg border border-indigo-900/40 bg-indigo-950/20 p-4">
        <div className="flex items-start gap-3">
          <Shield className="mt-0.5 h-4 w-4 flex-shrink-0 text-indigo-400" />
          <div>
            <h3 className="text-sm font-semibold text-indigo-200">
              Wazuh manager: <span className="font-mono text-indigo-100">{WAZUH_MANAGER_IP}</span>
            </h3>
            <p className="mt-1 text-xs text-indigo-300/80">
              After install, use <span className="font-mono">Refresh from Wazuh</span> on the
              Agents tab to import newly-enrolled hosts. Then click{" "}
              <span className="font-mono">Link to container</span> on each row to enable
              cross-tier correlation.
            </p>
          </div>
        </div>
      </div>

      {/* ── Registration token / password — sibling card to the manager
          block above; same indigo palette so the two info cards read as a
          consistent "what you need to know before installing" cluster. */}
      <div className="rounded-lg border border-indigo-900/40 bg-indigo-950/20 p-4">
        <div className="flex items-start gap-3">
          <KeyRound className="mt-0.5 h-4 w-4 flex-shrink-0 text-indigo-400" />
          <div>
            <h3 className="text-sm font-semibold text-indigo-200">
              Registration password (only when authd requires it)
            </h3>
            <p className="mt-1 text-xs text-indigo-300/80">
              Wazuh's enrolment service (<span className="font-mono">authd</span>) optionally
              requires a shared secret. If the manager has{" "}
              <span className="font-mono">use_password=yes</span> in{" "}
              <span className="font-mono">ossec.conf</span>, every install snippet below needs
              the password too. Retrieve it from the manager and add the password line marked
              in each script.
            </p>
            <pre className="mt-2 overflow-x-auto rounded border border-indigo-900/40 bg-indigo-950/40 px-3 py-2 text-[11px] text-indigo-100">
{`# On the Wazuh manager host:
docker exec -it single-node-wazuh.manager-1 cat /var/ossec/etc/authd.pass`}
            </pre>
            <p className="mt-2 text-[11px] text-indigo-300/60">
              If the file doesn't exist or is empty, this manager allows passwordless
              enrolment and you can skip the registration step entirely.
            </p>
          </div>
        </div>
      </div>

      <section>
        <h3 className="mb-2 flex items-center gap-2 text-sm font-semibold text-white">
          <LinuxIcon className="h-4 w-4 text-white" /> Linux (Debian / Ubuntu)
        </h3>
        <CodeBlock label="install-wazuh-agent.sh" code={linuxScript} shell="bash" />
      </section>

      <section>
        <h3 className="mb-2 flex items-center gap-2 text-sm font-semibold text-white">
          <WindowsIcon className="h-4 w-4 text-white" /> Windows
        </h3>
        <CodeBlock label="install-wazuh-agent.ps1" code={windowsScript} shell="powershell" />
      </section>

      <section>
        <h3 className="mb-2 flex items-center gap-2 text-sm font-semibold text-white">
          <DockerIcon className="h-4 w-4 text-white" /> Docker — sidecar
        </h3>
        <p className="mb-2 text-xs text-gray-500">
          Recommended for containerised workloads. Runs the agent in its own container
          while sharing the workload's process and network namespaces.
        </p>
        <CodeBlock label="docker run" code={dockerScript} shell="bash" />
      </section>

      <section>
        <h3 className="mb-2 flex items-center gap-2 text-sm font-semibold text-white">
          <DockerIcon className="h-4 w-4 text-white" /> Docker — inside an existing container
        </h3>
        <p className="mb-2 text-xs text-gray-500">
          Useful for one-off enrolment when adding a sidecar isn't possible. Bake the
          steps into the Dockerfile once you're satisfied.
        </p>
        <CodeBlock label="docker exec" code={inContainerScript} shell="bash" />
      </section>
    </div>
  );
}

// (removed) Per-page dashboard tab consolidated into /dashboard?tab=runtime.


// ── Page ──────────────────────────────────────────────────────────────────

export default function RuntimePage() {
  // Tabs intentionally do NOT include a per-page Dashboard — the SOC
  // overview lives on the main /dashboard with `?tab=runtime`. This page
  // stays focused on agent management + install snippets so we don't
  // duplicate the dashboard surface.
  const [tab, setTab] = useState<"agents" | "reachability" | "install">("agents");
  const [linkAgent, setLinkAgent] = useState<WorkloadAgent | null>(null);
  const qc = useQueryClient();
  const { toast } = useToast();

  const { data: agents, isLoading } = useQuery({
    queryKey: ["runtime-agents"],
    queryFn:  runtimeApi.list,
    refetchInterval: 30_000, // status / lastAlertAt is naturally fresh
  });
  const { data: containers } = useQuery({
    queryKey: ["containers"],
    queryFn:  containersApi.list,
  });

  const discover = useMutation({
    mutationFn: runtimeApi.discover,
    onSuccess: (r) => {
      qc.invalidateQueries({ queryKey: ["runtime-agents"] });
      if (!r.enabled) toast.error(r.reason ?? "Discovery disabled");
      else toast.success(`Found ${r.discovered.length} agent(s); imported ${r.upserted}`);
    },
    onError: (err: Error) => toast.error(err.message || "Discovery failed"),
  });

  const ingest = useMutation({
    mutationFn: runtimeApi.triggerIngest,
    onSuccess: (s) => {
      qc.invalidateQueries({ queryKey: ["runtime-agents"] });
      qc.invalidateQueries({ queryKey: ["findings"] });
      qc.invalidateQueries({ queryKey: ["attack-paths"] });
      if (!s.enabled) {
        toast.error(s.reason ?? "Ingestion disabled");
        return;
      }
      toast.success(
        `Polled ${s.agentsPolled}/${s.agentsConsidered} agents · ` +
        `${s.alertsIngested} alerts · ${s.findingsTouched} findings touched`,
      );
    },
    onError: (err: Error) => toast.error(err.message || "Ingest failed"),
  });

  const remove = useMutation({
    mutationFn: (id: string) => runtimeApi.remove(id),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ["runtime-agents"] });
      toast.success("Agent removed from BreachLens");
    },
    onError: (err: Error) => toast.error(err.message || "Remove failed"),
  });

  return (
    <div className="p-6">
      <div className="mb-4 flex items-center justify-between">
        <div>
          <h1 className="text-3xl font-bold text-white">Runtime</h1>
          <p className="mt-1 text-sm text-gray-400">
            Wazuh-monitored hosts and containers feeding RUNTIME findings into the
            correlation engine.
          </p>
        </div>
        <div className="flex items-center gap-2">
          <Can role="ADMIN">
            <button
              onClick={() => discover.mutate()}
              disabled={discover.isPending}
              className="flex items-center gap-2 rounded-lg border border-gray-700 bg-gray-800 px-3 py-2 text-sm font-medium text-gray-200 hover:border-indigo-600 hover:bg-gray-700 disabled:opacity-50"
            >
              <RefreshCcw className={`h-4 w-4 ${discover.isPending ? "animate-spin" : ""}`} />
              Refresh from Wazuh
            </button>
          </Can>
          <button
            onClick={() => ingest.mutate()}
            disabled={ingest.isPending}
            className="flex items-center gap-2 rounded-lg bg-indigo-700 px-4 py-2 text-sm font-medium text-white hover:bg-indigo-600 disabled:opacity-50"
          >
            <RotateCw className={`h-4 w-4 ${ingest.isPending ? "animate-spin" : ""}`} />
            Run ingest now
          </button>
        </div>
      </div>

      {/* Tabs */}
      <div className="mb-5 flex gap-1 border-b border-gray-800">
        {(["agents", "install"] as const).map((t) => (
          <button
            key={t}
            onClick={() => setTab(t)}
            className={`px-4 py-2 text-sm font-medium transition-colors border-b-2 -mb-px ${
              tab === t
                ? "border-indigo-500 text-white"
                : "border-transparent text-gray-500 hover:text-gray-300"
            }`}
          >
            {t === "agents" ? "Agents" : "Install"}
          </button>
        ))}
      </div>

      {tab === "install" ? (
        <InstallTab />
      ) : isLoading ? (
        <div className="flex h-48 items-center justify-center text-gray-500">Loading…</div>
      ) : !agents || agents.length === 0 ? (
        <div className="flex h-64 flex-col items-center justify-center gap-3 text-gray-500">
          <Activity className="h-8 w-8" />
          <p className="text-sm">No runtime agents enrolled yet.</p>
          <p className="text-xs text-gray-600">
            Install Wazuh on a host and click <span className="text-gray-400">Refresh from Wazuh</span>{" "}
            to import it, or open the <button onClick={() => setTab("install")} className="text-indigo-400 hover:text-indigo-300 underline">Install tab</button> for setup snippets.
          </p>
        </div>
      ) : (
        <div className="overflow-x-auto rounded-lg border border-gray-800">
          <table className="w-full text-sm">
            <thead className="border-b border-gray-800 bg-gray-900">
              <tr className="text-left text-xs text-gray-500">
                <th className="px-4 py-3 font-medium">Agent</th>
                <th className="px-4 py-3 font-medium">Status</th>
                <th className="px-4 py-3 font-medium">Linked Container</th>
                <th className="px-4 py-3 font-medium">Runtime Findings</th>
                <th className="px-4 py-3 font-medium">Last Alert</th>
                <th className="px-4 py-3 font-medium">Last Heartbeat</th>
                <th className="px-4 py-3 font-medium" aria-label="Actions"></th>
              </tr>
            </thead>
            <tbody className="divide-y divide-gray-800 bg-gray-900/50">
              {agents.map((a) => (
                <tr key={a.id} className="hover:bg-gray-800/40">
                  <td className="px-4 py-3">
                    <div className="font-medium text-gray-200">{a.wazuhAgentName}</div>
                    <div className="font-mono text-xs text-gray-500">
                      ID {a.wazuhAgentId}
                      {a.agentVersion && <span className="ml-2">v{a.agentVersion}</span>}
                    </div>
                    {a.lastIngestError && (
                      <div className="mt-1 flex items-start gap-1 text-xs text-red-400">
                        <AlertCircle className="mt-0.5 h-3 w-3 flex-shrink-0" />
                        <span className="break-all">{a.lastIngestError}</span>
                      </div>
                    )}
                  </td>
                  <td className="px-4 py-3">
                    <AgentStatusPill status={a.status} />
                  </td>
                  <td className="px-4 py-3 font-mono text-xs">
                    {a.linkedContainerImageRef ? (
                      <span className="text-gray-200">{a.linkedContainerImageRef}</span>
                    ) : (
                      <span className="text-gray-600 italic">— unlinked —</span>
                    )}
                  </td>
                  <td className="px-4 py-3 text-gray-300">
                    {a.runtimeFindingCount ?? 0}
                  </td>
                  <td className="px-4 py-3 text-gray-400">
                    {a.lastAlertAt ? formatRelative(a.lastAlertAt) : "Never"}
                  </td>
                  <td className="px-4 py-3 text-gray-400">
                    {a.lastHeartbeatAt ? formatRelative(a.lastHeartbeatAt) : "Never"}
                  </td>
                  <td className="px-4 py-3">
                    <div className="flex items-center justify-end gap-1.5">
                      <Can role="ADMIN">
                        <button
                          onClick={() => setLinkAgent(a)}
                          className="flex items-center gap-1.5 rounded border border-gray-700 bg-gray-800 px-2.5 py-1 text-xs text-gray-300 hover:border-indigo-600 hover:text-indigo-300"
                          title={a.linkedContainerId ? "Change linked container" : "Link to a container"}
                        >
                          {a.linkedContainerId ? (
                            <><Link2 className="h-3 w-3" /> Linked</>
                          ) : (
                            <><Link2Off className="h-3 w-3" /> Link</>
                          )}
                        </button>
                      </Can>
                      <Can role="ADMIN">
                        <button
                          onClick={() => {
                            if (confirm(`Remove agent "${a.wazuhAgentName}" from BreachLens?\n\nThis only disassociates it from BreachLens; the agent stays enrolled in Wazuh.`)) {
                              remove.mutate(a.id);
                            }
                          }}
                          className="text-gray-600 hover:text-red-400"
                          title="Remove from BreachLens"
                        >
                          <Trash2 className="h-4 w-4" />
                        </button>
                      </Can>
                    </div>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}

      {linkAgent && (
        <LinkContainerModal
          agent={linkAgent}
          containers={containers ?? []}
          onClose={() => setLinkAgent(null)}
        />
      )}
    </div>
  );
}
