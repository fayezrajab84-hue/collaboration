/**
 * GitHubAccountsPage — Phase 29 Slice C1.
 *
 * Lists, creates, edits, and tests GitHub posture-scan targets. Mirrors
 * CloudAccountsPage's shape so the UX is consistent for operators who
 * already added a CloudAccount in Slice A.
 *
 * Two auth paths via discriminator:
 *   - GitHub App installation (preferred — token auto-rotates, reuses
 *     Phase 22.6 plumbing): operator supplies installationId, no PAT.
 *   - Personal Access Token (PAT) fallback: operator pastes a token,
 *     encrypted at rest via encryptionService.
 *
 * UX deliberate choices:
 *   - "Test connection" button on the create modal validates the
 *     credentials hit GitHub BEFORE save. Same rationale as CSPM's
 *     test-connection.
 *   - Per-row Scan + Test buttons let operators re-validate after
 *     GitHub-side changes (token rotated, App permissions changed).
 *   - Auth method picker is a toggle inside the create/edit modals,
 *     not a separate provider entity, since both paths produce the
 *     same scan and the operator's mental model is "one GitHub account".
 */
import { useState } from "react";
import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import { Plus, Trash2, Pencil, Play, X, CheckCircle2, AlertTriangle, Github, RefreshCw } from "lucide-react";
import {
  githubAccountsApi,
  type GitHubAccountListItem,
  type CreateGitHubAccountRequest,
  type GitHubTestConnectionResult,
} from "../lib/api";
import Can from "../components/Can";
import FindingCountBadges from "../components/FindingCountBadges";
import ScanStatusBadge from "../components/ScanStatusBadge";
import { useTargetScanStatus } from "../hooks/useTargetScanStatus";
import { useToast } from "../hooks/useToast";
import { formatRelative } from "../lib/utils";

// ── Add modal ────────────────────────────────────────────────────────────

function AddGitHubAccountModal({ onClose }: { onClose: () => void }) {
  const [displayName,  setDisplayName]  = useState("");
  const [accountLogin, setAccountLogin] = useState("");
  const [accountType,  setAccountType]  = useState<"USER" | "ORGANIZATION">("ORGANIZATION");
  const [authMethod,   setAuthMethod]   = useState<"PAT" | "APP">("PAT");
  const [token,        setToken]        = useState("");
  const [installationId, setInstallationId] = useState("");
  const [testResult,   setTestResult]   = useState<GitHubTestConnectionResult | null>(null);

  const qc = useQueryClient();
  const { toast } = useToast();

  const formData = (): CreateGitHubAccountRequest => ({
    displayName,
    accountLogin,
    accountType,
    ...(authMethod === "PAT"
      ? { token }
      : { installationId: parseInt(installationId, 10) || undefined }),
  });

  const test = useMutation({
    mutationFn: () => githubAccountsApi.testConnectionInline(formData()),
    onSuccess:  (r) => setTestResult(r),
    onError:    (e: Error) => setTestResult({ ok: false, message: e.message }),
  });

  const add = useMutation({
    mutationFn: () => githubAccountsApi.create(formData()),
    onSuccess:  () => {
      qc.invalidateQueries({ queryKey: ["github-accounts"] });
      toast.success("GitHub account added");
      onClose();
    },
    onError: (e: Error & { response?: { data?: { error?: string } } }) =>
      toast.error(e.response?.data?.error ?? e.message ?? "Failed to add GitHub account"),
  });

  const credFilled = authMethod === "PAT" ? token.length >= 20 : Boolean(parseInt(installationId, 10));
  const allFilled  = displayName && accountLogin && credFilled;

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/60 px-4">
      <div className="w-full max-w-xl rounded-xl border border-gray-700 bg-gray-900 p-6 shadow-2xl">
        <div className="mb-4 flex items-center justify-between">
          <div>
            <h2 className="text-base font-semibold text-white">Add GitHub Account</h2>
            <p className="mt-0.5 text-xs text-gray-500">
              Posture target — Prowler will run 24 checks across organization, repository, and workflow scopes.
            </p>
          </div>
          <button onClick={onClose} className="text-gray-500 hover:text-gray-200"><X className="h-4 w-4" /></button>
        </div>

        <div className="space-y-3">
          <Field label="Display name" hint="e.g. 'Production GitHub'">
            <input
              className="w-full rounded bg-gray-800 px-3 py-2 text-sm text-gray-200 placeholder-gray-500 focus:outline-none focus:ring-1 focus:ring-indigo-500"
              placeholder="Production GitHub"
              value={displayName}
              onChange={(e) => setDisplayName(e.target.value)}
            />
          </Field>

          <div className="grid grid-cols-2 gap-3">
            <Field label="Account login" hint="GitHub username or org name">
              <input
                className="w-full rounded bg-gray-800 px-3 py-2 font-mono text-xs text-gray-200 placeholder-gray-500 focus:outline-none focus:ring-1 focus:ring-indigo-500"
                placeholder="my-org"
                value={accountLogin}
                onChange={(e) => setAccountLogin(e.target.value)}
              />
            </Field>
            <Field label="Account type" hint="Some checks (e.g. MFA required) only apply to orgs">
              <select
                className="w-full rounded bg-gray-800 px-3 py-2 text-xs text-gray-200 focus:outline-none focus:ring-1 focus:ring-indigo-500"
                value={accountType}
                onChange={(e) => setAccountType(e.target.value as "USER" | "ORGANIZATION")}
              >
                <option value="ORGANIZATION">Organization</option>
                <option value="USER">User</option>
              </select>
            </Field>
          </div>

          {/* Auth method toggle */}
          <div>
            <label className="mb-1 block text-xs font-medium text-gray-300">Authentication</label>
            <div className="mb-2 flex gap-2 rounded border border-gray-700 bg-gray-800/40 p-1">
              <button
                onClick={() => setAuthMethod("PAT")}
                className={`flex-1 rounded px-3 py-1.5 text-xs font-medium transition-colors ${
                  authMethod === "PAT"
                    ? "bg-gray-700 text-white"
                    : "text-gray-400 hover:text-white"
                }`}
              >
                Personal access token
              </button>
              <button
                onClick={() => setAuthMethod("APP")}
                className={`flex-1 rounded px-3 py-1.5 text-xs font-medium transition-colors ${
                  authMethod === "APP"
                    ? "bg-gray-700 text-white"
                    : "text-gray-400 hover:text-white"
                }`}
                title="Requires the GitHub App to be configured on this deployment"
              >
                GitHub App installation
              </button>
            </div>

            {authMethod === "PAT" ? (
              <Field label="" hint="Needs read:org + repo scopes. Encrypted at rest with AES-256-GCM; never returned to the client.">
                <input
                  type="password"
                  className="w-full rounded bg-gray-800 px-3 py-2 font-mono text-xs text-gray-200 placeholder-gray-500 focus:outline-none focus:ring-1 focus:ring-indigo-500"
                  placeholder="ghp_•••••••••••••••••••••••••••••••••••"
                  value={token}
                  onChange={(e) => setToken(e.target.value)}
                />
              </Field>
            ) : (
              <Field label="" hint="The numeric installation ID from your GitHub App's installation page (Settings → Integrations → GitHub Apps).">
                <input
                  type="text"
                  className="w-full rounded bg-gray-800 px-3 py-2 font-mono text-xs text-gray-200 placeholder-gray-500 focus:outline-none focus:ring-1 focus:ring-indigo-500"
                  placeholder="12345678"
                  value={installationId}
                  onChange={(e) => setInstallationId(e.target.value.replace(/[^0-9]/g, ""))}
                />
              </Field>
            )}
          </div>
        </div>

        {testResult && <TestConnectionBanner result={testResult} />}

        <div className="mt-5 flex items-center justify-end gap-2">
          <button onClick={onClose} className="rounded px-3 py-1.5 text-sm text-gray-400 hover:text-gray-200">Cancel</button>
          <button
            onClick={() => test.mutate()}
            disabled={!allFilled || test.isPending}
            className="rounded border border-gray-600 px-3 py-1.5 text-sm text-gray-200 hover:bg-gray-800 disabled:opacity-50"
            title="Validate credentials against GitHub before saving"
          >
            {test.isPending ? "Testing…" : "Test connection"}
          </button>
          <button
            onClick={() => add.mutate()}
            disabled={!allFilled || add.isPending}
            className="rounded bg-indigo-700 px-4 py-1.5 text-sm font-medium text-white hover:bg-indigo-600 disabled:opacity-50"
          >
            {add.isPending ? "Adding…" : "Add Account"}
          </button>
        </div>
      </div>
    </div>
  );
}

// ── Edit modal ───────────────────────────────────────────────────────────

function EditGitHubAccountModal({ account, onClose }: { account: GitHubAccountListItem; onClose: () => void }) {
  const [displayName,  setDisplayName]  = useState(account.displayName);
  const [accountLogin, setAccountLogin] = useState(account.accountLogin);
  const [accountType,  setAccountType]  = useState(account.accountType);
  const [token,        setToken]        = useState("");

  const qc = useQueryClient();
  const { toast } = useToast();

  const update = useMutation({
    mutationFn: () => githubAccountsApi.update(account.id, {
      displayName,
      accountLogin,
      accountType,
      ...(token ? { token } : {}),
    }),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ["github-accounts"] });
      toast.success("GitHub account updated");
      onClose();
    },
    onError: (e: Error) => toast.error(e.message),
  });

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/60 px-4">
      <div className="w-full max-w-xl rounded-xl border border-gray-700 bg-gray-900 p-6 shadow-2xl">
        <div className="mb-4 flex items-center justify-between">
          <div>
            <h2 className="text-base font-semibold text-white">Edit GitHub Account</h2>
            <p className="mt-0.5 text-xs text-gray-500">
              Update display + login. Paste a new token to rotate; leave blank to keep the existing one.
            </p>
          </div>
          <button onClick={onClose} className="text-gray-500 hover:text-gray-200"><X className="h-4 w-4" /></button>
        </div>

        <div className="space-y-3">
          <Field label="Display name">
            <input
              className="w-full rounded bg-gray-800 px-3 py-2 text-sm text-gray-200 placeholder-gray-500 focus:outline-none focus:ring-1 focus:ring-indigo-500"
              value={displayName}
              onChange={(e) => setDisplayName(e.target.value)}
            />
          </Field>
          <div className="grid grid-cols-2 gap-3">
            <Field label="Account login">
              <input
                className="w-full rounded bg-gray-800 px-3 py-2 font-mono text-xs text-gray-200 placeholder-gray-500 focus:outline-none focus:ring-1 focus:ring-indigo-500"
                value={accountLogin}
                onChange={(e) => setAccountLogin(e.target.value)}
              />
            </Field>
            <Field label="Account type">
              <select
                className="w-full rounded bg-gray-800 px-3 py-2 text-xs text-gray-200 focus:outline-none focus:ring-1 focus:ring-indigo-500"
                value={accountType}
                onChange={(e) => setAccountType(e.target.value as "USER" | "ORGANIZATION")}
              >
                <option value="ORGANIZATION">Organization</option>
                <option value="USER">User</option>
              </select>
            </Field>
          </div>
          <Field label="New PAT (optional)" hint="Paste a new token to rotate. Leave blank to keep the existing one.">
            <input
              type="password"
              className="w-full rounded bg-gray-800 px-3 py-2 font-mono text-xs text-gray-200 placeholder-gray-500 focus:outline-none focus:ring-1 focus:ring-indigo-500"
              placeholder={account.credentialsConfigured ? "•••••••••• (kept)" : "ghp_••••••••••"}
              value={token}
              onChange={(e) => setToken(e.target.value)}
            />
          </Field>
        </div>

        <div className="mt-5 flex items-center justify-end gap-2">
          <button onClick={onClose} className="rounded px-3 py-1.5 text-sm text-gray-400 hover:text-gray-200">Cancel</button>
          <button
            onClick={() => update.mutate()}
            disabled={update.isPending}
            className="rounded bg-indigo-700 px-4 py-1.5 text-sm font-medium text-white hover:bg-indigo-600 disabled:opacity-50"
          >
            {update.isPending ? "Saving…" : "Save changes"}
          </button>
        </div>
      </div>
    </div>
  );
}

// ── Test result banner ──────────────────────────────────────────────────

function TestConnectionBanner({ result }: { result: GitHubTestConnectionResult }) {
  if (result.ok) {
    return (
      <div className="mt-4 flex items-start gap-2 rounded border border-emerald-700/60 bg-emerald-950/30 p-3 text-xs text-emerald-200">
        <CheckCircle2 className="mt-0.5 h-4 w-4 shrink-0" />
        <div>
          <div className="font-semibold">Credentials valid</div>
          <div className="mt-0.5 text-emerald-300/80">{result.message}</div>
        </div>
      </div>
    );
  }
  return (
    <div className="mt-4 flex items-start gap-2 rounded border border-red-700/60 bg-red-950/30 p-3 text-xs text-red-200">
      <AlertTriangle className="mt-0.5 h-4 w-4 shrink-0" />
      <div>
        <div className="font-semibold">Connection test failed</div>
        <div className="mt-0.5 text-red-300/80">{result.message}</div>
      </div>
    </div>
  );
}

// ── Field wrapper ───────────────────────────────────────────────────────

function Field({ label, hint, children }: { label: string; hint?: string; children: React.ReactNode }) {
  return (
    <div>
      {label && <label className="mb-1 block text-xs font-medium text-gray-300">{label}</label>}
      {children}
      {hint && <p className="mt-1 text-[11px] text-gray-500">{hint}</p>}
    </div>
  );
}

// ── Per-row scan button ─────────────────────────────────────────────────

function ScanButton({ accountId, disabled }: { accountId: string; disabled?: boolean }) {
  const qc = useQueryClient();
  const { toast } = useToast();
  const { status, isActive } = useTargetScanStatus(accountId);
  const scan = useMutation({
    mutationFn: () => githubAccountsApi.triggerScan(accountId),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ["scans"] });
      qc.invalidateQueries({ queryKey: ["scans", "active"] });
      qc.invalidateQueries({ queryKey: ["github-accounts"] });
      toast.success("GitHub posture scan queued (Prowler)");
    },
    onError: (err: Error & { response?: { data?: { error?: string } } }) =>
      toast.error(err.response?.data?.error ?? err.message ?? "Failed to queue scan"),
  });
  const rawStatus = status ?? (scan.isPending ? "PENDING" : null);
  const displayStatus = rawStatus && rawStatus !== "COMPLETED" ? rawStatus : null;
  return (
    <div className="flex items-center gap-2">
      {displayStatus && <ScanStatusBadge status={displayStatus} />}
      <button
        onClick={() => scan.mutate()}
        disabled={Boolean(disabled) || scan.isPending || isActive}
        className="flex items-center gap-1.5 rounded bg-indigo-700 px-2.5 py-1 text-xs font-medium text-white hover:bg-indigo-600 disabled:opacity-50"
        title={disabled ? "Configure credentials before scanning" : "Run Prowler GitHub posture audit"}
      >
        <Play className="h-3 w-3" /> Scan
      </button>
    </div>
  );
}

// ── Per-row test-connection button ──────────────────────────────────────

function TestConnectionButton({ accountId }: { accountId: string }) {
  const qc = useQueryClient();
  const { toast } = useToast();
  const test = useMutation({
    mutationFn: () => githubAccountsApi.testConnection(accountId),
    onSuccess: (r) => {
      qc.invalidateQueries({ queryKey: ["github-accounts"] });
      if (r.ok) toast.success(r.message);
      else      toast.error(r.message);
    },
    onError: (e: Error) => toast.error(e.message ?? "Test failed"),
  });
  return (
    <button
      onClick={() => test.mutate()}
      disabled={test.isPending}
      className="flex items-center gap-1.5 rounded border border-gray-700 px-2.5 py-1 text-xs text-gray-300 hover:bg-gray-800 disabled:opacity-50"
      title="Validate credentials against GitHub"
    >
      <RefreshCw className={`h-3 w-3 ${test.isPending ? "animate-spin" : ""}`} />
      Test
    </button>
  );
}

// ── Main page ───────────────────────────────────────────────────────────

export default function GitHubAccountsPage() {
  const [showAdd,    setShowAdd]    = useState(false);
  const [editTarget, setEditTarget] = useState<GitHubAccountListItem | null>(null);

  const { data: accounts, isLoading } = useQuery({
    queryKey: ["github-accounts"],
    queryFn:  githubAccountsApi.list,
  });

  const qc = useQueryClient();
  const { toast } = useToast();
  const del = useMutation({
    mutationFn: (id: string) => githubAccountsApi.delete(id),
    onSuccess:  () => {
      qc.invalidateQueries({ queryKey: ["github-accounts"] });
      toast.success("GitHub account deleted");
    },
  });

  return (
    <div className="p-6">
      <div className="mb-6 flex items-start justify-between">
        <div>
          <h1 className="text-xl font-semibold text-white">GitHub accounts</h1>
          <p className="mt-1 text-xs text-gray-500">
            Posture targets — Prowler runs 24 checks per scan (org MFA / branch protection / secret scanning / dependabot / signed commits / etc.).
          </p>
        </div>
        <Can role="DEVELOPER">
          <button
            onClick={() => setShowAdd(true)}
            className="flex items-center gap-1.5 rounded bg-indigo-700 px-3 py-1.5 text-sm font-medium text-white hover:bg-indigo-600"
          >
            <Plus className="h-4 w-4" /> Add GitHub Account
          </button>
        </Can>
      </div>

      {isLoading ? (
        <div className="text-sm text-gray-500">Loading…</div>
      ) : !accounts || accounts.length === 0 ? (
        <EmptyState onAdd={() => setShowAdd(true)} />
      ) : (
        <div className="overflow-hidden rounded-lg border border-gray-800">
          <table className="w-full text-sm">
            <thead className="bg-gray-900/60 text-[10px] uppercase tracking-wider text-gray-500">
              <tr>
                <th className="px-4 py-2 text-left">Account</th>
                <th className="px-4 py-2 text-left">Login</th>
                <th className="px-4 py-2 text-left">Auth</th>
                <th className="px-4 py-2 text-left">Findings</th>
                <th className="px-4 py-2 text-left">Last test / scan</th>
                <th className="px-4 py-2 text-right">Actions</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-gray-800">
              {accounts.map((a) => (
                <tr key={a.id} className="hover:bg-gray-900/50">
                  <td className="px-4 py-3">
                    <div className="flex items-center gap-2">
                      <Github className="h-4 w-4 text-indigo-400" />
                      <div>
                        <div className="font-medium text-gray-100">{a.displayName}</div>
                        <div className="text-[10px] uppercase tracking-wide text-gray-500">{a.accountType}</div>
                      </div>
                    </div>
                  </td>
                  <td className="px-4 py-3 font-mono text-xs text-gray-300">{a.accountLogin}</td>
                  <td className="px-4 py-3 text-xs">
                    {a.installationId != null ? (
                      <span className="rounded bg-indigo-900/40 px-1.5 py-0.5 text-[10px] font-medium text-indigo-200" title={`Installation #${a.installationId}`}>
                        App
                      </span>
                    ) : a.credentialsConfigured ? (
                      <span className="rounded bg-gray-800 px-1.5 py-0.5 text-[10px] font-medium text-gray-300">
                        PAT
                      </span>
                    ) : (
                      <span className="text-yellow-400">none</span>
                    )}
                  </td>
                  <td className="px-4 py-3">
                    <FindingCountBadges counts={a.findingCounts} />
                  </td>
                  <td className="px-4 py-3 text-xs text-gray-400">
                    {a.lastScanError ? (
                      <span className="flex items-center gap-1.5 text-red-400" title={a.lastScanError}>
                        <AlertTriangle className="h-3 w-3" /> credentials invalid
                      </span>
                    ) : !a.credentialsConfigured ? (
                      <span className="text-yellow-400">credentials needed</span>
                    ) : a.lastScannedAt ? (
                      formatRelative(a.lastScannedAt)
                    ) : (
                      <span className="text-gray-500">never scanned</span>
                    )}
                  </td>
                  <td className="px-4 py-3">
                    <div className="flex items-center justify-end gap-1.5">
                      <Can role="DEVELOPER">
                        <ScanButton accountId={a.id} disabled={!a.credentialsConfigured || !a.isActive} />
                      </Can>
                      <TestConnectionButton accountId={a.id} />
                      <Can role="DEVELOPER">
                        <button
                          onClick={() => setEditTarget(a)}
                          className="rounded p-1.5 text-gray-500 hover:bg-gray-800 hover:text-gray-200"
                          title="Edit"
                        >
                          <Pencil className="h-3.5 w-3.5" />
                        </button>
                      </Can>
                      <Can role="ADMIN">
                        <button
                          onClick={() => {
                            if (confirm(`Delete "${a.displayName}"? This cascades to all GitHub posture findings on this account.`)) {
                              del.mutate(a.id);
                            }
                          }}
                          className="rounded p-1.5 text-gray-500 hover:bg-gray-800 hover:text-red-400"
                          title="Delete"
                        >
                          <Trash2 className="h-3.5 w-3.5" />
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

      {showAdd      && <AddGitHubAccountModal  onClose={() => setShowAdd(false)} />}
      {editTarget   && <EditGitHubAccountModal account={editTarget} onClose={() => setEditTarget(null)} />}
    </div>
  );
}

function EmptyState({ onAdd }: { onAdd: () => void }) {
  return (
    <div className="rounded-xl border border-dashed border-gray-800 bg-gray-900/30 p-10 text-center">
      <Github className="mx-auto h-10 w-10 text-gray-600" />
      <h2 className="mt-3 text-base font-semibold text-white">No GitHub accounts yet</h2>
      <p className="mx-auto mt-1 max-w-sm text-xs text-gray-500">
        Add your GitHub user or organization. Prowler will run 24 posture checks
        (MFA enforcement, branch protection, secret scanning, dependabot, signed commits, etc.)
        and surface failing checks in the Code → Posture sub-pivot.
      </p>
      <Can role="DEVELOPER">
        <button
          onClick={onAdd}
          className="mt-4 inline-flex items-center gap-1.5 rounded bg-indigo-700 px-3 py-1.5 text-sm font-medium text-white hover:bg-indigo-600"
        >
          <Plus className="h-4 w-4" /> Add GitHub Account
        </button>
      </Can>
    </div>
  );
}
