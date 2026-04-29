/**
 * CloudAccountsPage — Phase 29 Slice A.
 *
 * Lists, creates, edits, and tests CSPM cloud-account targets. Slice A
 * supports AZURE only; future provider support will land additional
 * forms (AWS / GCP) inside the same page rather than separate pages —
 * the asset model is one-per-(provider, scope), not one-page-per-provider.
 *
 * UX deliberate choices:
 *   - "Test connection" button on the create modal validates against
 *     Azure BEFORE the row is committed. Reduces "I saved bad creds and
 *     don't know why scans fail" flow.
 *   - On the list, each row has its own "Test" button so operators can
 *     re-validate after Azure-side changes (SP rotated, role removed)
 *     without triggering a full scan.
 *   - The encrypted credential blob is never returned by the API; the
 *     `credentialsConfigured` boolean drives the "credentials needed"
 *     hint without exposing the blob. Editing only re-encrypts when
 *     the operator pastes a new clientSecret — rename-only edits skip
 *     the encryption churn.
 */
import { useState } from "react";
import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import { Plus, Trash2, Pencil, X, CheckCircle2, AlertTriangle, Cloud, RefreshCw } from "lucide-react";
import {
  cloudAccountsApi,
  type CloudAccountListItem,
  type CreateAzureCloudAccountRequest,
  type TestConnectionResult,
} from "../lib/api";
import Can from "../components/Can";
import FindingCountBadges from "../components/FindingCountBadges";
import { useToast } from "../hooks/useToast";
import { formatRelative } from "../lib/utils";

// ── Helpers ──────────────────────────────────────────────────────────────

function maskGuid(guid: string | null): string {
  if (!guid) return "—";
  if (guid.length < 12) return guid;
  return `${guid.slice(0, 8)}…${guid.slice(-4)}`;
}

// ── Add modal ────────────────────────────────────────────────────────────

function AddCloudAccountModal({ onClose }: { onClose: () => void }) {
  const [displayName,    setDisplayName]    = useState("");
  const [tenantId,       setTenantId]       = useState("");
  const [azureClientId,  setAzureClientId]  = useState("");
  const [subscriptionId, setSubscriptionId] = useState("");
  const [clientSecret,   setClientSecret]   = useState("");
  const [testResult,     setTestResult]     = useState<TestConnectionResult | null>(null);

  const qc = useQueryClient();
  const { toast } = useToast();

  const formData = (): CreateAzureCloudAccountRequest => ({
    provider: "AZURE",
    displayName,
    tenantId,
    azureClientId,
    subscriptionId,
    clientSecret,
  });

  // Test runs against the inline endpoint — credentials aren't saved
  // until the operator clicks Add Account.
  const test = useMutation({
    mutationFn: () => cloudAccountsApi.testConnectionInline(formData()),
    onSuccess:  (r) => setTestResult(r),
    onError:    (e: Error) => setTestResult({ ok: false, code: "unknown", message: e.message }),
  });

  const add = useMutation({
    mutationFn: () => cloudAccountsApi.create(formData()),
    onSuccess:  () => {
      qc.invalidateQueries({ queryKey: ["cloud-accounts"] });
      toast.success("Cloud account added");
      onClose();
    },
    onError: (e: Error & { response?: { data?: { error?: string } } }) =>
      toast.error(e.response?.data?.error ?? e.message ?? "Failed to add cloud account"),
  });

  const allFilled = displayName && tenantId && azureClientId && subscriptionId && clientSecret;

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/60 px-4">
      <div className="w-full max-w-xl rounded-xl border border-gray-700 bg-gray-900 p-6 shadow-2xl">
        <div className="mb-4 flex items-center justify-between">
          <div>
            <h2 className="text-base font-semibold text-white">Add Azure Cloud Account</h2>
            <p className="mt-0.5 text-xs text-gray-500">
              Service Principal credentials for one Azure subscription. The SP needs at least the Reader role on the target subscription.
            </p>
          </div>
          <button onClick={onClose} className="text-gray-500 hover:text-gray-200"><X className="h-4 w-4" /></button>
        </div>

        <div className="space-y-3">
          <Field label="Display name" hint="e.g. 'Production Azure'">
            <input
              className="w-full rounded bg-gray-800 px-3 py-2 text-sm text-gray-200 placeholder-gray-500 focus:outline-none focus:ring-1 focus:ring-indigo-500"
              placeholder="Production Azure"
              value={displayName}
              onChange={(e) => setDisplayName(e.target.value)}
            />
          </Field>
          <Field label="Tenant ID" hint="Entra ID directory (tenant) GUID">
            <input
              className="w-full rounded bg-gray-800 px-3 py-2 font-mono text-xs text-gray-200 placeholder-gray-500 focus:outline-none focus:ring-1 focus:ring-indigo-500"
              placeholder="00000000-0000-0000-0000-000000000000"
              value={tenantId}
              onChange={(e) => setTenantId(e.target.value)}
            />
          </Field>
          <Field label="Service Principal client ID" hint="The SP application (client) ID">
            <input
              className="w-full rounded bg-gray-800 px-3 py-2 font-mono text-xs text-gray-200 placeholder-gray-500 focus:outline-none focus:ring-1 focus:ring-indigo-500"
              placeholder="00000000-0000-0000-0000-000000000000"
              value={azureClientId}
              onChange={(e) => setAzureClientId(e.target.value)}
            />
          </Field>
          <Field label="Subscription ID" hint="Single subscription scope for Slice A">
            <input
              className="w-full rounded bg-gray-800 px-3 py-2 font-mono text-xs text-gray-200 placeholder-gray-500 focus:outline-none focus:ring-1 focus:ring-indigo-500"
              placeholder="00000000-0000-0000-0000-000000000000"
              value={subscriptionId}
              onChange={(e) => setSubscriptionId(e.target.value)}
            />
          </Field>
          <Field label="Client secret" hint="Encrypted at rest with AES-256-GCM; never returned to the client">
            <input
              type="password"
              className="w-full rounded bg-gray-800 px-3 py-2 font-mono text-xs text-gray-200 placeholder-gray-500 focus:outline-none focus:ring-1 focus:ring-indigo-500"
              placeholder="••••••••"
              value={clientSecret}
              onChange={(e) => setClientSecret(e.target.value)}
            />
          </Field>
        </div>

        {testResult && <TestConnectionBanner result={testResult} />}

        <div className="mt-5 flex items-center justify-end gap-2">
          <button onClick={onClose} className="rounded px-3 py-1.5 text-sm text-gray-400 hover:text-gray-200">Cancel</button>
          <button
            onClick={() => test.mutate()}
            disabled={!allFilled || test.isPending}
            className="rounded border border-gray-600 px-3 py-1.5 text-sm text-gray-200 hover:bg-gray-800 disabled:opacity-50"
            title="Validate credentials against Azure before saving"
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

function EditCloudAccountModal({ account, onClose }: { account: CloudAccountListItem; onClose: () => void }) {
  const [displayName,    setDisplayName]    = useState(account.displayName);
  const [tenantId,       setTenantId]       = useState(account.tenantId ?? "");
  const [azureClientId,  setAzureClientId]  = useState(account.azureClientId ?? "");
  const [subscriptionId, setSubscriptionId] = useState(account.subscriptionId ?? "");
  // Empty = don't rotate; non-empty triggers a re-encryption server-side.
  const [clientSecret,   setClientSecret]   = useState("");

  const qc = useQueryClient();
  const { toast } = useToast();

  const save = useMutation({
    mutationFn: () => cloudAccountsApi.update(account.id, {
      displayName:    displayName    !== account.displayName    ? displayName    : undefined,
      tenantId:       tenantId       !== account.tenantId       ? tenantId       : undefined,
      azureClientId:  azureClientId  !== account.azureClientId  ? azureClientId  : undefined,
      subscriptionId: subscriptionId !== account.subscriptionId ? subscriptionId : undefined,
      clientSecret:   clientSecret || undefined,
    }),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ["cloud-accounts"] });
      toast.success(clientSecret ? "Cloud account updated (credentials rotated)" : "Cloud account updated");
      onClose();
    },
    onError: (e: Error) => toast.error(e.message ?? "Failed to update"),
  });

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/60 px-4">
      <div className="w-full max-w-xl rounded-xl border border-gray-700 bg-gray-900 p-6 shadow-2xl">
        <div className="mb-4 flex items-center justify-between">
          <h2 className="text-base font-semibold text-white">Edit Cloud Account</h2>
          <button onClick={onClose} className="text-gray-500 hover:text-gray-200"><X className="h-4 w-4" /></button>
        </div>
        <div className="space-y-3">
          <Field label="Display name">
            <input className="w-full rounded bg-gray-800 px-3 py-2 text-sm text-gray-200" value={displayName} onChange={(e) => setDisplayName(e.target.value)} />
          </Field>
          <Field label="Tenant ID">
            <input className="w-full rounded bg-gray-800 px-3 py-2 font-mono text-xs text-gray-200" value={tenantId} onChange={(e) => setTenantId(e.target.value)} />
          </Field>
          <Field label="Client ID">
            <input className="w-full rounded bg-gray-800 px-3 py-2 font-mono text-xs text-gray-200" value={azureClientId} onChange={(e) => setAzureClientId(e.target.value)} />
          </Field>
          <Field label="Subscription ID">
            <input className="w-full rounded bg-gray-800 px-3 py-2 font-mono text-xs text-gray-200" value={subscriptionId} onChange={(e) => setSubscriptionId(e.target.value)} />
          </Field>
          <Field label="Rotate client secret" hint="Leave blank to keep the existing secret">
            <input type="password" className="w-full rounded bg-gray-800 px-3 py-2 font-mono text-xs text-gray-200" placeholder="•••••••• (unchanged)" value={clientSecret} onChange={(e) => setClientSecret(e.target.value)} />
          </Field>
        </div>
        <div className="mt-5 flex items-center justify-end gap-2">
          <button onClick={onClose} className="rounded px-3 py-1.5 text-sm text-gray-400 hover:text-gray-200">Cancel</button>
          <button onClick={() => save.mutate()} disabled={save.isPending} className="rounded bg-indigo-700 px-4 py-1.5 text-sm font-medium text-white hover:bg-indigo-600 disabled:opacity-50">
            {save.isPending ? "Saving…" : "Save"}
          </button>
        </div>
      </div>
    </div>
  );
}

// ── Test-connection feedback ────────────────────────────────────────────

function TestConnectionBanner({ result }: { result: TestConnectionResult }) {
  if (result.ok) {
    return (
      <div className="mt-4 flex items-start gap-2 rounded border border-emerald-700/60 bg-emerald-950/30 p-3 text-xs text-emerald-200">
        <CheckCircle2 className="mt-0.5 h-4 w-4 shrink-0" />
        <div>
          <div className="font-semibold">Credentials valid</div>
          <div className="mt-0.5 text-emerald-300/80">
            Subscription <span className="font-mono">{result.subscription.name}</span> ({result.subscription.state}) is reachable.
          </div>
        </div>
      </div>
    );
  }
  return (
    <div className="mt-4 flex items-start gap-2 rounded border border-red-700/60 bg-red-950/30 p-3 text-xs text-red-200">
      <AlertTriangle className="mt-0.5 h-4 w-4 shrink-0" />
      <div>
        <div className="font-semibold">{
          result.code === "invalid_client"          ? "Invalid Service Principal credentials" :
          result.code === "subscription_not_found" ? "Subscription not visible to this SP"  :
          result.code === "network"                ? "Network error contacting Azure"        :
                                                     "Connection test failed"
        }</div>
        <div className="mt-0.5 text-red-300/80">{result.message}</div>
      </div>
    </div>
  );
}

// ── Field wrapper ───────────────────────────────────────────────────────

function Field({ label, hint, children }: { label: string; hint?: string; children: React.ReactNode }) {
  return (
    <div>
      <label className="mb-1 block text-xs font-medium text-gray-300">{label}</label>
      {children}
      {hint && <p className="mt-1 text-[11px] text-gray-500">{hint}</p>}
    </div>
  );
}

// ── Per-row test-connection button ──────────────────────────────────────

function TestConnectionButton({ accountId }: { accountId: string }) {
  const qc = useQueryClient();
  const { toast } = useToast();
  const test = useMutation({
    mutationFn: () => cloudAccountsApi.testConnection(accountId),
    onSuccess: (r) => {
      qc.invalidateQueries({ queryKey: ["cloud-accounts"] });
      if (r.ok) toast.success(`Reachable: ${r.subscription.name}`);
      else      toast.error(r.message);
    },
    onError: (e: Error) => toast.error(e.message ?? "Test failed"),
  });
  return (
    <button
      onClick={() => test.mutate()}
      disabled={test.isPending}
      className="flex items-center gap-1.5 rounded border border-gray-700 px-2.5 py-1 text-xs text-gray-300 hover:bg-gray-800 disabled:opacity-50"
      title="Validate credentials against Azure"
    >
      <RefreshCw className={`h-3 w-3 ${test.isPending ? "animate-spin" : ""}`} />
      Test
    </button>
  );
}

// ── Main page ───────────────────────────────────────────────────────────

export default function CloudAccountsPage() {
  const [showAdd,    setShowAdd]    = useState(false);
  const [editTarget, setEditTarget] = useState<CloudAccountListItem | null>(null);

  const { data: accounts, isLoading } = useQuery({
    queryKey: ["cloud-accounts"],
    queryFn:  cloudAccountsApi.list,
  });

  const qc = useQueryClient();
  const { toast } = useToast();
  const del = useMutation({
    mutationFn: (id: string) => cloudAccountsApi.delete(id),
    onSuccess:  () => {
      qc.invalidateQueries({ queryKey: ["cloud-accounts"] });
      toast.success("Cloud account deleted");
    },
  });

  return (
    <div className="p-6">
      <div className="mb-6 flex items-start justify-between">
        <div>
          <h1 className="text-xl font-semibold text-white">Cloud accounts</h1>
          <p className="mt-1 text-xs text-gray-500">
            CSPM targets — one cloud-provider scope per account. Slice A: Azure subscriptions via Service Principal.
          </p>
        </div>
        <Can role="DEVELOPER">
          <button
            onClick={() => setShowAdd(true)}
            className="flex items-center gap-1.5 rounded bg-indigo-700 px-3 py-1.5 text-sm font-medium text-white hover:bg-indigo-600"
          >
            <Plus className="h-4 w-4" /> Add Azure Account
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
                <th className="px-4 py-2 text-left">Subscription</th>
                <th className="px-4 py-2 text-left">Tenant</th>
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
                      <Cloud className="h-4 w-4 text-indigo-400" />
                      <div>
                        <div className="font-medium text-gray-100">{a.displayName}</div>
                        <div className="text-[10px] uppercase tracking-wide text-gray-500">{a.provider}</div>
                      </div>
                    </div>
                  </td>
                  <td className="px-4 py-3 font-mono text-xs text-gray-300">{maskGuid(a.subscriptionId)}</td>
                  <td className="px-4 py-3 font-mono text-xs text-gray-400">{maskGuid(a.tenantId)}</td>
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
                            if (confirm(`Delete "${a.displayName}"? This cascades to all CSPM findings on this account.`)) {
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

      {showAdd      && <AddCloudAccountModal  onClose={() => setShowAdd(false)} />}
      {editTarget   && <EditCloudAccountModal account={editTarget} onClose={() => setEditTarget(null)} />}
    </div>
  );
}

function EmptyState({ onAdd }: { onAdd: () => void }) {
  return (
    <div className="rounded-xl border border-dashed border-gray-800 bg-gray-900/30 p-10 text-center">
      <Cloud className="mx-auto h-10 w-10 text-gray-600" />
      <h2 className="mt-3 text-base font-semibold text-white">No cloud accounts yet</h2>
      <p className="mx-auto mt-1 max-w-sm text-xs text-gray-500">
        Add an Azure subscription with a Service Principal that has at least the Reader role.
        BreachLens will evaluate it against the CSPM ruleset on each scan.
      </p>
      <Can role="DEVELOPER">
        <button
          onClick={onAdd}
          className="mt-4 inline-flex items-center gap-1.5 rounded bg-indigo-700 px-3 py-1.5 text-sm font-medium text-white hover:bg-indigo-600"
        >
          <Plus className="h-4 w-4" /> Add Azure Account
        </button>
      </Can>
    </div>
  );
}
