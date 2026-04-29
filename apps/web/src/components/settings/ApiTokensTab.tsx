/**
 * ApiTokensTab — Phase A4 CI integration UI.
 *
 * Lets ADMIN+ operators mint, list, and revoke long-lived bearer tokens
 * for non-interactive callers (CI pipelines, the breachlens CLI,
 * scripts). Replaces the awkward "extract a session cookie from
 * DevTools" pattern that Phase A1-A3's GitHub Action shipped with.
 *
 * UI flow for minting:
 *   1. Operator clicks "Generate token"
 *   2. Modal collects: name + scopes + expiry
 *   3. POST /auth/tokens returns plaintext ONCE
 *   4. Modal switches to "copy this token" panel with one-click copy
 *      and an explicit "I have saved this" button — won't dismiss until
 *      acknowledged (the plaintext is unrecoverable after dismissal)
 *
 * Scope picker uses checkbox-style multi-select with descriptions —
 * operators choosing scopes need to know what each one unlocks
 * ("scans:trigger" alone is enough for a CI gate workflow).
 */
import { useState } from "react";
import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import { Key, Plus, Trash2, Copy, Check, X, Calendar, Clock } from "lucide-react";
import { apiTokensApi, type ApiToken, type MintTokenResponse } from "../../lib/api";
import { useToast } from "../../hooks/useToast";
import { formatRelative } from "../../lib/utils";

const SCOPE_DESCRIPTIONS: Record<string, string> = {
  "scans:trigger": "POST scan triggers (repos / containers / domains)",
  "scans:read":    "Read scan status + SARIF export",
  "findings:read": "Read findings + filters + summary stats",
};

const EXPIRY_OPTIONS: Array<{ label: string; days: number | null }> = [
  { label: "30 days",  days: 30 },
  { label: "90 days",  days: 90 },
  { label: "180 days", days: 180 },
  { label: "1 year",   days: 365 },
  { label: "Never",    days: null },
];

export default function ApiTokensTab() {
  const qc = useQueryClient();
  const { toast } = useToast();
  const [showMint, setShowMint] = useState(false);
  const [justMinted, setJustMinted] = useState<MintTokenResponse | null>(null);

  const { data, isLoading } = useQuery({
    queryKey: ["api-tokens"],
    queryFn:  apiTokensApi.list,
  });

  const revoke = useMutation({
    mutationFn: (id: string) => apiTokensApi.revoke(id, false),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ["api-tokens"] });
      toast.success("Token revoked");
    },
    onError: (err: Error) => toast.error(err.message || "Revoke failed"),
  });

  const tokens = data?.tokens ?? [];
  const allScopes = data?.allScopes ?? Object.keys(SCOPE_DESCRIPTIONS);
  const activeCount  = tokens.filter((t) => !t.revokedAt).length;
  const revokedCount = tokens.length - activeCount;

  return (
    <div className="space-y-5">
      {/* Header */}
      <div className="flex items-start justify-between">
        <div>
          <div className="flex items-center gap-2">
            <Key className="h-4 w-4 text-indigo-400" />
            <h2 className="text-base font-semibold text-white">API tokens</h2>
          </div>
          <p className="mt-1 text-xs text-gray-400">
            Long-lived bearer tokens for CI pipelines, the BreachLens CLI, and
            other non-interactive callers. Each token authenticates as the user
            who minted it, scoped to this organisation.
          </p>
        </div>
        <button
          onClick={() => { setShowMint(true); setJustMinted(null); }}
          className="flex items-center gap-2 rounded-lg bg-indigo-700 px-3 py-2 text-sm font-medium text-white hover:bg-indigo-600"
        >
          <Plus className="h-4 w-4" />
          Generate token
        </button>
      </div>

      {/* Counts strip */}
      {tokens.length > 0 && (
        <div className="flex gap-3 text-xs">
          <span className="rounded border border-indigo-800/60 bg-indigo-950/30 px-2 py-1 text-indigo-200">
            {activeCount} active
          </span>
          {revokedCount > 0 && (
            <span className="rounded border border-gray-700/60 bg-gray-800/40 px-2 py-1 text-gray-400">
              {revokedCount} revoked
            </span>
          )}
        </div>
      )}

      {/* Table */}
      {isLoading ? (
        <div className="flex h-32 items-center justify-center text-gray-500">Loading…</div>
      ) : tokens.length === 0 ? (
        <div className="flex h-48 flex-col items-center justify-center gap-3 rounded-lg border border-dashed border-gray-800 bg-gray-900/30 text-gray-500">
          <Key className="h-8 w-8" />
          <p className="text-sm">No API tokens yet.</p>
          <p className="max-w-xs text-center text-xs text-gray-600">
            Generate a token to use the BreachLens GitHub Action, the
            <span className="font-mono"> breachlens</span> CLI, or any
            scripted access to <span className="font-mono">/api/...</span>.
          </p>
        </div>
      ) : (
        <div className="overflow-x-auto rounded-lg border border-gray-800">
          <table className="w-full text-sm">
            <thead className="border-b border-gray-800 bg-gray-900">
              <tr className="text-left text-xs text-gray-500">
                <th className="px-3 py-3 font-medium">Name</th>
                <th className="px-3 py-3 font-medium">Token</th>
                <th className="px-3 py-3 font-medium">Scopes</th>
                <th className="px-3 py-3 font-medium">Created by</th>
                <th className="px-3 py-3 font-medium">Last used</th>
                <th className="px-3 py-3 font-medium">Expires</th>
                <th className="px-3 py-3 font-medium" aria-label="Actions"></th>
              </tr>
            </thead>
            <tbody className="divide-y divide-gray-800 bg-gray-900/50">
              {tokens.map((t) => <TokenRow key={t.id} token={t} onRevoke={() => revoke.mutate(t.id)} />)}
            </tbody>
          </table>
        </div>
      )}

      {/* Mint modal */}
      {showMint && (
        <MintModal
          allScopes={allScopes}
          justMinted={justMinted}
          onMinted={(r) => {
            setJustMinted(r);
            qc.invalidateQueries({ queryKey: ["api-tokens"] });
          }}
          onClose={() => { setShowMint(false); setJustMinted(null); }}
        />
      )}
    </div>
  );
}

// ── Row ──────────────────────────────────────────────────────────────────

function TokenRow({ token, onRevoke }: { token: ApiToken; onRevoke: () => void }) {
  const isRevoked = !!token.revokedAt;
  const isExpired = !!token.expiresAt && new Date(token.expiresAt) < new Date();
  const status = isRevoked ? "revoked" : isExpired ? "expired" : "active";

  return (
    <tr className={`hover:bg-gray-800/40 ${isRevoked || isExpired ? "opacity-50" : ""}`}>
      <td className="px-3 py-2.5">
        <div className="flex items-center gap-2">
          <span className="text-gray-200">{token.name}</span>
          {status !== "active" && (
            <span className="rounded border border-gray-700/60 bg-gray-800 px-1.5 py-0.5 text-[10px] uppercase text-gray-400">
              {status}
            </span>
          )}
        </div>
      </td>
      <td className="px-3 py-2.5 font-mono text-xs text-gray-400">
        {token.prefix}<span className="opacity-60">…</span>
      </td>
      <td className="px-3 py-2.5">
        <div className="flex flex-wrap gap-1">
          {token.scopes.map((s) => (
            <span
              key={s}
              className="rounded border border-indigo-900/50 bg-indigo-950/30 px-1.5 py-0.5 text-[10px] font-mono text-indigo-300"
            >
              {s}
            </span>
          ))}
        </div>
      </td>
      <td className="px-3 py-2.5 text-xs text-gray-400">{token.createdBy.username}</td>
      <td className="px-3 py-2.5 text-xs text-gray-400">
        {token.lastUsedAt ? formatRelative(token.lastUsedAt) : <span className="italic text-gray-600">never</span>}
      </td>
      <td className="px-3 py-2.5 text-xs text-gray-400">
        {token.expiresAt ? formatRelative(token.expiresAt) : <span className="italic text-gray-600">never</span>}
      </td>
      <td className="px-3 py-2.5 text-right">
        {!isRevoked && (
          <button
            onClick={() => {
              if (confirm(`Revoke token "${token.name}"? This cannot be undone — any CI pipeline using it will start failing.`)) {
                onRevoke();
              }
            }}
            className="text-gray-500 hover:text-red-400"
            title="Revoke token"
          >
            <Trash2 className="h-4 w-4" />
          </button>
        )}
      </td>
    </tr>
  );
}

// ── Mint modal ───────────────────────────────────────────────────────────

function MintModal({
  allScopes, justMinted, onMinted, onClose,
}: {
  allScopes:  string[];
  justMinted: MintTokenResponse | null;
  onMinted:   (r: MintTokenResponse) => void;
  onClose:    () => void;
}) {
  const { toast } = useToast();
  const [name,   setName]   = useState("");
  const [scopes, setScopes] = useState<Set<string>>(new Set(["scans:trigger", "scans:read", "findings:read"]));
  const [expiryDays, setExpiryDays] = useState<number | null>(90);
  const [copied, setCopied] = useState(false);

  const mint = useMutation({
    mutationFn: () => {
      const expiresAt = expiryDays === null
        ? null
        : new Date(Date.now() + expiryDays * 24 * 3600 * 1000).toISOString();
      return apiTokensApi.mint({ name: name.trim(), scopes: [...scopes], expiresAt });
    },
    onSuccess: (r) => onMinted(r),
    onError:   (err: Error) => toast.error(err.message || "Mint failed"),
  });

  function copyToken() {
    if (!justMinted) return;
    navigator.clipboard.writeText(justMinted.token).then(() => {
      setCopied(true);
      setTimeout(() => setCopied(false), 2000);
    });
  }

  function toggleScope(s: string) {
    const next = new Set(scopes);
    if (next.has(s)) next.delete(s); else next.add(s);
    setScopes(next);
  }

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/60">
      <div className="w-full max-w-xl rounded-xl border border-gray-700 bg-gray-900 p-6 shadow-2xl">
        <div className="mb-4 flex items-center justify-between">
          <h2 className="text-base font-semibold text-white">
            {justMinted ? "Token created — copy it now" : "Generate API token"}
          </h2>
          <button onClick={onClose} className="text-gray-500 hover:text-gray-200">
            <X className="h-4 w-4" />
          </button>
        </div>

        {justMinted ? (
          // ── Plaintext-reveal panel ─────────────────────────────────
          <div className="space-y-4">
            <div className="rounded-lg border border-indigo-900/40 bg-indigo-950/20 p-3">
              <div className="flex items-start gap-2">
                <Key className="mt-0.5 h-4 w-4 flex-shrink-0 text-indigo-400" />
                <p className="text-xs text-indigo-200">
                  This is the only time you'll see this token. Copy it now and store it
                  somewhere safe (your GitHub secret, password manager, etc.).
                </p>
              </div>
            </div>

            <div>
              <label className="mb-1 block text-xs text-gray-400">Token</label>
              <div className="flex gap-2">
                <input
                  type="text"
                  readOnly
                  value={justMinted.token}
                  className="flex-1 rounded border border-gray-700 bg-gray-950 px-3 py-2 font-mono text-xs text-gray-200"
                  onFocus={(e) => e.currentTarget.select()}
                />
                <button
                  onClick={copyToken}
                  className="flex items-center gap-1.5 rounded border border-gray-700 bg-gray-800 px-3 py-2 text-xs text-gray-300 hover:border-indigo-600 hover:text-indigo-300"
                >
                  {copied ? <Check className="h-3 w-3 text-emerald-400" /> : <Copy className="h-3 w-3" />}
                  {copied ? "Copied" : "Copy"}
                </button>
              </div>
            </div>

            <div className="rounded border border-gray-800 bg-gray-950 p-3 font-mono text-[11px] text-gray-300">
              <div className="mb-1 text-[10px] uppercase text-gray-500">Quick test</div>
              curl -H "Authorization: Bearer {justMinted.token.slice(0, 12)}…" \<br />
              {"  "}https://your-breachlens/api/scans?limit=1
            </div>

            <div className="flex justify-end">
              <button
                onClick={onClose}
                className="rounded bg-indigo-700 px-4 py-2 text-sm font-medium text-white hover:bg-indigo-600"
              >
                I've saved the token
              </button>
            </div>
          </div>
        ) : (
          // ── Mint form ─────────────────────────────────────────────
          <form
            onSubmit={(e) => { e.preventDefault(); mint.mutate(); }}
            className="space-y-4"
          >
            <div>
              <label className="mb-1 block text-xs text-gray-400">Name</label>
              <input
                type="text"
                value={name}
                onChange={(e) => setName(e.target.value)}
                placeholder="e.g. GitHub Actions for myrepo"
                required
                maxLength={120}
                className="w-full rounded border border-gray-700 bg-gray-950 px-3 py-2 text-sm text-gray-200 placeholder-gray-600 focus:border-indigo-600 focus:outline-none"
              />
              <p className="mt-1 text-[10px] text-gray-500">
                Operator-facing label so you can identify this token later.
              </p>
            </div>

            <div>
              <label className="mb-1.5 block text-xs text-gray-400">Scopes</label>
              <div className="space-y-1.5">
                {allScopes.map((s) => (
                  <label
                    key={s}
                    className="flex cursor-pointer items-start gap-2 rounded border border-gray-800 bg-gray-950 px-3 py-2 hover:border-gray-700"
                  >
                    <input
                      type="checkbox"
                      checked={scopes.has(s)}
                      onChange={() => toggleScope(s)}
                      className="mt-0.5 h-3.5 w-3.5 rounded border-gray-600 bg-gray-800 text-indigo-600 focus:ring-1 focus:ring-indigo-500"
                    />
                    <div className="min-w-0">
                      <div className="font-mono text-xs text-gray-200">{s}</div>
                      <div className="text-[11px] text-gray-500">
                        {SCOPE_DESCRIPTIONS[s] ?? "—"}
                      </div>
                    </div>
                  </label>
                ))}
              </div>
            </div>

            <div>
              <label className="mb-1.5 block text-xs text-gray-400">Expires</label>
              <div className="flex flex-wrap gap-1.5">
                {EXPIRY_OPTIONS.map((opt) => (
                  <button
                    key={opt.label}
                    type="button"
                    onClick={() => setExpiryDays(opt.days)}
                    className={`flex items-center gap-1.5 rounded border px-2.5 py-1 text-xs ${
                      expiryDays === opt.days
                        ? "border-indigo-700/60 bg-indigo-950/40 text-indigo-200"
                        : "border-gray-700 bg-gray-800 text-gray-300 hover:border-indigo-600"
                    }`}
                  >
                    {opt.days === null ? <Calendar className="h-3 w-3" /> : <Clock className="h-3 w-3" />}
                    {opt.label}
                  </button>
                ))}
              </div>
            </div>

            <div className="flex justify-end gap-2 pt-2">
              <button
                type="button"
                onClick={onClose}
                className="rounded px-3 py-2 text-sm text-gray-400 hover:text-gray-200"
              >
                Cancel
              </button>
              <button
                type="submit"
                disabled={mint.isPending || !name.trim() || scopes.size === 0}
                className="rounded bg-indigo-700 px-4 py-2 text-sm font-medium text-white hover:bg-indigo-600 disabled:cursor-not-allowed disabled:opacity-50"
              >
                {mint.isPending ? "Generating…" : "Generate token"}
              </button>
            </div>
          </form>
        )}
      </div>
    </div>
  );
}
