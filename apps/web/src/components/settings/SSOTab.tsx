/**
 * SSO (OIDC) configuration tab.
 *
 * Phase 22 PR 3 Slice A: lets ADMIN+ configure an OIDC IdP for the org.
 * Slice B (next session) wires up the actual passport-openidconnect login
 * flow that consumes this config. Until then, saved configs are dormant —
 * the UI reflects this with a "OIDC login lands in Slice B" notice.
 *
 * Test-connection button hits the IdP's /.well-known/openid-configuration
 * to validate the issuer URL before save. No clientId/clientSecret check —
 * those only get exercised on a real login.
 */
import { useState, useEffect } from "react";
import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import {
  KeyRound, Loader2, Check, AlertCircle, Trash2, Info, Plug, Plus, X,
} from "lucide-react";
import { ssoApi, type MemberRole, type SsoUpsert, type SsoTestResult } from "../../lib/api";
import { useToast } from "../../hooks/useToast";

const ROLES: MemberRole[] = ["OWNER", "ADMIN", "SECURITY", "DEVELOPER", "VIEWER"];

// Provider presets — pre-fill issuer URL placeholder + show provider-specific
// setup notes. These are guidance only; the actual config is generic OIDC.
type ProviderPreset = "generic" | "entra" | "okta" | "auth0" | "google" | "keycloak";

const PROVIDER_PRESETS: Record<ProviderPreset, {
  label:           string;
  issuerTemplate:  string;
  notes:           string[];
}> = {
  generic: {
    label:          "Generic OIDC",
    issuerTemplate: "https://your-idp.example.com",
    notes: [
      "Any standards-compliant OIDC IdP works. Discovery happens at <issuerUrl>/.well-known/openid-configuration.",
    ],
  },
  entra: {
    label:          "Microsoft Entra ID (Azure AD)",
    issuerTemplate: "https://login.microsoftonline.com/<tenant-id>/v2.0",
    notes: [
      "Register an app at Azure Portal → Microsoft Entra ID → App registrations → New registration.",
      "Set Redirect URI to your /auth/sso/callback URL.",
      "Add a Client Secret under Certificates & secrets — copy the VALUE (not the secret ID).",
      "Token configuration → Optional claims → emit 'groups' as 'sam_account_name' (otherwise groups arrive as opaque GUIDs).",
      "Use '/common/v2.0' instead of '<tenant-id>/v2.0' to accept any Microsoft account (multi-tenant).",
      "Users in ≥150 groups: the IdP returns a _claim_names indirection that we can't expand without Graph API access — those users fall back to the default role.",
    ],
  },
  okta: {
    label:          "Okta",
    issuerTemplate: "https://<your-tenant>.okta.com/oauth2/default",
    notes: [
      "Applications → Create App Integration → OIDC + Web Application.",
      "Sign-in redirect URIs: your /auth/sso/callback URL.",
      "Assignments → Allow your users + grant groups claim via the default authorization server's claim editor.",
    ],
  },
  auth0: {
    label:          "Auth0",
    issuerTemplate: "https://<your-tenant>.auth0.com",
    notes: [
      "Applications → Create Application → Regular Web Application.",
      "Allowed Callback URLs: your /auth/sso/callback URL.",
      "Auth0 doesn't include a 'groups' claim by default — add a custom Action to inject one if you want group → role mapping.",
    ],
  },
  google: {
    label:          "Google Workspace",
    issuerTemplate: "https://accounts.google.com",
    notes: [
      "Cloud Console → APIs & Services → Credentials → OAuth 2.0 Client IDs → Web Application.",
      "Authorized redirect URIs: your /auth/sso/callback URL.",
      "⚠ Google does NOT include groups in OIDC claims. All users get the default role unless you build a Directory API integration on top.",
    ],
  },
  keycloak: {
    label:          "Keycloak",
    issuerTemplate: "https://<your-keycloak>/realms/<realm-name>",
    notes: [
      "Clients → Create → Client type: openid-connect, Confidential.",
      "Valid redirect URIs: your /auth/sso/callback URL.",
      "Client scopes → groups → Mappers: add a 'Group Membership' mapper, set Token Claim Name = 'groups', Full group path = OFF.",
    ],
  },
};

interface FormState {
  issuerUrl:           string;
  clientId:            string;
  clientSecret:        string;       // blank when not re-entering on update
  allowedEmailDomains: string[];
  groupRoleMapping:    Record<string, MemberRole>;
  defaultRole:         MemberRole;
  isActive:            boolean;
}

const EMPTY_FORM: FormState = {
  issuerUrl:           "",
  clientId:            "",
  clientSecret:        "",
  allowedEmailDomains: [],
  groupRoleMapping:    {},
  defaultRole:         "DEVELOPER",
  isActive:            true,
};

export default function SSOTab() {
  const qc      = useQueryClient();
  const { toast } = useToast();

  const { data: existing } = useQuery({
    queryKey: ["sso"],
    queryFn:  ssoApi.get,
  });

  const [form, setForm] = useState<FormState>(EMPTY_FORM);
  const [domainInput, setDomainInput] = useState("");
  const [groupInput, setGroupInput]   = useState("");
  const [groupRole, setGroupRole]     = useState<MemberRole>("DEVELOPER");
  const [testResult, setTestResult]   = useState<SsoTestResult | null>(null);
  // Provider preset is local-only — guidance for the form, not persisted.
  // Detect from existing issuerUrl when hydrating, default to "generic".
  const [provider, setProvider] = useState<ProviderPreset>("generic");

  // Hydrate form from existing config when it loads. Also infer the provider
  // preset from the issuer URL so the right guidance shows for already-saved
  // configs.
  useEffect(() => {
    if (existing) {
      setForm({
        issuerUrl:           existing.issuerUrl,
        clientId:            existing.clientId,
        clientSecret:        "",   // never echo
        allowedEmailDomains: existing.allowedEmailDomains,
        groupRoleMapping:    existing.groupRoleMapping,
        defaultRole:         existing.defaultRole,
        isActive:            existing.isActive,
      });
      setProvider(detectProvider(existing.issuerUrl));
    }
  }, [existing]);

  const save = useMutation({
    mutationFn: () => {
      const payload: SsoUpsert = {
        issuerUrl:           form.issuerUrl.trim(),
        clientId:            form.clientId.trim(),
        allowedEmailDomains: form.allowedEmailDomains,
        groupRoleMapping:    form.groupRoleMapping,
        defaultRole:         form.defaultRole,
        isActive:            form.isActive,
      };
      // Only send clientSecret when the user typed one — preserves existing
      // encrypted value on update.
      if (form.clientSecret) payload.clientSecret = form.clientSecret;
      return ssoApi.save(payload);
    },
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ["sso"] });
      toast.success("SSO configuration saved");
      setForm((f) => ({ ...f, clientSecret: "" }));   // wipe input after save
    },
    onError: (err: Error & { response?: { data?: { error?: string } } }) => {
      toast.error(err.response?.data?.error ?? err.message);
    },
  });

  const remove = useMutation({
    mutationFn: ssoApi.remove,
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ["sso"] });
      toast.info("SSO configuration removed");
      setForm(EMPTY_FORM);
      setTestResult(null);
    },
    onError: (err: Error) => toast.error(err.message),
  });

  const test = useMutation({
    mutationFn: () => ssoApi.test(form.issuerUrl.trim()),
    onSuccess: (data) => {
      setTestResult(data);
      if (data.ok) toast.success(`Discovery OK (${data.latencyMs}ms)`);
    },
    onError: (err: Error & { response?: { data?: SsoTestResult } }) => {
      const data = err.response?.data;
      if (data) setTestResult(data);
      toast.error(data?.message ?? err.message);
    },
  });

  function addDomain() {
    const v = domainInput.trim().toLowerCase();
    if (!v) return;
    if (!/^[a-z0-9.-]+$/.test(v)) {
      toast.error("Invalid domain — letters, digits, dots, hyphens only");
      return;
    }
    if (form.allowedEmailDomains.includes(v)) return;
    setForm((f) => ({ ...f, allowedEmailDomains: [...f.allowedEmailDomains, v] }));
    setDomainInput("");
  }

  function removeDomain(d: string) {
    setForm((f) => ({ ...f, allowedEmailDomains: f.allowedEmailDomains.filter((x) => x !== d) }));
  }

  function addGroupMapping() {
    const k = groupInput.trim();
    if (!k) return;
    setForm((f) => ({ ...f, groupRoleMapping: { ...f.groupRoleMapping, [k]: groupRole } }));
    setGroupInput("");
  }

  function removeGroupMapping(k: string) {
    setForm((f) => {
      const m = { ...f.groupRoleMapping };
      delete m[k];
      return { ...f, groupRoleMapping: m };
    });
  }

  const isConfigured = !!existing;

  return (
    <div className="space-y-6">
      {/* ── Header ─────────────────────────────────────────────────────────── */}
      <header className="flex items-start justify-between">
        <div>
          <h2 className="flex items-center gap-2 text-base font-semibold text-white">
            <KeyRound className="h-4 w-4 text-indigo-400" />
            Single Sign-On (OIDC)
          </h2>
          <p className="mt-1 text-xs text-gray-400">
            Configure an OpenID Connect identity provider — Okta, Azure AD, Google Workspace, Auth0, Keycloak.
          </p>
        </div>
        {isConfigured && (
          <span className="rounded-full bg-indigo-900/40 border border-indigo-800/40 px-2.5 py-0.5 text-xs text-indigo-300">
            {existing.isActive ? "Configured" : "Configured (disabled)"}
          </span>
        )}
      </header>

      {/* ── Slice-B-coming notice ──────────────────────────────────────────── */}
      <div className="flex items-start gap-2 rounded-md border border-indigo-900/40 bg-indigo-950/30 px-3 py-2 text-xs text-gray-300">
        <Info className="h-3.5 w-3.5 mt-0.5 shrink-0 text-indigo-400" />
        <div className="leading-relaxed">
          <strong className="text-gray-100">Configuration only.</strong>{" "}
          The OIDC login flow (passport-openidconnect strategy + JIT user provisioning + group → role mapping)
          ships in the next slice. Saved configs are validated and stored encrypted but won't yet drive any login.
          Use this tab now to capture IdP details ahead of the rollout.
        </div>
      </div>

      {/* ── Form ───────────────────────────────────────────────────────────── */}
      <form
        onSubmit={(e) => { e.preventDefault(); save.mutate(); }}
        className="space-y-4"
      >
        {/* Provider preset — guidance only, not persisted. Selecting changes
            the issuer URL placeholder + reveals provider-specific setup notes. */}
        <div>
          <label className="mb-1.5 block text-xs font-medium text-gray-300">Provider</label>
          <p className="mb-2 text-xs text-gray-500">
            Select your IdP for setup guidance — saved config is generic OIDC.
          </p>
          <select
            value={provider}
            onChange={(e) => setProvider(e.target.value as ProviderPreset)}
            className="w-full rounded bg-gray-800 px-3 py-2 text-xs text-gray-200 focus:outline-none focus:ring-1 focus:ring-indigo-500"
          >
            {(Object.entries(PROVIDER_PRESETS) as [ProviderPreset, typeof PROVIDER_PRESETS["generic"]][]).map(
              ([key, p]) => <option key={key} value={key}>{p.label}</option>,
            )}
          </select>
          {provider !== "generic" && (
            <ul className="mt-2 space-y-1 rounded-md border border-gray-800 bg-gray-950/60 px-3 py-2 text-[11px] text-gray-400">
              {PROVIDER_PRESETS[provider].notes.map((n, i) => (
                <li key={i} className="flex items-start gap-1.5">
                  <span className="mt-1.5 h-1 w-1 shrink-0 rounded-full bg-indigo-400" />
                  <span className="leading-relaxed">{n}</span>
                </li>
              ))}
            </ul>
          )}
        </div>

        <Field
          label="Issuer URL"
          placeholder={PROVIDER_PRESETS[provider].issuerTemplate}
          help="OIDC discovery happens at <issuerUrl>/.well-known/openid-configuration"
          value={form.issuerUrl}
          onChange={(v) => setForm((f) => ({ ...f, issuerUrl: v }))}
        />
        <Field
          label="Client ID"
          placeholder="0oa1abc2def3GHI4jk5l"
          value={form.clientId}
          onChange={(v) => setForm((f) => ({ ...f, clientId: v }))}
        />
        <Field
          label={isConfigured ? "Client Secret (leave blank to keep existing)" : "Client Secret"}
          type="password"
          placeholder={isConfigured && existing?.clientSecretSet ? "***configured***" : "shhh"}
          value={form.clientSecret}
          onChange={(v) => setForm((f) => ({ ...f, clientSecret: v }))}
        />

        {/* ── Allowed email domains ─────────────────────────────────────── */}
        <div>
          <label className="mb-1.5 block text-xs font-medium text-gray-300">
            Allowed email domains
          </label>
          <p className="mb-2 text-xs text-gray-500">
            Users with these email domains can sign in via this SSO. Leave empty to accept any domain.
          </p>
          <div className="flex flex-wrap items-center gap-2 rounded border border-gray-800 bg-gray-950 px-2 py-1.5">
            {form.allowedEmailDomains.map((d) => (
              <span
                key={d}
                className="inline-flex items-center gap-1 rounded-full bg-indigo-900/40 px-2 py-0.5 text-xs text-indigo-200 ring-1 ring-indigo-800/60"
              >
                {d}
                <button
                  type="button"
                  onClick={() => removeDomain(d)}
                  className="text-indigo-400 hover:text-white"
                  aria-label={`Remove ${d}`}
                >
                  <X className="h-3 w-3" />
                </button>
              </span>
            ))}
            <input
              type="text"
              value={domainInput}
              placeholder="acme.com"
              onChange={(e) => setDomainInput(e.target.value)}
              onKeyDown={(e) => {
                if (e.key === "Enter" || e.key === ",") {
                  e.preventDefault();
                  addDomain();
                }
              }}
              className="flex-1 min-w-[120px] bg-transparent text-xs text-gray-200 placeholder:text-gray-600 focus:outline-none"
            />
            {domainInput && (
              <button
                type="button"
                onClick={addDomain}
                className="rounded p-0.5 text-indigo-300 hover:bg-indigo-900/30"
                aria-label="Add domain"
              >
                <Plus className="h-3 w-3" />
              </button>
            )}
          </div>
        </div>

        {/* ── Default role + active toggle ──────────────────────────────── */}
        <div className="grid grid-cols-2 gap-4">
          <div>
            <label className="mb-1.5 block text-xs font-medium text-gray-300">Default role</label>
            <p className="mb-2 text-xs text-gray-500">
              Assigned when no group claim matches the mapping below.
            </p>
            <select
              value={form.defaultRole}
              onChange={(e) => setForm((f) => ({ ...f, defaultRole: e.target.value as MemberRole }))}
              className="w-full rounded bg-gray-800 px-3 py-2 text-xs text-gray-200 focus:outline-none focus:ring-1 focus:ring-indigo-500"
            >
              {ROLES.map((r) => <option key={r} value={r}>{r}</option>)}
            </select>
          </div>
          <div>
            <label className="mb-1.5 block text-xs font-medium text-gray-300">Status</label>
            <p className="mb-2 text-xs text-gray-500">
              Disable to keep the config but stop accepting SSO logins.
            </p>
            <label className="inline-flex items-center gap-2 text-xs text-gray-300">
              <input
                type="checkbox"
                checked={form.isActive}
                onChange={(e) => setForm((f) => ({ ...f, isActive: e.target.checked }))}
                className="h-4 w-4 rounded border-gray-700 bg-gray-800 text-indigo-600 focus:ring-indigo-500"
              />
              Active
            </label>
          </div>
        </div>

        {/* ── Group → role mapping ──────────────────────────────────────── */}
        <div>
          <label className="mb-1.5 block text-xs font-medium text-gray-300">
            Group → role mapping
          </label>
          <p className="mb-2 text-xs text-gray-500">
            Map IdP group claim values to BreachLens roles. First match wins; falls back to the default role above.
          </p>
          <div className="space-y-1.5">
            {Object.entries(form.groupRoleMapping).map(([k, v]) => (
              <div key={k} className="flex items-center gap-2 rounded border border-gray-800 bg-gray-950 px-2 py-1">
                <code className="flex-1 font-mono text-xs text-indigo-300">{k}</code>
                <span className="text-gray-600">→</span>
                <span className="rounded bg-gray-800 px-2 py-0.5 font-mono text-xs text-gray-200">{v}</span>
                <button
                  type="button"
                  onClick={() => removeGroupMapping(k)}
                  className="rounded p-1 text-gray-500 hover:bg-red-950/40 hover:text-red-300"
                >
                  <X className="h-3 w-3" />
                </button>
              </div>
            ))}
          </div>
          <div className="mt-2 flex items-center gap-2">
            <input
              type="text"
              value={groupInput}
              onChange={(e) => setGroupInput(e.target.value)}
              placeholder="devsecops-admins"
              className="flex-1 rounded border border-gray-800 bg-gray-950 px-2 py-1.5 text-xs text-gray-200 placeholder:text-gray-600 focus:border-indigo-700 focus:outline-none"
            />
            <span className="text-gray-600">→</span>
            <select
              value={groupRole}
              onChange={(e) => setGroupRole(e.target.value as MemberRole)}
              className="rounded border border-gray-800 bg-gray-950 px-2 py-1.5 text-xs text-gray-200 focus:border-indigo-700 focus:outline-none"
            >
              {ROLES.map((r) => <option key={r} value={r}>{r}</option>)}
            </select>
            <button
              type="button"
              onClick={addGroupMapping}
              disabled={!groupInput.trim()}
              className="rounded border border-indigo-700/40 bg-indigo-900/20 px-2.5 py-1 text-xs font-medium text-indigo-300 hover:bg-indigo-900/40 disabled:opacity-40"
            >
              <Plus className="inline h-3 w-3" /> Add
            </button>
          </div>
        </div>

        {/* ── Action buttons ────────────────────────────────────────────── */}
        <div className="flex flex-wrap items-center gap-3 pt-1">
          <button
            type="button"
            onClick={() => test.mutate()}
            disabled={!form.issuerUrl.trim() || test.isPending}
            className="inline-flex items-center gap-1.5 rounded-md border border-gray-700 bg-gray-800 px-3 py-1.5 text-xs font-semibold text-gray-200 hover:bg-gray-700 disabled:cursor-not-allowed disabled:opacity-40"
          >
            {test.isPending ? <Loader2 className="h-3 w-3 animate-spin" /> : <Plug className="h-3 w-3" />}
            Test connection
          </button>
          <button
            type="submit"
            disabled={save.isPending || !form.issuerUrl.trim() || !form.clientId.trim()}
            className="inline-flex items-center gap-1.5 rounded-md bg-indigo-600 px-3 py-1.5 text-xs font-semibold text-white hover:bg-indigo-500 disabled:cursor-not-allowed disabled:opacity-40"
          >
            {save.isPending ? <Loader2 className="h-3 w-3 animate-spin" /> : <Check className="h-3 w-3" />}
            {isConfigured ? "Update configuration" : "Save configuration"}
          </button>
          {isConfigured && (
            <button
              type="button"
              onClick={() => {
                if (confirm("Remove SSO configuration? Existing GitHub OAuth users will be unaffected.")) {
                  remove.mutate();
                }
              }}
              disabled={remove.isPending}
              className="ml-auto inline-flex items-center gap-1.5 rounded-md border border-indigo-900/50 bg-indigo-950/30 px-3 py-1.5 text-xs font-semibold text-indigo-300 hover:bg-indigo-950/50 disabled:opacity-40"
            >
              <Trash2 className="h-3 w-3" />
              Remove
            </button>
          )}
        </div>

        {/* ── Test result panel ─────────────────────────────────────────── */}
        {testResult && <TestResultPanel result={testResult} />}
      </form>
    </div>
  );
}

/** Best-effort guess at which preset matches an issuer URL. */
function detectProvider(issuerUrl: string): ProviderPreset {
  const u = issuerUrl.toLowerCase();
  if (u.includes("login.microsoftonline.com") || u.includes("sts.windows.net")) return "entra";
  if (u.includes(".okta.com") || u.includes(".oktapreview.com"))                return "okta";
  if (u.includes(".auth0.com"))                                                  return "auth0";
  if (u.includes("accounts.google.com"))                                         return "google";
  if (u.includes("/realms/"))                                                    return "keycloak";
  return "generic";
}

function Field({
  label, value, onChange, type = "text", placeholder, help,
}: {
  label:        string;
  value:        string;
  onChange:     (v: string) => void;
  type?:        "text" | "password" | "url";
  placeholder?: string;
  help?:        string;
}) {
  return (
    <div>
      <label className="mb-1.5 block text-xs font-medium text-gray-300">{label}</label>
      {help && <p className="mb-2 text-[11px] text-gray-500">{help}</p>}
      <input
        type={type}
        value={value}
        placeholder={placeholder}
        onChange={(e) => onChange(e.target.value)}
        className="w-full rounded bg-gray-800 px-3 py-2 text-xs text-gray-200 placeholder-gray-600 focus:outline-none focus:ring-1 focus:ring-indigo-500"
      />
    </div>
  );
}

function TestResultPanel({ result }: { result: SsoTestResult }) {
  if (result.ok) {
    return (
      <div className="rounded-md border border-teal-900/40 bg-teal-950/30 px-3 py-2 text-xs text-gray-300">
        <div className="flex items-center gap-2 text-teal-300 font-semibold">
          <Check className="h-3.5 w-3.5" />
          Discovery OK · {result.latencyMs}ms
        </div>
        <dl className="mt-2 grid grid-cols-[max-content_1fr] gap-x-3 gap-y-1 font-mono text-[10px] text-gray-400">
          <dt>issuer</dt>          <dd className="break-all text-gray-200">{result.issuer}</dd>
          <dt>token</dt>           <dd className="break-all text-gray-300">{result.tokenEndpoint}</dd>
          <dt>auth</dt>            <dd className="break-all text-gray-300">{result.authorizationEndpoint}</dd>
          {result.userinfoEndpoint && (
            <>
              <dt>userinfo</dt>    <dd className="break-all text-gray-300">{result.userinfoEndpoint}</dd>
            </>
          )}
          <dt>jwks</dt>            <dd className="break-all text-gray-300">{result.jwksUri}</dd>
          {result.scopesSupported && result.scopesSupported.length > 0 && (
            <>
              <dt>scopes</dt>      <dd className="text-gray-300">{result.scopesSupported.join(", ")}</dd>
            </>
          )}
        </dl>
      </div>
    );
  }
  return (
    <div className="rounded-md border border-red-900/50 bg-red-950/30 px-3 py-2 text-xs text-red-200">
      <div className="flex items-start gap-2">
        <AlertCircle className="h-3.5 w-3.5 mt-0.5 shrink-0 text-red-400" />
        <div>
          <div className="font-semibold text-red-300">{result.error ?? "Discovery failed"}</div>
          {result.message && <div className="mt-1 text-red-300/80">{result.message}</div>}
          <div className="mt-1 text-[10px] text-red-400/60">{result.latencyMs}ms</div>
        </div>
      </div>
    </div>
  );
}
