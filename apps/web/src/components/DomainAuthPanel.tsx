import { useState, useEffect } from "react";
import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import {
  ShieldCheck, ShieldOff, Save, Trash2,
  ChevronDown, ChevronUp, Lock, KeyRound,
} from "lucide-react";
import { domainsApi, type DomainAuthConfigInput } from "../lib/api";

interface Props {
  domainId: string;
}

type AuthTypeValue = "FORM" | "HEADER" | "COOKIE" | "OAUTH2";

const AUTH_TYPE_LABELS: Record<AuthTypeValue, string> = {
  FORM:   "Form Login (username / password)",
  HEADER: "HTTP Header (API key / Bearer token)",
  COOKIE: "Cookie (pre-obtained session)",
  OAUTH2: "OAuth2 (client credentials / ROPC)",
};

const AUTH_TYPE_DESCRIPTIONS: Record<AuthTypeValue, string> = {
  FORM:   "Scanner submits a login form, carries the session cookie for all subsequent requests.",
  HEADER: "Scanner injects a static HTTP header (e.g. Authorization: Bearer <token>) on every request.",
  COOKIE: "Scanner injects a cookie string you have already obtained (e.g. from a browser session).",
  OAUTH2: "Scanner exchanges OAuth2 credentials for a Bearer token before scanning. Supports client_credentials (M2M) and password (ROPC) grant types.",
};

const EMPTY_FORM: DomainAuthConfigInput = {
  authType:          "FORM",
  loginUrl:          "",
  usernameField:     "username",
  passwordField:     "password",
  username:          "",
  password:          "",
  loggedInPattern:   "Logout",
  loggedOutPattern:  "login",
  headerName:        "Authorization",
  headerValue:       "",
  oauth2TokenUrl:    "",
  oauth2ClientId:    "",
  oauth2ClientSecret: "",
  oauth2Scope:       "",
  oauth2GrantType:   "client_credentials",
};

export default function DomainAuthPanel({ domainId }: Props) {
  const qc = useQueryClient();
  const [open, setOpen]       = useState(false);
  const [authType, setAuthType] = useState<AuthTypeValue>("FORM");
  const [form, setForm]       = useState<DomainAuthConfigInput>(EMPTY_FORM);

  const { data: existing, isLoading } = useQuery({
    queryKey: ["domain-auth", domainId],
    queryFn:  () => domainsApi.getAuth(domainId),
    enabled:  open,
  });

  // Pre-fill non-secret fields when existing config is loaded
  useEffect(() => {
    if (existing) {
      const t = existing.authType as AuthTypeValue;
      setAuthType(t);
      setForm((f) => ({
        ...f,
        authType:         t,
        loginUrl:         existing.loginUrl        ?? "",
        usernameField:    existing.usernameField    ?? "username",
        passwordField:    existing.passwordField    ?? "password",
        loggedInPattern:  existing.loggedInPattern  ?? "Logout",
        loggedOutPattern: existing.loggedOutPattern ?? "login",
        headerName:       existing.headerName       ?? "Authorization",
        oauth2TokenUrl:   existing.oauth2TokenUrl   ?? "",
        oauth2ClientId:   existing.oauth2ClientId   ?? "",
        oauth2Scope:      existing.oauth2Scope      ?? "",
        oauth2GrantType:  (existing.oauth2GrantType ?? "client_credentials") as "client_credentials" | "password",
      }));
    }
  }, [existing]);

  const save = useMutation({
    mutationFn: () => domainsApi.saveAuth(domainId, { ...form, authType }),
    onSuccess:  () => qc.invalidateQueries({ queryKey: ["domain-auth", domainId] }),
  });

  const remove = useMutation({
    mutationFn: () => domainsApi.deleteAuth(domainId),
    onSuccess:  () => {
      qc.invalidateQueries({ queryKey: ["domain-auth", domainId] });
      setAuthType("FORM");
      setForm(EMPTY_FORM);
    },
  });

  const set = (key: keyof DomainAuthConfigInput, val: string) =>
    setForm((f) => ({ ...f, [key]: val }));

  const hasConfig = existing !== null && existing !== undefined;

  return (
    <div className="mt-3 rounded-lg border border-gray-700/60 bg-gray-800/40">
      {/* Header — always visible */}
      <button
        onClick={() => setOpen((o) => !o)}
        className="flex w-full items-center justify-between px-4 py-2.5 text-left"
      >
        <div className="flex items-center gap-2">
          <Lock className="h-3.5 w-3.5 text-indigo-400" />
          <span className="text-xs font-medium text-gray-300">Scan Credentials</span>
          {hasConfig && (
            <span className="flex items-center gap-1 rounded-full bg-emerald-900/50 px-2 py-0.5 text-[10px] font-medium text-emerald-400">
              <ShieldCheck className="h-3 w-3" />
              {existing.authType === "OAUTH2" ? "OAuth2" : "Configured"}
            </span>
          )}
        </div>
        {open
          ? <ChevronUp   className="h-3.5 w-3.5 text-gray-500" />
          : <ChevronDown className="h-3.5 w-3.5 text-gray-500" />}
      </button>

      {open && (
        <div className="border-t border-gray-700/60 px-4 pb-4 pt-3 space-y-3">
          {isLoading ? (
            <p className="text-xs text-gray-500">Loading…</p>
          ) : (
            <>
              {/* Auth type selector */}
              <div>
                <label className="mb-1 block text-[11px] font-medium text-gray-400">Auth Type</label>
                <select
                  value={authType}
                  onChange={(e) => {
                    const t = e.target.value as AuthTypeValue;
                    setAuthType(t);
                    setForm((f) => ({ ...f, authType: t }));
                  }}
                  className="w-full rounded bg-gray-700 px-2.5 py-1.5 text-xs text-gray-200 focus:outline-none focus:ring-1 focus:ring-indigo-500"
                >
                  {(Object.keys(AUTH_TYPE_LABELS) as AuthTypeValue[]).map((t) => (
                    <option key={t} value={t}>{AUTH_TYPE_LABELS[t]}</option>
                  ))}
                </select>
                <p className="mt-1 text-[10px] text-gray-500">{AUTH_TYPE_DESCRIPTIONS[authType]}</p>
              </div>

              {/* ── FORM fields ─────────────────────────────────────────── */}
              {authType === "FORM" && (
                <>
                  <Field
                    label="Login URL"
                    placeholder="/login.php or http://dvwa/login.php"
                    value={form.loginUrl ?? ""}
                    onChange={(v) => set("loginUrl", v)}
                  />
                  <div className="grid grid-cols-2 gap-2">
                    <Field label="Username field" placeholder="username"
                      value={form.usernameField ?? ""} onChange={(v) => set("usernameField", v)} />
                    <Field label="Password field" placeholder="password"
                      value={form.passwordField ?? ""} onChange={(v) => set("passwordField", v)} />
                  </div>
                  <div className="grid grid-cols-2 gap-2">
                    <Field label="Username" placeholder="admin"
                      value={form.username ?? ""} onChange={(v) => set("username", v)} />
                    <Field label="Password" placeholder="••••••••" type="password"
                      value={form.password ?? ""} onChange={(v) => set("password", v)} />
                  </div>
                  <div className="grid grid-cols-2 gap-2">
                    <Field
                      label="Logged-in indicator"
                      placeholder="Logout"
                      value={form.loggedInPattern ?? ""}
                      onChange={(v) => set("loggedInPattern", v)}
                      help="Text the scanner looks for to confirm login succeeded"
                    />
                    <Field
                      label="Logged-out indicator"
                      placeholder="login"
                      value={form.loggedOutPattern ?? ""}
                      onChange={(v) => set("loggedOutPattern", v)}
                      help="URL fragment that signals session has expired"
                    />
                  </div>
                </>
              )}

              {/* ── HEADER / COOKIE fields ──────────────────────────────── */}
              {(authType === "HEADER" || authType === "COOKIE") && (
                <>
                  <Field
                    label={authType === "HEADER" ? "Header name" : "Header name (Cookie)"}
                    placeholder={authType === "HEADER" ? "Authorization" : "Cookie"}
                    value={form.headerName ?? ""}
                    onChange={(v) => set("headerName", v)}
                  />
                  <Field
                    label={authType === "HEADER" ? "Header value" : "Cookie string"}
                    placeholder={
                      authType === "HEADER"
                        ? "Bearer eyJ…"
                        : "PHPSESSID=abc123; security=low"
                    }
                    value={form.headerValue ?? ""}
                    onChange={(v) => set("headerValue", v)}
                    type="password"
                    help="Value is stored encrypted and never shown again"
                  />
                </>
              )}

              {/* ── OAuth2 fields ───────────────────────────────────────── */}
              {authType === "OAUTH2" && (
                <>
                  <div className="rounded-md border border-indigo-900/40 bg-indigo-950/30 px-3 py-2 text-[11px] text-indigo-300">
                    <KeyRound className="mb-0.5 inline h-3 w-3 mr-1" />
                    The scanner will call the token endpoint before starting the scan and inject
                    the access token as <code className="font-mono">Authorization: Bearer …</code> on
                    all requests.
                  </div>

                  <Field
                    label="Token endpoint URL"
                    placeholder="https://auth.example.com/oauth/token"
                    value={form.oauth2TokenUrl ?? ""}
                    onChange={(v) => set("oauth2TokenUrl", v)}
                    help="The /token endpoint of your OAuth2 authorization server"
                  />

                  <div className="grid grid-cols-2 gap-2">
                    <Field
                      label="Client ID"
                      placeholder="my-client-id"
                      value={form.oauth2ClientId ?? ""}
                      onChange={(v) => set("oauth2ClientId", v)}
                    />
                    <Field
                      label="Client Secret"
                      placeholder="••••••••"
                      type="password"
                      value={form.oauth2ClientSecret ?? ""}
                      onChange={(v) => set("oauth2ClientSecret", v)}
                      help="Stored encrypted, never returned"
                    />
                  </div>

                  <div className="grid grid-cols-2 gap-2">
                    <Field
                      label="Scope (optional)"
                      placeholder="openid profile api:read"
                      value={form.oauth2Scope ?? ""}
                      onChange={(v) => set("oauth2Scope", v)}
                      help="Space-separated scope values"
                    />
                    <div>
                      <label className="mb-1 block text-[11px] font-medium text-gray-400">
                        Grant type
                      </label>
                      <select
                        value={form.oauth2GrantType ?? "client_credentials"}
                        onChange={(e) =>
                          set("oauth2GrantType", e.target.value as "client_credentials" | "password")
                        }
                        className="w-full rounded bg-gray-700 px-2.5 py-1.5 text-xs text-gray-200 focus:outline-none focus:ring-1 focus:ring-indigo-500"
                      >
                        <option value="client_credentials">client_credentials (M2M)</option>
                        <option value="password">password (ROPC)</option>
                      </select>
                    </div>
                  </div>

                  {/* Show username/password when password grant is selected */}
                  {form.oauth2GrantType === "password" && (
                    <div className="grid grid-cols-2 gap-2">
                      <Field
                        label="Username"
                        placeholder="user@example.com"
                        value={form.username ?? ""}
                        onChange={(v) => set("username", v)}
                      />
                      <Field
                        label="Password"
                        placeholder="••••••••"
                        type="password"
                        value={form.password ?? ""}
                        onChange={(v) => set("password", v)}
                      />
                    </div>
                  )}
                </>
              )}

              {/* ── Action buttons ──────────────────────────────────────── */}
              <div className="flex items-center gap-2 pt-1">
                <button
                  onClick={() => save.mutate()}
                  disabled={save.isPending}
                  className="flex items-center gap-1.5 rounded bg-indigo-600 px-3 py-1.5 text-xs font-medium text-white hover:bg-indigo-500 disabled:opacity-50"
                >
                  <Save className="h-3 w-3" />
                  {save.isPending
                    ? "Saving…"
                    : hasConfig ? "Update Credentials" : "Save Credentials"}
                </button>

                {hasConfig && (
                  <button
                    onClick={() => remove.mutate()}
                    disabled={remove.isPending}
                    className="flex items-center gap-1.5 rounded border border-red-800/50 px-3 py-1.5 text-xs font-medium text-red-400 hover:bg-red-900/20 disabled:opacity-50"
                  >
                    <ShieldOff className="h-3 w-3" />
                    {remove.isPending ? "Removing…" : "Remove"}
                  </button>
                )}

                {save.isSuccess && (
                  <span className="text-[11px] text-emerald-400">
                    Saved — next scan will use these credentials
                  </span>
                )}
                {save.isError && (
                  <span className="text-[11px] text-red-400">
                    {(save.error as Error).message}
                  </span>
                )}
              </div>

              <p className="text-[10px] text-gray-600">
                All credentials are encrypted with AES-256-GCM and never exposed in API
                responses. They are decrypted only inside the Docker network at scan time.
              </p>
            </>
          )}
        </div>
      )}
    </div>
  );
}

// ── Small reusable field ──────────────────────────────────────────────────────
function Field({
  label, placeholder, value, onChange, type = "text", help,
}: {
  label: string; placeholder?: string; value: string;
  onChange: (v: string) => void; type?: string; help?: string;
}) {
  return (
    <div>
      <label className="mb-1 block text-[11px] font-medium text-gray-400">{label}</label>
      <input
        type={type}
        className="w-full rounded bg-gray-700 px-2.5 py-1.5 text-xs text-gray-200 placeholder-gray-500 focus:outline-none focus:ring-1 focus:ring-indigo-500"
        placeholder={placeholder}
        value={value}
        onChange={(e) => onChange(e.target.value)}
      />
      {help && <p className="mt-0.5 text-[10px] text-gray-600">{help}</p>}
    </div>
  );
}
