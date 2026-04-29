/**
 * Azure Service Principal authentication helpers.
 *
 * Provides OAuth2 client-credentials flow against Entra ID + a basic
 * subscription-listing call against the Azure Resource Manager API.
 * Used by the CloudAccount test-connection endpoint to validate that
 * an operator-supplied (tenantId, clientId, clientSecret) trio can
 * actually authenticate AND can read the target subscription.
 *
 * Why no @azure/identity / @azure/arm-resources SDK: this file is
 * Slice-A-only validation; pulling in the full Azure JS SDK (~30MB
 * across the dependency tree) for two HTTP calls is overkill. The
 * Python scanner (Commit 2) will use azure-mgmt-* SDKs natively for
 * actual resource enumeration — that's where the SDK depth pays for
 * itself.
 *
 * Failure modes surfaced to the caller (via TestConnectionResult.error):
 *   - "invalid_client" — wrong tenantId / clientId / clientSecret
 *   - "subscription_not_found" — credentials work but SP can't read
 *     the named subscription (missing Reader role)
 *   - "network" — DNS / TLS / timeout to login.microsoftonline.com
 *     or management.azure.com
 *   - "unknown" — anything else; full message in `error.detail`
 */
import axios, { AxiosError } from "axios";

// ── Public surface ────────────────────────────────────────────────────────

export interface AzureCredentials {
  tenantId:       string;   // GUID
  clientId:       string;   // SP application id (GUID)
  clientSecret:   string;   // never logged; passed direct to AAD token endpoint
  subscriptionId: string;   // GUID — the subscription we test reachability against
}

export type TestConnectionResult =
  | { ok: true;  subscription: { id: string; name: string; state: string }; tokenExpiresAt: string }
  | { ok: false; code: "invalid_client" | "subscription_not_found" | "network" | "unknown"; message: string };

// ── OAuth2 client-credentials flow ───────────────────────────────────────
// Endpoint: https://login.microsoftonline.com/{tenantId}/oauth2/v2.0/token
// Scope:    https://management.azure.com/.default — required for ARM access
// Returns a bearer access token good for ~1 hour.

interface TokenResponse {
  access_token: string;
  expires_in:   number;     // seconds
  token_type:   "Bearer";
}

async function fetchAccessToken(creds: AzureCredentials): Promise<{ token: string; expiresAt: Date }> {
  const url = `https://login.microsoftonline.com/${encodeURIComponent(creds.tenantId)}/oauth2/v2.0/token`;
  const body = new URLSearchParams({
    grant_type:    "client_credentials",
    client_id:     creds.clientId,
    client_secret: creds.clientSecret,
    scope:         "https://management.azure.com/.default",
  });
  const resp = await axios.post<TokenResponse>(url, body.toString(), {
    headers: { "Content-Type": "application/x-www-form-urlencoded" },
    timeout: 10_000,
    validateStatus: () => true,   // hand-classify below; don't let axios throw
  });
  if (resp.status === 200 && resp.data?.access_token) {
    const expiresAt = new Date(Date.now() + (resp.data.expires_in - 60) * 1000);  // 1-min safety margin
    return { token: resp.data.access_token, expiresAt };
  }
  // 400 with error="invalid_client" or "unauthorized_client" both mean
  // the SP credentials are wrong. Bubble up as a typed failure so the
  // route can return 422 with a helpful message.
  const errCode = (resp.data as { error?: string } | undefined)?.error;
  if (resp.status === 400 || resp.status === 401) {
    throw Object.assign(new Error("Azure rejected SP credentials"), {
      _kind: "invalid_client" as const,
      detail: errCode ?? `HTTP ${resp.status}`,
    });
  }
  throw Object.assign(new Error("Token endpoint returned unexpected response"), {
    _kind: "unknown" as const,
    detail: `HTTP ${resp.status}: ${JSON.stringify(resp.data).slice(0, 200)}`,
  });
}

// ── ARM subscription read ────────────────────────────────────────────────
// Endpoint: GET https://management.azure.com/subscriptions/{id}?api-version=2022-12-01
// 404 → SP authenticated but doesn't have Reader on this subscription
// 200 → return the subscription's displayName + state for confirmation

interface ArmSubscription {
  id:                  string;
  subscriptionId:      string;
  displayName:         string;
  state:               string;
}

async function fetchSubscription(token: string, subscriptionId: string): Promise<ArmSubscription> {
  const url = `https://management.azure.com/subscriptions/${encodeURIComponent(subscriptionId)}?api-version=2022-12-01`;
  const resp = await axios.get<ArmSubscription>(url, {
    headers: { Authorization: `Bearer ${token}` },
    timeout: 10_000,
    validateStatus: () => true,
  });
  if (resp.status === 200 && resp.data?.subscriptionId) {
    return resp.data;
  }
  if (resp.status === 401 || resp.status === 403 || resp.status === 404) {
    throw Object.assign(new Error("Subscription not visible to this SP"), {
      _kind: "subscription_not_found" as const,
      detail: `HTTP ${resp.status} from ARM /subscriptions/${subscriptionId}`,
    });
  }
  throw Object.assign(new Error("ARM subscription endpoint returned unexpected response"), {
    _kind: "unknown" as const,
    detail: `HTTP ${resp.status}: ${JSON.stringify(resp.data).slice(0, 200)}`,
  });
}

// ── Public entry point ───────────────────────────────────────────────────

/**
 * Validate that the supplied credentials can authenticate AND can read
 * the target subscription. Returns a tagged-union result so the caller
 * can format a precise UI message. Never throws — all failures map to
 * `{ ok: false, code, message }`.
 */
export async function testAzureConnection(creds: AzureCredentials): Promise<TestConnectionResult> {
  try {
    const { token, expiresAt } = await fetchAccessToken(creds);
    const sub = await fetchSubscription(token, creds.subscriptionId);
    return {
      ok: true,
      subscription: {
        id:    sub.subscriptionId,
        name:  sub.displayName,
        state: sub.state,
      },
      tokenExpiresAt: expiresAt.toISOString(),
    };
  } catch (e) {
    // Tagged-error short-circuits — the helper functions throw with a
    // _kind discriminator we can pass straight through.
    const tagged = e as { _kind?: TestConnectionResult extends { ok: false; code: infer C } ? C : never; detail?: string; message?: string };
    if (tagged._kind === "invalid_client") {
      return { ok: false, code: "invalid_client", message: `Invalid Service Principal credentials: ${tagged.detail ?? tagged.message}` };
    }
    if (tagged._kind === "subscription_not_found") {
      return { ok: false, code: "subscription_not_found", message: `Subscription not visible to this SP — confirm the SP has Reader role on subscription ${creds.subscriptionId}` };
    }
    if (tagged._kind === "unknown") {
      return { ok: false, code: "unknown", message: tagged.detail ?? tagged.message ?? "unknown error" };
    }
    // Network / DNS / TLS errors come through as raw AxiosError without
    // a _kind tag — classify here.
    if (e instanceof AxiosError) {
      return {
        ok: false,
        code: "network",
        message: e.code === "ENOTFOUND" || e.code === "ETIMEDOUT" || e.code === "ECONNREFUSED"
          ? `Network error contacting Azure: ${e.code}`
          : `HTTP error: ${e.message}`,
      };
    }
    return { ok: false, code: "unknown", message: (e as Error).message ?? "unknown error" };
  }
}
