/**
 * Minimal OIDC client — implements just enough of the Authorization Code
 * Flow to provision BreachLens users from any standards-compliant IdP
 * (Okta, Azure AD, Google Workspace, Auth0, Keycloak).
 *
 * Why we rolled our own instead of openid-client / passport-openidconnect:
 *   1. Per-org config — most passport strategies want one strategy per app.
 *      We need to swap clientId/clientSecret/discovery URL per request.
 *   2. No third-party install dance with the baked-in node_modules layout.
 *   3. ~200 LoC; no dep surface to worry about.
 *
 * Trade-off vs full ID token verification:
 *   We trust the userinfo endpoint (HTTPS to IdP) instead of cryptographically
 *   verifying the id_token JWT signature against JWKS. The state+nonce CSRF
 *   protection still applies. For v1 this is acceptable for self-hosted
 *   deployments where TLS to the IdP is the trust boundary anyway.
 *   Layer in `jose` for JWT verification when stricter security is required
 *   (Phase 22 PR 3 Slice C or later).
 */
import { Role } from "@prisma/client";

// ── Types ────────────────────────────────────────────────────────────────────

export interface DiscoveryDoc {
  issuer:                  string;
  authorization_endpoint:  string;
  token_endpoint:          string;
  userinfo_endpoint?:      string;
  jwks_uri:                string;
  scopes_supported?:       string[];
}

export interface OidcOrgConfig {
  orgId:            string;
  issuerUrl:        string;
  clientId:         string;
  clientSecret:     string;             // decrypted at call site
  defaultRole:      Role;
  groupRoleMapping: Record<string, Role>;
}

export interface OidcUserProfile {
  /** Stable per-user IdP identifier — never changes across renames/email changes. */
  sub:      string;
  email?:   string;
  name?:    string;
  picture?: string;
  /** Group memberships — IdP-dependent. Okta+Azure AD: present in token if scope+config allow. Google: usually absent. */
  groups?:  string[];
  /**
   * True when the IdP signalled that the groups claim was too large to inline
   * (Entra ID: `_claim_names.groups` indirection, fired at ≥150 groups).
   * Caller should warn the operator since defaultRole will be assigned.
   */
  groupOverage?: boolean;
}

// ── Discovery cache ──────────────────────────────────────────────────────────
// Discovery docs change rarely; cache for 1h to avoid hammering the IdP on
// every login attempt. Per-issuer keyed (one entry per IdP across all orgs).

const DISCOVERY_TTL_MS  = 60 * 60 * 1000;
const DISCOVERY_TIMEOUT = 5_000;

const discoveryCache = new Map<string, { doc: DiscoveryDoc; fetchedAt: number }>();

export async function discover(issuerUrl: string): Promise<DiscoveryDoc> {
  const cached = discoveryCache.get(issuerUrl);
  if (cached && Date.now() - cached.fetchedAt < DISCOVERY_TTL_MS) return cached.doc;

  const url = issuerUrl.replace(/\/$/, "") + "/.well-known/openid-configuration";
  const resp = await fetch(url, { signal: AbortSignal.timeout(DISCOVERY_TIMEOUT) });
  if (!resp.ok) throw new OidcError("DISCOVERY_FAILED", `HTTP ${resp.status} from ${url}`);

  const doc = (await resp.json()) as DiscoveryDoc;
  if (!doc.authorization_endpoint || !doc.token_endpoint) {
    throw new OidcError("DISCOVERY_INCOMPLETE", "Missing authorization_endpoint or token_endpoint");
  }
  discoveryCache.set(issuerUrl, { doc, fetchedAt: Date.now() });
  return doc;
}

// ── Authorization URL builder ────────────────────────────────────────────────

export async function buildAuthorizationUrl(
  config: OidcOrgConfig,
  state: string,
  nonce: string,
  redirectUri: string,
  loginHint?: string,
): Promise<string> {
  const doc = await discover(config.issuerUrl);
  const params = new URLSearchParams({
    response_type: "code",
    client_id:     config.clientId,
    redirect_uri:  redirectUri,
    // Bare-minimum scope. We deliberately do NOT request `email`, `profile`,
    // `groups`, or `User.Read` here — those should be driven by the IdP-side
    // app/client registration (Entra: API permissions + Token Configuration →
    // Optional Claims; Okta: ID Token claims; Auth0: rules/actions). Sending
    // them from our side just causes "scope doesn't exist on resource"
    // failures on tenants that haven't exposed them. `openid` is the protocol
    // minimum — without it, Entra/Okta won't return an ID token and /userinfo
    // is unreachable.
    scope:         "openid",
    state,
    nonce,
  });
  // Pre-fill the username on the IdP login screen so the user doesn't have
  // to re-type the email they already entered on /login. Standard OIDC
  // parameter — honoured by Entra (skips username step entirely if SSO
  // applies), Okta, Google, Auth0.
  if (loginHint) {
    params.set("login_hint", loginHint);
  }
  return `${doc.authorization_endpoint}?${params.toString()}`;
}

// ── Token exchange + userinfo fetch ──────────────────────────────────────────

const TOKEN_TIMEOUT    = 10_000;
const USERINFO_TIMEOUT = 5_000;

export async function exchangeCodeForUserProfile(
  config: OidcOrgConfig,
  code: string,
  redirectUri: string,
): Promise<OidcUserProfile> {
  const doc = await discover(config.issuerUrl);

  // ── Token exchange ─────────────────────────────────────────────────────────
  // Standard authorization_code grant. We use client_secret_post (credentials
  // in body) instead of client_secret_basic (HTTP Basic) because more IdPs
  // accept it without explicit configuration.
  const tokenBody = new URLSearchParams({
    grant_type:    "authorization_code",
    code,
    redirect_uri:  redirectUri,
    client_id:     config.clientId,
    client_secret: config.clientSecret,
  });
  const tokenResp = await fetch(doc.token_endpoint, {
    method:  "POST",
    headers: { "content-type": "application/x-www-form-urlencoded", accept: "application/json" },
    body:    tokenBody,
    signal:  AbortSignal.timeout(TOKEN_TIMEOUT),
  });
  if (!tokenResp.ok) {
    const errText = await tokenResp.text().catch(() => "");
    throw new OidcError(
      "TOKEN_EXCHANGE_FAILED",
      `HTTP ${tokenResp.status}: ${errText.slice(0, 300)}`,
    );
  }
  const tokens = (await tokenResp.json()) as { access_token?: string; id_token?: string };
  if (!tokens.access_token) {
    throw new OidcError("TOKEN_EXCHANGE_FAILED", "No access_token in response");
  }

  // ── Userinfo fetch ─────────────────────────────────────────────────────────
  // Skips JWT signature verification of id_token. The userinfo endpoint is
  // authenticated by access_token over TLS to the IdP — same trust boundary.
  if (!doc.userinfo_endpoint) {
    throw new OidcError(
      "NO_USERINFO_ENDPOINT",
      `IdP at ${doc.issuer} doesn't expose a userinfo endpoint. Falling back to id_token JWT verification is not yet supported.`,
    );
  }
  const userResp = await fetch(doc.userinfo_endpoint, {
    headers: { authorization: `Bearer ${tokens.access_token}`, accept: "application/json" },
    signal:  AbortSignal.timeout(USERINFO_TIMEOUT),
  });
  if (!userResp.ok) {
    throw new OidcError("USERINFO_FAILED", `HTTP ${userResp.status} from userinfo endpoint`);
  }
  const profile = (await userResp.json()) as OidcUserProfile & Record<string, unknown>;

  // Normalise the groups claim — different IdPs use different keys.
  // Okta:     "groups"
  // Entra ID: "groups" (object IDs by default; configurable to sam_account_name)
  // Azure AD: same as Entra
  // Auth0:    custom-namespaced ("https://yourdomain/groups")
  // Keycloak: "groups" (with leading slash)
  const groups = extractGroups(profile);

  // Entra ID returns >150 groups as a `_claim_names`/`_claim_sources`
  // indirection rather than inline. Without a Microsoft Graph call we
  // can't enumerate them, so we surface a loud warning + fall back to
  // defaultRole. Operators can remediate by configuring the app
  // registration to emit `sam_account_name` (Entra) or by reducing the
  // user's group membership.
  if (!groups && profile["_claim_names"] && typeof profile["_claim_names"] === "object") {
    const claimNames = profile["_claim_names"] as Record<string, unknown>;
    if (claimNames["groups"]) {
      // Surfaced via the OidcUserProfile.groupOverage flag for the route
      // handler to log; not a hard failure.
      return {
        sub:          extractSubject(profile),
        email:        extractEmail(profile),
        name:         typeof profile.name === "string" ? profile.name : undefined,
        picture:      typeof profile.picture === "string" ? profile.picture : undefined,
        groups:       undefined,
        groupOverage: true,
      };
    }
  }

  return {
    sub:     extractSubject(profile),
    email:   extractEmail(profile),
    name:    typeof profile.name === "string" ? profile.name : undefined,
    picture: typeof profile.picture === "string" ? profile.picture : undefined,
    groups,
  };
}

function extractSubject(profile: Record<string, unknown>): string {
  // Entra also emits `oid` (object ID) which is more stable than `sub` across
  // app re-registrations. Prefer `sub` (standard) but fall through.
  return String(profile["sub"] ?? profile["oid"] ?? "");
}

/**
 * Resolve a user-facing email from the userinfo response. Entra is the
 * common case where `email` is null but `preferred_username` (the UPN)
 * is present and looks like an email. Try in standards-preferred order.
 *
 * Returns undefined if nothing email-shaped is found — caller surfaces
 * `no_email_in_profile` to the operator with a remediation pointer.
 */
function extractEmail(profile: Record<string, unknown>): string | undefined {
  const candidates = [
    profile["email"],
    profile["preferred_username"],
    profile["upn"],          // Entra legacy claim, sometimes still present
    profile["unique_name"],  // Entra v1 token claim
  ];
  for (const c of candidates) {
    if (typeof c === "string" && c.includes("@")) {
      return c.toLowerCase();
    }
  }
  return undefined;
}

function extractGroups(profile: Record<string, unknown>): string[] | undefined {
  // `roles` is included as a fallback for Entra ID app registrations that
  // expose role assignments instead of group membership.
  const candidates = [profile["groups"], profile["roles"]];
  for (const c of candidates) {
    if (Array.isArray(c)) {
      // Strip Keycloak-style leading slashes for cleaner mapping keys.
      return c.filter((x): x is string => typeof x === "string").map((g) => g.replace(/^\//, ""));
    }
  }
  return undefined;
}

// ── Role resolution ──────────────────────────────────────────────────────────

/**
 * Map IdP groups → BreachLens role using the org's configured mapping.
 * First match in iteration order wins. Falls back to defaultRole when no
 * group is in the mapping (or no groups returned by the IdP).
 *
 * Re-runs on every login so role changes propagate without a re-invite.
 */
export function resolveRole(
  config: OidcOrgConfig,
  groups: string[] | undefined,
): Role {
  if (groups && groups.length > 0) {
    for (const g of groups) {
      const role = config.groupRoleMapping[g];
      if (role) return role;
    }
  }
  return config.defaultRole;
}

// ── Errors ───────────────────────────────────────────────────────────────────

export type OidcErrorKind =
  | "DISCOVERY_FAILED"
  | "DISCOVERY_INCOMPLETE"
  | "TOKEN_EXCHANGE_FAILED"
  | "NO_USERINFO_ENDPOINT"
  | "USERINFO_FAILED"
  | "STATE_MISMATCH"
  | "NO_SSO_FOR_DOMAIN"
  | "NO_EMAIL_IN_PROFILE";

export class OidcError extends Error {
  constructor(public kind: OidcErrorKind, message: string) {
    super(message);
    this.name = "OidcError";
  }
}
