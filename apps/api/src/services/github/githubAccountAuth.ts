/**
 * Phase 29 Slice C1 — GitHub posture asset auth helpers.
 *
 * Two auth paths supported via discriminator:
 *
 *   1. APP_INSTALLATION (preferred) — `installationId` set on the
 *      GitHubAccount row. The token is minted on demand from the App's
 *      private key + installation id (auto-rotates, 1h TTL). Reuses
 *      `apps/api/src/github/app.ts` for the JWT → installation token
 *      exchange.
 *
 *   2. PAT (fallback) — `encryptedCredentials` holds a base64-blob with
 *      a Personal Access Token. Decrypted at scan time, used as a Bearer
 *      header against the GitHub API. Acceptable for pre-Marketplace dev
 *      and customers who can't grant the GitHub App org-wide.
 *
 * `testGitHubConnection` validates that either auth path can successfully
 * authenticate against the GitHub API and that the named account is
 * reachable. Returns `{ ok, message }` matching the shape of
 * `testAzureConnection` in `services/cloud/azureAuth.ts`.
 */
import axios from "axios";
import { decrypt } from "../encryptionService.js";
import { getInstallationToken } from "../../github/app.js";
import { logger } from "../../logger.js";

const GITHUB_API = "https://api.github.com";

export interface GitHubAccountCredentials {
  installationId?: number | null;
  encryptedCredentials?: string | null;
  accountLogin: string;
  accountType: "USER" | "ORGANIZATION";
}

export interface TestConnectionResult {
  ok: boolean;
  message: string;
  /** Login of the authenticated principal — for sanity-checking the
   *  operator pasted the right token / installed in the right org. */
  authenticatedAs?: string;
}

/**
 * Attempts to authenticate via App installation token first (when
 * configured), then falls back to the PAT path. Returns ok=false with a
 * useful operator message on any failure.
 */
export async function testGitHubConnection(
  creds: GitHubAccountCredentials,
): Promise<TestConnectionResult> {
  const token = await resolveToken(creds);
  if (!token.ok) return { ok: false, message: token.message };

  const client = axios.create({
    baseURL: GITHUB_API,
    headers: {
      Authorization: `Bearer ${token.value}`,
      Accept: "application/vnd.github.v3+json",
      "User-Agent": "BreachLens/1.0",
    },
    timeout: 15_000,
  });

  // Verify the named account exists + is reachable. Use the typed
  // endpoint matching the operator's declared accountType so we
  // surface a clear error if they mistyped (e.g. an org login but
  // selected USER).
  const path = creds.accountType === "ORGANIZATION"
    ? `/orgs/${creds.accountLogin}`
    : `/users/${creds.accountLogin}`;

  try {
    const r = await client.get<{ login: string }>(path);
    return {
      ok: true,
      message: `Connected to ${creds.accountType === "ORGANIZATION" ? "organization" : "user"} '${r.data.login}'.`,
      authenticatedAs: r.data.login,
    };
  } catch (e) {
    const status = (e as { response?: { status?: number } }).response?.status;
    if (status === 401) return { ok: false, message: "GitHub rejected the credentials (401). The token may be revoked or expired." };
    if (status === 403) return { ok: false, message: "GitHub returned 403 — token lacks required scopes (need read:org for org-level checks)." };
    if (status === 404) return { ok: false, message: `Account '${creds.accountLogin}' not found, or token cannot see it. Check spelling + accountType.` };
    return { ok: false, message: `GitHub API error: ${(e as Error).message}` };
  }
}

/**
 * Resolves the bearer token for a GitHubAccount row, picking the right
 * auth path. Centralised so scan workers + test-connection share one
 * code path.
 */
export async function resolveToken(
  creds: GitHubAccountCredentials,
): Promise<{ ok: true; value: string } | { ok: false; message: string }> {
  // Prefer App installation auth when available.
  if (creds.installationId != null) {
    try {
      const token = await getInstallationToken(creds.installationId);
      if (!token) return { ok: false, message: "GitHub App is not configured on this deployment (set GITHUB_APP_ID + GITHUB_APP_PRIVATE_KEY)." };
      return { ok: true, value: token };
    } catch (e) {
      logger.warn(`[github-account-auth] App installation token mint failed: ${(e as Error).message}`);
      return { ok: false, message: `Failed to mint App installation token: ${(e as Error).message}` };
    }
  }

  // Fall back to encrypted PAT.
  if (creds.encryptedCredentials) {
    try {
      const blob = JSON.parse(decrypt(creds.encryptedCredentials)) as { token?: string };
      if (!blob.token) return { ok: false, message: "Decrypted credential blob has no token field." };
      return { ok: true, value: blob.token };
    } catch (e) {
      logger.error(`[github-account-auth] PAT decrypt failed: ${(e as Error).message}`);
      return { ok: false, message: "Failed to decrypt stored PAT — encryption key may have rotated." };
    }
  }

  return { ok: false, message: "GitHubAccount has no auth configured. Set installationId (App) or encryptedCredentials (PAT)." };
}
