/**
 * GitHub App auth — mints installation access tokens used for PR check runs
 * and inline review comments.
 *
 * Flow:
 *   1. Sign a short-lived JWT (10 min) with the App's private key (App auth).
 *   2. Exchange it for an installation token via
 *      POST /app/installations/:id/access_tokens  (1-hour token).
 *   3. Cache tokens per installation until 60s before expiry.
 *
 * All helpers return `null` when `GITHUB_APP_ID` / `GITHUB_APP_PRIVATE_KEY`
 * aren't configured — callers should gracefully fall back to PAT-based
 * webhooks when the App isn't set up.
 */
import jwt from "jsonwebtoken";
import axios from "axios";
import { config } from "../config.js";
import { logger } from "../logger.js";

const GITHUB_API = "https://api.github.com";

interface CachedToken {
  token:     string;
  expiresAt: number; // epoch ms
}

const tokenCache = new Map<number, CachedToken>();

export function isGitHubAppConfigured(): boolean {
  return Boolean(config.GITHUB_APP_ID && config.GITHUB_APP_PRIVATE_KEY);
}

/**
 * Build an App-level JWT (iss = app id, exp = now+10min).
 * Required for `/app/*` endpoints (listing installations, minting tokens).
 */
export function buildAppJwt(): string | null {
  if (!isGitHubAppConfigured()) return null;
  const now = Math.floor(Date.now() / 1000);
  // GitHub recommends `iat` 60s in the past to tolerate clock skew
  const payload = { iat: now - 60, exp: now + 10 * 60, iss: config.GITHUB_APP_ID };
  // PEM may come in env as a single line with literal \n — normalise
  const key = (config.GITHUB_APP_PRIVATE_KEY ?? "").replace(/\\n/g, "\n");
  return jwt.sign(payload, key, { algorithm: "RS256" });
}

/**
 * Mint (or reuse cached) installation token.
 * Returns null if App isn't configured or minting fails.
 */
export async function getInstallationToken(installationId: number): Promise<string | null> {
  if (!isGitHubAppConfigured()) return null;

  const cached = tokenCache.get(installationId);
  if (cached && cached.expiresAt - 60_000 > Date.now()) {
    return cached.token;
  }

  const appJwt = buildAppJwt();
  if (!appJwt) return null;

  try {
    const res = await axios.post(
      `${GITHUB_API}/app/installations/${installationId}/access_tokens`,
      {},
      {
        headers: {
          Authorization: `Bearer ${appJwt}`,
          Accept: "application/vnd.github+json",
          "User-Agent": "DevSecOps-Platform/1.0",
        },
        timeout: 15_000,
      }
    );
    const token = res.data.token as string;
    const expiresAt = new Date(res.data.expires_at as string).getTime();
    tokenCache.set(installationId, { token, expiresAt });
    return token;
  } catch (err) {
    logger.error("Failed to mint installation token", {
      installationId,
      error: (err as Error).message,
    });
    return null;
  }
}

/** Axios client pre-authed with an installation token. */
export async function installationClient(installationId: number) {
  const token = await getInstallationToken(installationId);
  if (!token) return null;
  return axios.create({
    baseURL: GITHUB_API,
    headers: {
      Authorization: `Bearer ${token}`,
      Accept: "application/vnd.github+json",
      "User-Agent": "DevSecOps-Platform/1.0",
      "X-GitHub-Api-Version": "2022-11-28",
    },
    timeout: 20_000,
  });
}

/**
 * List changed files for a PR — used by the incremental scanner to restrict
 * Semgrep/Trivy/TruffleHog/Checkov to only what the PR touches.
 */
export async function listPullRequestFiles(
  installationId: number,
  owner: string,
  repo:  string,
  prNumber: number
): Promise<string[]> {
  const client = await installationClient(installationId);
  if (!client) return [];
  const files: string[] = [];
  let page = 1;
  // GitHub caps at 3000 files; loop until empty page
  while (page < 30) {
    const res = await client.get(
      `/repos/${owner}/${repo}/pulls/${prNumber}/files`,
      { params: { per_page: 100, page } }
    );
    const batch = res.data as Array<{ filename: string; status: string }>;
    if (batch.length === 0) break;
    // Exclude removed files — they can't produce findings
    for (const f of batch) {
      if (f.status !== "removed") files.push(f.filename);
    }
    if (batch.length < 100) break;
    page += 1;
  }
  return files;
}
