import axios from "axios";
import { decrypt } from "../services/encryptionService.js";
import { logger } from "../logger.js";
import { config } from "../config.js";

const GITHUB_API = "https://api.github.com";

function makeClient(token: string) {
  return axios.create({
    baseURL: GITHUB_API,
    headers: {
      Authorization: `Bearer ${token}`,
      Accept: "application/vnd.github.v3+json",
      "User-Agent": "DevSecOps-Platform/1.0",
    },
    timeout: 15_000,
  });
}

export async function getRepo(encryptedToken: string, owner: string, name: string) {
  const token = decrypt(encryptedToken);
  const client = makeClient(token);
  const res = await client.get(`/repos/${owner}/${name}`);
  return res.data as {
    id: number;
    full_name: string;
    html_url: string;
    default_branch: string;
    private: boolean;
    language: string | null;
    clone_url: string;
  };
}

export async function listUserRepos(encryptedToken: string, page = 1) {
  const token = decrypt(encryptedToken);
  const client = makeClient(token);
  const res = await client.get("/user/repos", {
    params: { per_page: 50, page, sort: "updated", type: "all" },
  });
  return res.data as Array<{
    id: number;
    full_name: string;
    html_url: string;
    default_branch: string;
    private: boolean;
    language: string | null;
  }>;
}

export async function createWebhook(
  encryptedToken: string,
  owner: string,
  name: string,
  webhookUrl: string,
  secret: string
) {
  const token = decrypt(encryptedToken);
  const client = makeClient(token);
  try {
    const res = await client.post(`/repos/${owner}/${name}/hooks`, {
      name: "web",
      active: true,
      events: ["push", "pull_request"],
      config: {
        url: webhookUrl,
        content_type: "json",
        secret,
        insecure_ssl: "0",
      },
    });
    return res.data as { id: number };
  } catch (err) {
    logger.warn("Failed to create GitHub webhook", { owner, name, error: (err as Error).message });
    return null;
  }
}

export function parseGitHubUrl(url: string): { owner: string; name: string } | null {
  try {
    const parsed = new URL(url);
    if (parsed.hostname !== "github.com") return null;
    const parts = parsed.pathname.replace(/^\//, "").replace(/\.git$/, "").split("/");
    if (parts.length < 2 || !parts[0] || !parts[1]) return null;
    return { owner: parts[0], name: parts[1] };
  } catch {
    return null;
  }
}

export function getCloneUrl(encryptedToken: string, fullName: string) {
  const token = decrypt(encryptedToken);
  return `https://x-access-token:${token}@github.com/${fullName}.git`;
}

export function getWebhookUrl() {
  return `${config.API_PUBLIC_URL}/api/webhooks/github`;
}
