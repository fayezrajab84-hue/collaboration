import { z } from "zod";

const envSchema = z.object({
  NODE_ENV: z.enum(["development", "production", "test"]).default("development"),
  PORT: z.coerce.number().default(3000),
  DATABASE_URL: z.string().min(1),
  REDIS_URL: z.string().min(1),
  SESSION_SECRET: z.string().min(32),
  GITHUB_CLIENT_ID: z.string().min(1),
  GITHUB_CLIENT_SECRET: z.string().min(1),
  GITHUB_CALLBACK_URL: z.string().url(),
  SCANNER_URL: z.string().url(),
  SCANNER_PENTEST_URL: z.string().url().optional(),
  API_INTERNAL_URL: z.string().url().optional(), // e.g. http://api:3000 — used by scanner for phase callbacks
  API_PUBLIC_URL: z.string().url(),
  FRONTEND_URL: z.string().url(),
  ENCRYPTION_KEY: z.string().length(64), // 32 bytes as hex
  ZAP_API_KEY: z.string().min(1),
  ZAP_BASE_URL: z.string().url(),
  SCAN_WORKSPACE_DIR: z.string().default("/tmp/scan_workspace"),
  OLLAMA_URL:   z.string().url().default("http://ollama:11434"),
  OLLAMA_MODEL: z.string().default("qwen2.5-coder:7b"),
  // GitHub App (optional — enables PR checks & inline comments)
  GITHUB_APP_ID:             z.string().optional(),
  GITHUB_APP_PRIVATE_KEY:    z.string().optional(), // PEM contents (literal \n preserved)
  GITHUB_APP_WEBHOOK_SECRET: z.string().optional(),
  GITHUB_APP_SLUG:           z.string().optional(),
  // Phase 28 Slice A — Wazuh runtime ingestion. All optional; ingestion
  // service no-ops when WAZUH_API_URL is unset, so the rest of the platform
  // works for environments without Wazuh deployed. When set, the service
  // polls every WAZUH_POLL_INTERVAL_SECONDS for alerts on enrolled agents
  // and creates RUNTIME findings.
  WAZUH_API_URL:                z.string().url().optional(),
  WAZUH_API_USER:               z.string().optional(),
  WAZUH_API_PASSWORD:           z.string().optional(),
  // Wazuh 4.x stores alerts in the indexer (OpenSearch), not behind the
  // manager API. The manager API is still used for agent management /
  // status; alerts come from the indexer via basic auth on
  // /wazuh-alerts-*/_search. When unset, the ingest service falls back
  // to the manager-API path (works on older Wazuh deployments only).
  WAZUH_INDEXER_URL:            z.string().url().optional(),
  WAZUH_INDEXER_USER:           z.string().optional(),
  WAZUH_INDEXER_PASSWORD:       z.string().optional(),
  WAZUH_POLL_INTERVAL_SECONDS:  z.coerce.number().int().min(30).default(60),
  // For tests / dev: skip TLS validation against Wazuh's self-signed certs.
  // Defaults to false (strict TLS) in production.
  WAZUH_INSECURE_TLS:           z.coerce.boolean().default(false),
});

const parsed = envSchema.safeParse(process.env);

if (!parsed.success) {
  console.error("❌ Invalid environment variables:");
  console.error(parsed.error.flatten().fieldErrors);
  process.exit(1);
}

export const config = parsed.data;
export type Config = typeof config;
