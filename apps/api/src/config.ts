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
  OLLAMA_MODEL: z.string().default("llama3.2:3b"),
});

const parsed = envSchema.safeParse(process.env);

if (!parsed.success) {
  console.error("❌ Invalid environment variables:");
  console.error(parsed.error.flatten().fieldErrors);
  process.exit(1);
}

export const config = parsed.data;
export type Config = typeof config;
