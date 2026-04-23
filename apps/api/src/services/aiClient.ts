/**
 * AI Client — multi-provider abstraction.
 *
 * One adapter, four backends (Anthropic / OpenAI / Gemini / Ollama).
 * All seven AI services in this codebase route through this module so we can
 * swap providers per-org or per-service without touching call sites.
 *
 * Routing precedence (highest first):
 *   1. AIServiceRouting row for (org, service) — explicit override
 *   2. AIProvider row with isDefault=true for that org
 *   3. Hard fallback to OLLAMA at OLLAMA_URL (preserves current dev experience
 *      when nothing has been configured yet)
 *
 * IMPLEMENTATION STATUS: signatures only. The four `*Adapter.invoke` functions
 * and the cost table are stubbed and will throw at runtime — wired in next
 * PR. This file exists so call sites can be migrated against the final API
 * surface without waiting for the providers to land.
 */

import { z } from "zod";
import type {
  AIProviderType,
  AIServiceName,
} from "@prisma/client";

// ── Public API ───────────────────────────────────────────────────────────────

/** Inputs that every call site must supply. */
export interface AIInvokeOptions<TSchema extends z.ZodTypeAny | undefined = undefined> {
  /** Which logical service is calling — drives routing + telemetry. */
  service: AIServiceName;
  /** Org context — required so we can pick that org's provider config. */
  orgId: string;
  /** System prompt. Cached automatically when the provider supports it. */
  system: string;
  /** User message (single-turn) or message history (multi-turn for CHAT). */
  messages: AIMessage[];
  /**
   * If set, response is parsed + validated against this Zod schema. Uses
   * provider-native structured output where available (Anthropic JSON mode,
   * OpenAI structured outputs, Gemini responseSchema, Ollama format:"json").
   * Returns the parsed object as `result.data`. Omit for free-text output.
   */
  schema?: TSchema;
  /** Soft cap on output tokens. Provider-specific. */
  maxOutputTokens?: number;
  /** 0 = deterministic, 1 = creative. Default 0.1 for security workloads. */
  temperature?: number;
  /** For correlating telemetry rows back to the resource that triggered the call. */
  findingId?: string;
  scanJobId?: string;
}

export interface AIMessage {
  role: "user" | "assistant";
  content: string;
}

/** Successful invocation result. */
export interface AIInvokeResult<TSchema extends z.ZodTypeAny | undefined> {
  /** Parsed object if `schema` was provided, otherwise raw text. */
  data: TSchema extends z.ZodTypeAny ? z.infer<TSchema> : string;
  /** The exact text the model returned (pre-parse). */
  rawText: string;
  /** Resolved provider + model that handled the call (post-routing). */
  providerType: AIProviderType;
  model: string;
  /** Telemetry — also persisted to AICallLog. */
  usage: {
    inputTokens: number;
    outputTokens: number;
    cachedInputTokens: number;   // 0 if provider doesn't support caching
    latencyMs: number;
    costUsd: number;
  };
}

/**
 * Single entry point. Resolve provider via routing → call provider adapter
 * → record AICallLog row → return parsed result.
 *
 * Error handling: throws a typed AIError on any failure so call sites can
 * fall back gracefully (e.g. drop the FP triage if the provider is down).
 */
export async function invokeAI<TSchema extends z.ZodTypeAny | undefined>(
  _opts: AIInvokeOptions<TSchema>,
): Promise<AIInvokeResult<TSchema>> {
  throw new Error("[aiClient] not yet implemented — pending provider adapters");
}

// ── Provider adapter contract ────────────────────────────────────────────────
// One file per provider implements this. Adapters are responsible for:
//   - translating AIInvokeOptions into provider SDK calls
//   - applying provider-specific features when supported (prompt caching,
//     structured outputs, extended thinking, batch API)
//   - normalising token counts + computing cost from PRICE_TABLE
//   - returning AIInvokeResult OR throwing AIError

export interface ResolvedProvider {
  providerType: AIProviderType;
  model: string;
  apiKey?: string;
  baseUrl?: string;
}

export interface ProviderAdapter {
  invoke<TSchema extends z.ZodTypeAny | undefined>(
    provider: ResolvedProvider,
    opts: AIInvokeOptions<TSchema>,
  ): Promise<AIInvokeResult<TSchema>>;
}

// Adapter stubs — flesh out one at a time.
// Recommended order: ollama (preserves dev experience) → anthropic
// (default for prod) → openai → gemini.
export const anthropicAdapter: ProviderAdapter = {
  invoke: async () => { throw new Error("anthropicAdapter: not yet implemented"); },
};
export const openaiAdapter: ProviderAdapter = {
  invoke: async () => { throw new Error("openaiAdapter: not yet implemented"); },
};
export const geminiAdapter: ProviderAdapter = {
  invoke: async () => { throw new Error("geminiAdapter: not yet implemented"); },
};
export const ollamaAdapter: ProviderAdapter = {
  invoke: async () => { throw new Error("ollamaAdapter: not yet implemented"); },
};

// ── Errors ───────────────────────────────────────────────────────────────────

export type AIErrorKind =
  | "PROVIDER_UNCONFIGURED"   // no AIProvider row + no fallback
  | "PROVIDER_DOWN"           // network / 5xx
  | "RATE_LIMITED"            // 429
  | "QUOTA_EXCEEDED"          // billing / monthly cap
  | "INVALID_OUTPUT"          // schema parse failed after retries
  | "UNAUTHORIZED"            // bad API key
  | "TIMEOUT";

export class AIError extends Error {
  constructor(
    public kind: AIErrorKind,
    message: string,
    public providerType?: AIProviderType,
    public retryable = false,
  ) {
    super(message);
    this.name = "AIError";
  }
}

// ── Cost table ───────────────────────────────────────────────────────────────
// USD per million tokens. Read at AICallLog insert time so historical rows
// stay correct when prices change. Adapters call `priceFor(model)` not the
// table directly.
//
// IMPORTANT: keep this in sync with provider pricing pages. Stale entries
// silently undercount cost dashboards.
export interface PriceEntry {
  inputPerMTok:        number;
  cachedInputPerMTok:  number;   // 0 = caching not supported
  outputPerMTok:       number;
}

export const PRICE_TABLE: Record<string, PriceEntry> = {
  // ── Anthropic ──
  "claude-sonnet-4-5":  { inputPerMTok: 3.00, cachedInputPerMTok: 0.30, outputPerMTok: 15.00 },
  "claude-haiku-4-5":   { inputPerMTok: 1.00, cachedInputPerMTok: 0.10, outputPerMTok:  5.00 },
  "claude-opus-4-5":    { inputPerMTok: 15.00, cachedInputPerMTok: 1.50, outputPerMTok: 75.00 },
  // ── OpenAI ──
  "gpt-5":              { inputPerMTok: 2.50, cachedInputPerMTok: 1.25, outputPerMTok: 10.00 },
  "gpt-5-mini":         { inputPerMTok: 0.15, cachedInputPerMTok: 0.075, outputPerMTok: 0.60 },
  // ── Gemini ──
  "gemini-2.5-pro":     { inputPerMTok: 1.25, cachedInputPerMTok: 0.31, outputPerMTok: 5.00 },
  "gemini-2.5-flash":   { inputPerMTok: 0.075, cachedInputPerMTok: 0.018, outputPerMTok: 0.30 },
  // ── Ollama (local — zero monetary cost; track tokens for capacity planning) ──
  "_ollama_default":    { inputPerMTok: 0,    cachedInputPerMTok: 0,    outputPerMTok: 0 },
};

export function priceFor(model: string): PriceEntry {
  return PRICE_TABLE[model] ?? PRICE_TABLE["_ollama_default"]!;
}
