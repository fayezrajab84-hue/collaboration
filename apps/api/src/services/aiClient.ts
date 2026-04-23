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
 *   3. Hard fallback to OLLAMA at config.OLLAMA_URL — preserves the current
 *      dev experience when nothing has been configured yet
 *
 * IMPLEMENTATION STATUS:
 *   - ollamaAdapter: implemented
 *   - anthropic / openai / gemini adapters: stubs (next PR)
 *
 * Every successful or failed call writes an AICallLog row best-effort. Logging
 * failures never block the caller; they're emitted to the structured logger.
 */

import axios, { AxiosError } from "axios";
import { z } from "zod";
import { AIProviderType, type AIServiceName } from "@prisma/client";
import prisma from "../db.js";
import { logger } from "../logger.js";
import { config } from "../config.js";
import { decrypt } from "./encryptionService.js";

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
  /** Per-call timeout override (ms). */
  timeoutMs?: number;
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
  opts: AIInvokeOptions<TSchema>,
): Promise<AIInvokeResult<TSchema>> {
  const resolved = await resolveProvider(opts.orgId, opts.service);
  const adapter  = ADAPTERS[resolved.providerType];

  const t0 = Date.now();
  try {
    const result = await adapter.invoke(resolved, opts);
    void writeCallLog({
      orgId:        opts.orgId,
      service:      opts.service,
      providerType: result.providerType,
      model:        result.model,
      usage:        result.usage,
      findingId:    opts.findingId,
      scanJobId:    opts.scanJobId,
      errorMessage: null,
    });
    return result;
  } catch (err) {
    const latencyMs = Date.now() - t0;
    const message   = err instanceof Error ? err.message : String(err);
    void writeCallLog({
      orgId:        opts.orgId,
      service:      opts.service,
      providerType: resolved.providerType,
      model:        resolved.model,
      usage:        { inputTokens: 0, outputTokens: 0, cachedInputTokens: 0, latencyMs, costUsd: 0 },
      findingId:    opts.findingId,
      scanJobId:    opts.scanJobId,
      errorMessage: message.slice(0, 500),
    });
    throw err;
  }
}

// ── Routing ──────────────────────────────────────────────────────────────────

/**
 * Pick the provider that handles a given (org, service) call.
 *
 * Precedence:
 *   1. AIServiceRouting (org-specific override per service)
 *   2. AIProvider with isDefault=true for that org
 *   3. Synthetic OLLAMA fallback to config.OLLAMA_URL — keeps dev UX working
 *      when an org hasn't configured anything yet.
 *
 * Throws AIError(PROVIDER_UNCONFIGURED) only if a routing override points at
 * an inactive provider — explicit misconfiguration, not "missing config".
 */
async function resolveProvider(
  orgId: string,
  service: AIServiceName,
): Promise<ResolvedProvider> {
  // 1. Per-service routing override
  const routing = await prisma.aIServiceRouting.findUnique({
    where:   { orgId_service: { orgId, service } },
    include: { provider: true },
  });
  if (routing) {
    if (!routing.provider.isActive) {
      throw new AIError(
        "PROVIDER_UNCONFIGURED",
        `AIServiceRouting for ${service} points at inactive ${routing.provider.type} provider`,
        routing.provider.type,
      );
    }
    return providerRowToResolved(routing.provider, routing.modelOverride);
  }

  // 2. Org default provider
  const def = await prisma.aIProvider.findFirst({
    where: { orgId, isDefault: true, isActive: true },
  });
  if (def) return providerRowToResolved(def, null);

  // 3. Synthetic OLLAMA fallback — same shape as a real row, no DB lookup
  return {
    providerType: AIProviderType.OLLAMA,
    model:        config.OLLAMA_MODEL,
    baseUrl:      config.OLLAMA_URL,
    apiKey:       undefined,
  };
}

function providerRowToResolved(
  row: { type: AIProviderType; encryptedConfig: unknown; defaultModel: string; baseUrl: string | null },
  modelOverride: string | null,
): ResolvedProvider {
  const model   = modelOverride ?? row.defaultModel;
  const baseUrl = row.baseUrl ?? undefined;

  let apiKey: string | undefined;
  if (row.type !== AIProviderType.OLLAMA) {
    // encryptedConfig is { apiKey: "<base64-cipher>" }
    const cfg = row.encryptedConfig as { apiKey?: string } | null;
    if (!cfg?.apiKey) {
      throw new AIError(
        "PROVIDER_UNCONFIGURED",
        `${row.type} provider missing encrypted apiKey`,
        row.type,
      );
    }
    try {
      apiKey = decrypt(cfg.apiKey);
    } catch (err) {
      throw new AIError(
        "UNAUTHORIZED",
        `Failed to decrypt ${row.type} apiKey: ${err instanceof Error ? err.message : String(err)}`,
        row.type,
      );
    }
  }

  return { providerType: row.type, model, baseUrl, apiKey };
}

// ── Provider adapter contract ────────────────────────────────────────────────

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

// ── Ollama adapter ───────────────────────────────────────────────────────────
// Local CPU/GPU inference. Free per-token cost. Used as the default for dev
// and as the hard fallback when an org hasn't configured a paid provider.

const OLLAMA_DEFAULT_TIMEOUT_MS = 360_000;  // 6 min — CPU inference can be slow

export const ollamaAdapter: ProviderAdapter = {
  async invoke<TSchema extends z.ZodTypeAny | undefined>(
    provider: ResolvedProvider,
    opts: AIInvokeOptions<TSchema>,
  ): Promise<AIInvokeResult<TSchema>> {
    const baseUrl = provider.baseUrl ?? config.OLLAMA_URL;
    const t0      = Date.now();

    const body: Record<string, unknown> = {
      model:    provider.model,
      messages: [
        { role: "system", content: opts.system },
        ...opts.messages.map((m) => ({ role: m.role, content: m.content })),
      ],
      stream:  false,
      options: {
        temperature: opts.temperature ?? 0.1,
        num_predict: opts.maxOutputTokens ?? 900,
        num_ctx:     4096,
      },
    };
    if (opts.schema) body["format"] = "json";

    let resp;
    try {
      resp = await axios.post(`${baseUrl}/api/chat`, body, {
        timeout: opts.timeoutMs ?? OLLAMA_DEFAULT_TIMEOUT_MS,
      });
    } catch (err) {
      throw mapAxiosError(err, AIProviderType.OLLAMA);
    }

    const rawText = String(resp.data?.message?.content ?? resp.data?.response ?? "");
    // Ollama reports prompt_eval_count + eval_count
    const inputTokens  = Number(resp.data?.prompt_eval_count ?? 0);
    const outputTokens = Number(resp.data?.eval_count ?? 0);

    const data = parseAndValidate(rawText, opts.schema) as AIInvokeResult<TSchema>["data"];

    return {
      data,
      rawText,
      providerType: AIProviderType.OLLAMA,
      model:        provider.model,
      usage: {
        inputTokens,
        outputTokens,
        cachedInputTokens: 0,
        latencyMs:         Date.now() - t0,
        costUsd:           0,    // local inference — track tokens for capacity, not billing
      },
    };
  },
};

// ── Stub adapters (next PRs) ─────────────────────────────────────────────────

// ── Anthropic adapter ────────────────────────────────────────────────────────
// Uses the public Messages API directly (no SDK dep). Applies cache_control
// breakpoint on the system prompt — security workloads reuse the same long
// system prompt across many findings, so the savings are substantial.

const ANTHROPIC_API_URL          = "https://api.anthropic.com/v1/messages";
const ANTHROPIC_VERSION          = "2023-06-01";
const ANTHROPIC_DEFAULT_TIMEOUT  = 120_000;
const ANTHROPIC_CACHE_MIN_TOKENS = 1024;   // Anthropic requires ≥1024 tokens to cache

export const anthropicAdapter: ProviderAdapter = {
  async invoke<TSchema extends z.ZodTypeAny | undefined>(
    provider: ResolvedProvider,
    opts: AIInvokeOptions<TSchema>,
  ): Promise<AIInvokeResult<TSchema>> {
    if (!provider.apiKey) {
      throw new AIError("PROVIDER_UNCONFIGURED", "Anthropic provider missing apiKey", AIProviderType.ANTHROPIC);
    }
    const t0 = Date.now();

    // Cache breakpoint: only attach when system prompt is large enough to
    // qualify for the cache (Anthropic returns an error otherwise).
    // Rough estimate: 4 chars ≈ 1 token.
    type SystemBlock = { type: "text"; text: string; cache_control?: { type: "ephemeral" } };
    const systemBlocks: SystemBlock[] = opts.system.length / 4 >= ANTHROPIC_CACHE_MIN_TOKENS
      ? [{ type: "text", text: opts.system, cache_control: { type: "ephemeral" } }]
      : [{ type: "text", text: opts.system }];

    // Structured output via JSON-only system suffix when a schema is supplied.
    // Anthropic doesn't expose a `response_format` field — we steer via prompt.
    if (opts.schema) {
      systemBlocks.push({
        type: "text",
        text: "\n\nRespond ONLY with a single valid JSON object. No prose, no markdown fences.",
      });
    }

    const body: Record<string, unknown> = {
      model:       provider.model,
      max_tokens:  opts.maxOutputTokens ?? 1024,
      temperature: opts.temperature ?? 0.1,
      system:      systemBlocks,
      messages:    opts.messages.map((m) => ({ role: m.role, content: m.content })),
    };

    let resp;
    try {
      resp = await axios.post(ANTHROPIC_API_URL, body, {
        timeout: opts.timeoutMs ?? ANTHROPIC_DEFAULT_TIMEOUT,
        headers: {
          "x-api-key":         provider.apiKey,
          "anthropic-version": ANTHROPIC_VERSION,
          "content-type":      "application/json",
        },
      });
    } catch (err) {
      throw mapAxiosError(err, AIProviderType.ANTHROPIC);
    }

    // content is an array of blocks; we asked for a single text response
    const blocks  = (resp.data?.content ?? []) as Array<{ type: string; text?: string }>;
    const rawText = blocks.filter((b) => b.type === "text").map((b) => b.text ?? "").join("");

    const usage = resp.data?.usage ?? {};
    const inputTokens       = Number(usage.input_tokens ?? 0);
    const outputTokens      = Number(usage.output_tokens ?? 0);
    const cachedInputTokens = Number(usage.cache_read_input_tokens ?? 0);
    const cacheCreated      = Number(usage.cache_creation_input_tokens ?? 0);

    const price   = priceFor(provider.model);
    // Anthropic bills cache writes at 1.25x input rate — approximate from input price
    const costUsd =
      (inputTokens       * price.inputPerMTok       / 1_000_000) +
      (cachedInputTokens * price.cachedInputPerMTok / 1_000_000) +
      (cacheCreated      * price.inputPerMTok * 1.25 / 1_000_000) +
      (outputTokens      * price.outputPerMTok      / 1_000_000);

    const data = parseAndValidate(rawText, opts.schema) as AIInvokeResult<TSchema>["data"];

    return {
      data,
      rawText,
      providerType: AIProviderType.ANTHROPIC,
      model:        provider.model,
      usage: {
        inputTokens,
        outputTokens,
        cachedInputTokens,
        latencyMs: Date.now() - t0,
        costUsd,
      },
    };
  },
};
// ── OpenAI adapter ───────────────────────────────────────────────────────────
// Chat Completions API. Uses response_format: json_object when a schema is
// supplied (works on all gpt-4o+ / gpt-5 models). Cached input is reported
// in usage.prompt_tokens_details.cached_tokens — automatic on prompts ≥1024
// tokens; no client-side opt-in needed.

const OPENAI_API_URL         = "https://api.openai.com/v1/chat/completions";
const OPENAI_DEFAULT_TIMEOUT = 120_000;

export const openaiAdapter: ProviderAdapter = {
  async invoke<TSchema extends z.ZodTypeAny | undefined>(
    provider: ResolvedProvider,
    opts: AIInvokeOptions<TSchema>,
  ): Promise<AIInvokeResult<TSchema>> {
    if (!provider.apiKey) {
      throw new AIError("PROVIDER_UNCONFIGURED", "OpenAI provider missing apiKey", AIProviderType.OPENAI);
    }
    const t0  = Date.now();
    const url = (provider.baseUrl ?? "https://api.openai.com") + "/v1/chat/completions";

    const body: Record<string, unknown> = {
      model:       provider.model,
      max_tokens:  opts.maxOutputTokens ?? 1024,
      temperature: opts.temperature ?? 0.1,
      messages: [
        { role: "system", content: opts.system },
        ...opts.messages.map((m) => ({ role: m.role, content: m.content })),
      ],
    };
    if (opts.schema) body["response_format"] = { type: "json_object" };

    let resp;
    try {
      resp = await axios.post(url === "/v1/chat/completions" ? OPENAI_API_URL : url, body, {
        timeout: opts.timeoutMs ?? OPENAI_DEFAULT_TIMEOUT,
        headers: {
          authorization:  `Bearer ${provider.apiKey}`,
          "content-type": "application/json",
        },
      });
    } catch (err) {
      throw mapAxiosError(err, AIProviderType.OPENAI);
    }

    const rawText = String(resp.data?.choices?.[0]?.message?.content ?? "");
    const usage   = resp.data?.usage ?? {};
    const inputTokens       = Number(usage.prompt_tokens ?? 0);
    const outputTokens      = Number(usage.completion_tokens ?? 0);
    const cachedInputTokens = Number(usage.prompt_tokens_details?.cached_tokens ?? 0);

    const price   = priceFor(provider.model);
    // OpenAI bills cached tokens at the cached rate; non-cached input at the input rate.
    const billableInput = Math.max(0, inputTokens - cachedInputTokens);
    const costUsd =
      (billableInput     * price.inputPerMTok       / 1_000_000) +
      (cachedInputTokens * price.cachedInputPerMTok / 1_000_000) +
      (outputTokens      * price.outputPerMTok      / 1_000_000);

    const data = parseAndValidate(rawText, opts.schema) as AIInvokeResult<TSchema>["data"];

    return {
      data,
      rawText,
      providerType: AIProviderType.OPENAI,
      model:        provider.model,
      usage: { inputTokens, outputTokens, cachedInputTokens, latencyMs: Date.now() - t0, costUsd },
    };
  },
};

// ── Gemini adapter ───────────────────────────────────────────────────────────
// Generative Language API (v1beta). Schema enforcement via responseMimeType +
// responseSchema. Cached tokens are reported in usageMetadata.cachedContentTokenCount.

const GEMINI_DEFAULT_TIMEOUT = 120_000;

export const geminiAdapter: ProviderAdapter = {
  async invoke<TSchema extends z.ZodTypeAny | undefined>(
    provider: ResolvedProvider,
    opts: AIInvokeOptions<TSchema>,
  ): Promise<AIInvokeResult<TSchema>> {
    if (!provider.apiKey) {
      throw new AIError("PROVIDER_UNCONFIGURED", "Gemini provider missing apiKey", AIProviderType.GEMINI);
    }
    const t0      = Date.now();
    const baseUrl = provider.baseUrl ?? "https://generativelanguage.googleapis.com";
    const url     = `${baseUrl}/v1beta/models/${encodeURIComponent(provider.model)}:generateContent?key=${encodeURIComponent(provider.apiKey)}`;

    const generationConfig: Record<string, unknown> = {
      temperature:     opts.temperature ?? 0.1,
      maxOutputTokens: opts.maxOutputTokens ?? 1024,
    };
    if (opts.schema) generationConfig["responseMimeType"] = "application/json";

    const body = {
      systemInstruction: { parts: [{ text: opts.system }] },
      contents: opts.messages.map((m) => ({
        // Gemini uses "model" instead of "assistant"
        role:  m.role === "assistant" ? "model" : "user",
        parts: [{ text: m.content }],
      })),
      generationConfig,
    };

    let resp;
    try {
      resp = await axios.post(url, body, {
        timeout: opts.timeoutMs ?? GEMINI_DEFAULT_TIMEOUT,
        headers: { "content-type": "application/json" },
      });
    } catch (err) {
      throw mapAxiosError(err, AIProviderType.GEMINI);
    }

    const candidate = resp.data?.candidates?.[0];
    const parts     = candidate?.content?.parts ?? [];
    const rawText   = parts.map((p: { text?: string }) => p.text ?? "").join("");

    const usage = resp.data?.usageMetadata ?? {};
    const inputTokens       = Number(usage.promptTokenCount ?? 0);
    const outputTokens      = Number(usage.candidatesTokenCount ?? 0);
    const cachedInputTokens = Number(usage.cachedContentTokenCount ?? 0);

    const price         = priceFor(provider.model);
    const billableInput = Math.max(0, inputTokens - cachedInputTokens);
    const costUsd =
      (billableInput     * price.inputPerMTok       / 1_000_000) +
      (cachedInputTokens * price.cachedInputPerMTok / 1_000_000) +
      (outputTokens      * price.outputPerMTok      / 1_000_000);

    const data = parseAndValidate(rawText, opts.schema) as AIInvokeResult<TSchema>["data"];

    return {
      data,
      rawText,
      providerType: AIProviderType.GEMINI,
      model:        provider.model,
      usage: { inputTokens, outputTokens, cachedInputTokens, latencyMs: Date.now() - t0, costUsd },
    };
  },
};

const ADAPTERS: Record<AIProviderType, ProviderAdapter> = {
  ANTHROPIC: anthropicAdapter,
  OPENAI:    openaiAdapter,
  GEMINI:    geminiAdapter,
  OLLAMA:    ollamaAdapter,
};

// ── Helpers ──────────────────────────────────────────────────────────────────

function parseAndValidate(rawText: string, schema: z.ZodTypeAny | undefined): unknown {
  if (!schema) return rawText;
  // Some providers (notably Gemini) wrap JSON in ```json ... ``` fences even
  // when responseMimeType=application/json is requested. Strip fences and
  // fall back to extracting the first {...} / [...] block if needed.
  const stripped = stripJsonFences(rawText);
  let parsed: unknown;
  try {
    parsed = JSON.parse(stripped);
  } catch {
    throw new AIError("INVALID_OUTPUT", `model returned non-JSON: ${rawText.slice(0, 200)}`);
  }
  const result = schema.safeParse(parsed);
  if (!result.success) {
    throw new AIError("INVALID_OUTPUT", `schema validation failed: ${result.error.message}`);
  }
  return result.data;
}

function stripJsonFences(text: string): string {
  let s = text.trim();
  // ```json ... ``` or ``` ... ```
  const fenceMatch = s.match(/^```(?:json|JSON)?\s*\n?([\s\S]*?)\n?```$/);
  if (fenceMatch && fenceMatch[1] !== undefined) {
    s = fenceMatch[1].trim();
  }
  // If still not parseable as-is, try extracting the first balanced { ... } or [ ... ]
  if (s.startsWith("{") || s.startsWith("[")) return s;
  const objStart = s.indexOf("{");
  const arrStart = s.indexOf("[");
  const start =
    objStart === -1 ? arrStart :
    arrStart === -1 ? objStart :
    Math.min(objStart, arrStart);
  if (start === -1) return s;
  const open = s[start];
  const close = open === "{" ? "}" : "]";
  const end = s.lastIndexOf(close);
  if (end > start) return s.slice(start, end + 1);
  return s;
}

function mapAxiosError(err: unknown, providerType: AIProviderType): AIError {
  if (err instanceof AxiosError) {
    const status = err.response?.status;
    if (err.code === "ECONNABORTED") return new AIError("TIMEOUT", err.message, providerType, true);
    if (status === 401 || status === 403) return new AIError("UNAUTHORIZED", err.message, providerType);
    if (status === 429) return new AIError("RATE_LIMITED", err.message, providerType, true);
    if (status && status >= 500) return new AIError("PROVIDER_DOWN", err.message, providerType, true);
    if (!err.response) return new AIError("PROVIDER_DOWN", err.message, providerType, true);
  }
  const msg = err instanceof Error ? err.message : String(err);
  return new AIError("PROVIDER_DOWN", msg, providerType, false);
}

interface CallLogInput {
  orgId: string;
  service: AIServiceName;
  providerType: AIProviderType;
  model: string;
  usage: AIInvokeResult<undefined>["usage"];
  findingId?: string;
  scanJobId?: string;
  errorMessage: string | null;
}

async function writeCallLog(input: CallLogInput): Promise<void> {
  try {
    await prisma.aICallLog.create({
      data: {
        orgId:             input.orgId,
        service:           input.service,
        providerType:      input.providerType,
        model:             input.model,
        inputTokens:       input.usage.inputTokens,
        outputTokens:      input.usage.outputTokens,
        cachedInputTokens: input.usage.cachedInputTokens,
        latencyMs:         input.usage.latencyMs,
        costUsd:           input.usage.costUsd,
        findingId:         input.findingId,
        scanJobId:         input.scanJobId,
        errorMessage:      input.errorMessage,
      },
    });
  } catch (err) {
    // Telemetry failures must never propagate
    logger.warn(`[aiClient] failed to write AICallLog: ${err instanceof Error ? err.message : String(err)}`);
  }
}

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
