/**
 * Settings → AI Providers tab.
 *
 * Configure per-org AI providers (Anthropic / OpenAI / Gemini / Ollama),
 * mark one as the default, optionally pin individual services to a specific
 * provider, and view 30-day usage / cost rollup.
 *
 * apiKeys are write-only — the API never returns them, only `hasApiKey:bool`.
 */

import { useState } from "react";
import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import { Bot, Check, X, Star, Zap, BarChart3 } from "lucide-react";
import {
  aiProvidersApi,
  type AIProvider,
  type AIProviderType,
  type AIServiceName,
} from "../../lib/api";
import { useToast } from "../../hooks/useToast";

const PROVIDER_META: Record<AIProviderType, { label: string; defaultModel: string; needsKey: boolean; needsBaseUrl: boolean; helpUrl: string }> = {
  ANTHROPIC: { label: "Anthropic Claude", defaultModel: "claude-sonnet-4-5",  needsKey: true,  needsBaseUrl: false, helpUrl: "https://console.anthropic.com/settings/keys" },
  OPENAI:    { label: "OpenAI",           defaultModel: "gpt-5",              needsKey: true,  needsBaseUrl: false, helpUrl: "https://platform.openai.com/api-keys" },
  GEMINI:    { label: "Google Gemini",    defaultModel: "gemini-2.5-pro",     needsKey: true,  needsBaseUrl: false, helpUrl: "https://aistudio.google.com/apikey" },
  OLLAMA:    { label: "Ollama (local)",   defaultModel: "qwen2.5-coder:7b",   needsKey: false, needsBaseUrl: true,  helpUrl: "https://ollama.com" },
};

const SERVICE_META: Record<AIServiceName, { label: string; description: string }> = {
  ANALYSE_FINDING: { label: "Finding Analysis",     description: "Drawer summary + remediation steps" },
  FP_TRIAGE:       { label: "False-Positive Triage", description: "Verdict + confidence per finding" },
  FIX_SUGGESTION:  { label: "Fix Suggestion",        description: "AI-generated unified diff patches" },
  SCAN_SUMMARY:    { label: "Scan Summary",          description: "Post-scan natural-language summary" },
  RISK_SCORE:      { label: "Risk Score",            description: "Per-target 0-100 risk reasoning" },
  CHAT:            { label: "Security Chat",         description: "Interactive Q&A about findings" },
  GROUP_INSIGHT:   { label: "Group Insight",         description: "Cluster-level commentary" },
};

// ── Provider card (one per type) ─────────────────────────────────────────────

function ProviderCard({ type, existing }: { type: AIProviderType; existing: AIProvider | undefined }) {
  const meta  = PROVIDER_META[type];
  const qc    = useQueryClient();
  const { toast } = useToast();

  const [apiKey,       setApiKey]       = useState("");
  const [defaultModel, setDefaultModel] = useState(existing?.defaultModel ?? meta.defaultModel);
  const [baseUrl,      setBaseUrl]      = useState(existing?.baseUrl ?? (type === "OLLAMA" ? "http://ollama:11434" : ""));

  const upsert = useMutation({
    mutationFn: () => aiProvidersApi.upsert(type, {
      apiKey:       apiKey || undefined,
      defaultModel,
      baseUrl:      baseUrl || undefined,
    }),
    onSuccess: () => {
      setApiKey("");
      qc.invalidateQueries({ queryKey: ["ai-providers"] });
      toast.success(`${meta.label} saved`);
    },
    onError: (err: unknown) => {
      toast.error(`Save failed: ${err instanceof Error ? err.message : "unknown error"}`);
    },
  });

  const remove = useMutation({
    mutationFn: () => aiProvidersApi.remove(type),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ["ai-providers"] });
      qc.invalidateQueries({ queryKey: ["ai-routings"] });
      toast.success(`${meta.label} removed`);
    },
  });

  const setDefault = useMutation({
    mutationFn: () => aiProvidersApi.setDefault(type),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ["ai-providers"] });
      toast.success(`${meta.label} is now the default`);
    },
  });

  const test = useMutation({
    mutationFn: () => aiProvidersApi.test(type),
    onSuccess: (data) => {
      toast.success(
        `${meta.label} OK · ${data.model} · ${data.latencyMs}ms · ${data.tokens?.input ?? 0}/${data.tokens?.output ?? 0} tok`,
      );
    },
    onError: (err: unknown) => {
      toast.error(`${meta.label} test failed: ${err instanceof Error ? err.message : "unknown error"}`);
    },
  });

  return (
    <div className="rounded-lg border border-gray-700 bg-gray-800/50 p-4 space-y-3">
      <div className="flex items-center justify-between">
        <div className="flex items-center gap-3">
          <Bot className="h-5 w-5 text-indigo-400" />
          <h3 className="font-medium text-white">{meta.label}</h3>
          {existing?.isDefault && (
            <span className="inline-flex items-center gap-1 rounded-full border border-gray-700 bg-gray-800/60 px-2 py-0.5 text-xs font-medium text-gray-300">
              <Star className="h-3 w-3 text-amber-400" /> Default
            </span>
          )}
          {existing && !existing.isDefault && (
            <span className="inline-flex items-center gap-1 rounded-full border border-gray-700 bg-gray-800/60 px-2 py-0.5 text-xs font-medium text-gray-300">
              <Check className="h-3 w-3 text-indigo-400" /> Configured
            </span>
          )}
        </div>
        <a href={meta.helpUrl} target="_blank" rel="noreferrer" className="text-xs text-indigo-400 hover:underline">
          Get key →
        </a>
      </div>

      <div className="grid grid-cols-1 gap-2">
        {meta.needsKey && (
          <div>
            <label className="block text-xs text-gray-400 mb-1">API Key</label>
            <input
              type="password"
              value={apiKey}
              onChange={(e) => setApiKey(e.target.value)}
              placeholder={existing?.hasApiKey ? "•••••••••••• (leave blank to keep)" : "sk-…"}
              className="w-full rounded border border-gray-700 bg-gray-900 px-3 py-1.5 text-sm text-gray-100"
              autoComplete="off"
            />
          </div>
        )}
        {meta.needsBaseUrl && (
          <div>
            <label className="block text-xs text-gray-400 mb-1">Base URL</label>
            <input
              type="url"
              value={baseUrl}
              onChange={(e) => setBaseUrl(e.target.value)}
              placeholder="http://ollama:11434"
              className="w-full rounded border border-gray-700 bg-gray-900 px-3 py-1.5 text-sm text-gray-100"
            />
          </div>
        )}
        <div>
          <label className="block text-xs text-gray-400 mb-1">Default Model</label>
          <input
            type="text"
            value={defaultModel}
            onChange={(e) => setDefaultModel(e.target.value)}
            className="w-full rounded border border-gray-700 bg-gray-900 px-3 py-1.5 text-sm text-gray-100"
          />
        </div>
      </div>

      <div className="flex flex-wrap gap-2 pt-1">
        <button
          onClick={() => upsert.mutate()}
          disabled={upsert.isPending || (meta.needsKey && !existing?.hasApiKey && !apiKey)}
          className="rounded bg-indigo-700 px-3 py-1.5 text-xs font-medium text-white hover:bg-indigo-600 disabled:opacity-40"
        >
          {upsert.isPending ? "Saving…" : existing ? "Update" : "Save"}
        </button>
        {existing && !existing.isDefault && (
          <button
            onClick={() => setDefault.mutate()}
            disabled={setDefault.isPending}
            className="group rounded border border-gray-700 bg-gray-900/60 px-3 py-1.5 text-xs text-gray-300 hover:border-gray-600 hover:text-white disabled:opacity-40"
          >
            <Star className="mr-1 inline h-3 w-3 text-gray-500 group-hover:text-amber-400" /> Make default
          </button>
        )}
        {existing && (
          <button
            onClick={() => test.mutate()}
            disabled={test.isPending}
            className="group rounded border border-gray-700 bg-gray-900/60 px-3 py-1.5 text-xs text-gray-300 hover:border-gray-600 hover:text-white disabled:opacity-40"
          >
            <Zap className="mr-1 inline h-3 w-3 text-gray-500 group-hover:text-indigo-400" /> {test.isPending ? "Testing…" : "Test"}
          </button>
        )}
        {existing && (
          <button
            onClick={() => remove.mutate()}
            disabled={remove.isPending}
            className="group ml-auto rounded border border-gray-700 bg-gray-900/60 px-3 py-1.5 text-xs text-gray-400 hover:border-red-900/60 hover:text-red-400 disabled:opacity-40"
          >
            <X className="mr-1 inline h-3 w-3 text-gray-500 group-hover:text-red-400" /> Remove
          </button>
        )}
      </div>
    </div>
  );
}

// ── Per-service routing matrix ───────────────────────────────────────────────

function RoutingMatrix({ providers }: { providers: AIProvider[] }) {
  const qc       = useQueryClient();
  const { toast } = useToast();

  const { data: routings = [] } = useQuery({
    queryKey: ["ai-routings"],
    queryFn:  aiProvidersApi.routings,
  });

  const setRouting = useMutation({
    mutationFn: ({ service, providerId }: { service: AIServiceName; providerId: string }) =>
      aiProvidersApi.setRouting(service, { providerId }),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ["ai-routings"] });
      toast.success("Routing saved");
    },
  });

  const clearRouting = useMutation({
    mutationFn: (service: AIServiceName) => aiProvidersApi.clearRouting(service),
    onSuccess: () => qc.invalidateQueries({ queryKey: ["ai-routings"] }),
  });

  const services = Object.keys(SERVICE_META) as AIServiceName[];
  const routingByService = new Map(routings.map((r) => [r.service, r]));

  if (providers.length === 0) {
    return (
      <p className="text-sm text-gray-500 italic">
        Configure at least one provider above to enable per-service routing.
      </p>
    );
  }

  return (
    <div className="overflow-hidden rounded-lg border border-gray-700">
      <table className="w-full text-sm">
        <thead className="bg-gray-900/50 text-xs uppercase text-gray-400">
          <tr>
            <th className="px-3 py-2 text-left">Service</th>
            <th className="px-3 py-2 text-left">Routed to</th>
            <th className="px-3 py-2"></th>
          </tr>
        </thead>
        <tbody className="divide-y divide-gray-800">
          {services.map((svc) => {
            const meta    = SERVICE_META[svc];
            const current = routingByService.get(svc);
            return (
              <tr key={svc}>
                <td className="px-3 py-2 align-top">
                  <div className="font-medium text-gray-100">{meta.label}</div>
                  <div className="text-xs text-gray-500">{meta.description}</div>
                </td>
                <td className="px-3 py-2">
                  <select
                    value={current?.providerId ?? ""}
                    onChange={(e) => {
                      const v = e.target.value;
                      if (!v) clearRouting.mutate(svc);
                      else    setRouting.mutate({ service: svc, providerId: v });
                    }}
                    className="rounded border border-gray-700 bg-gray-900 px-2 py-1 text-xs text-gray-100"
                  >
                    <option value="">— Use org default —</option>
                    {providers.map((p) => (
                      <option key={p.id} value={p.id}>
                        {PROVIDER_META[p.type].label} · {p.defaultModel}
                      </option>
                    ))}
                  </select>
                </td>
                <td className="px-3 py-2 text-right">
                  {current && (
                    <button
                      onClick={() => clearRouting.mutate(svc)}
                      className="text-xs text-gray-500 hover:text-gray-300"
                    >
                      Reset
                    </button>
                  )}
                </td>
              </tr>
            );
          })}
        </tbody>
      </table>
    </div>
  );
}

// ── 30-day usage rollup ──────────────────────────────────────────────────────

function UsagePanel() {
  const { data, isLoading } = useQuery({
    queryKey: ["ai-usage"],
    queryFn:  aiProvidersApi.usage,
  });

  if (isLoading) return <p className="text-sm text-gray-500">Loading usage…</p>;
  if (!data || !data.totals || data.totals._count === 0) {
    return <p className="text-sm text-gray-500 italic">No AI calls in the last 30 days yet.</p>;
  }

  const t = data.totals;
  const fmt = (n: number | string | null | undefined) =>
    n == null ? "0" : Number(n).toLocaleString(undefined, { maximumFractionDigits: 4 });

  return (
    <div className="space-y-4">
      <div className="grid grid-cols-2 gap-3 sm:grid-cols-4">
        <Stat label="Calls"          value={fmt(t._count)} />
        <Stat label="Input tokens"   value={fmt(t._sum.inputTokens)} />
        <Stat label="Output tokens"  value={fmt(t._sum.outputTokens)} />
        <Stat label="Cost (USD)"     value={`$${fmt(t._sum.costUsd)}`} />
      </div>

      <div>
        <h4 className="mb-2 text-xs font-semibold uppercase text-gray-400">By service</h4>
        <div className="space-y-1">
          {data.byService.map((row) => (
            <Row
              key={row.service}
              label={SERVICE_META[row.service]?.label ?? row.service}
              calls={row._count}
              cost={Number(row._sum.costUsd ?? 0)}
            />
          ))}
        </div>
      </div>

      <div>
        <h4 className="mb-2 text-xs font-semibold uppercase text-gray-400">By provider · model</h4>
        <div className="space-y-1">
          {data.byProvider.map((row) => (
            <Row
              key={`${row.providerType}-${row.model}`}
              label={`${PROVIDER_META[row.providerType]?.label} · ${row.model}`}
              calls={row._count}
              cost={Number(row._sum.costUsd ?? 0)}
            />
          ))}
        </div>
      </div>
    </div>
  );
}

function Stat({ label, value }: { label: string; value: string }) {
  return (
    <div className="rounded-lg border border-gray-700 bg-gray-800/50 px-3 py-2">
      <div className="text-xs text-gray-400">{label}</div>
      <div className="mt-0.5 font-mono text-sm text-white">{value}</div>
    </div>
  );
}

function Row({ label, calls, cost }: { label: string; calls: number; cost: number }) {
  return (
    <div className="flex items-center justify-between rounded border border-gray-800 bg-gray-900/30 px-3 py-1.5 text-xs">
      <span className="text-gray-300">{label}</span>
      <span className="font-mono text-gray-400">
        {calls} calls · ${cost.toLocaleString(undefined, { maximumFractionDigits: 4 })}
      </span>
    </div>
  );
}

// ── Tab entrypoint ───────────────────────────────────────────────────────────

export default function AIProvidersTab() {
  const { data: providers = [], isLoading } = useQuery({
    queryKey: ["ai-providers"],
    queryFn:  aiProvidersApi.list,
  });

  const byType = new Map(providers.map((p) => [p.type, p]));
  const types: AIProviderType[] = ["ANTHROPIC", "OPENAI", "GEMINI", "OLLAMA"];

  return (
    <div className="space-y-6">
      <div>
        <h2 className="text-base font-semibold text-white">AI Providers</h2>
        <p className="mt-1 text-sm text-gray-400">
          Configure one or more LLM backends. The default provider handles every AI feature
          unless a per-service override below routes it elsewhere.
        </p>
      </div>

      {isLoading ? (
        <p className="text-sm text-gray-500">Loading…</p>
      ) : (
        <div className="grid grid-cols-1 gap-3 lg:grid-cols-2">
          {types.map((t) => (
            <ProviderCard key={t} type={t} existing={byType.get(t)} />
          ))}
        </div>
      )}

      <div>
        <h3 className="text-sm font-semibold text-white">Per-service routing</h3>
        <p className="mb-3 mt-1 text-xs text-gray-500">
          Pin individual AI services to a specific provider — e.g. cheap local Ollama for
          finding analysis, paid Anthropic for FP triage where accuracy matters most.
        </p>
        <RoutingMatrix providers={providers} />
      </div>

      <div>
        <div className="mb-3 flex items-center gap-2">
          <BarChart3 className="h-4 w-4 text-indigo-400" />
          <h3 className="text-sm font-semibold text-white">Last 30 days</h3>
        </div>
        <UsagePanel />
      </div>
    </div>
  );
}
