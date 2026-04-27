/**
 * Policies tab — manage security-gate policies used by the PR check run.
 * Admins can create/edit/delete policies; each policy is a list of rules
 * (severity threshold, new-only block, SLA, ignore dev deps, required
 * scan types) applied to one-or-more repositories.
 */
import { useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { Plus, Trash2, ShieldCheck, Edit3, Check, X } from "lucide-react";
import { apiClient } from "../../lib/api";
import { useToast } from "../../hooks/useToast";
import Can from "../Can";

type RuleType =
  | "SEVERITY_THRESHOLD"
  | "BLOCK_ON_NEW_ONLY"
  | "SLA_DAYS"
  | "IGNORE_DEV_DEPS"
  | "SCAN_TYPE_REQUIRED";

interface PolicyRule {
  id?:    string;
  type:   RuleType;
  config: Record<string, unknown>;
}

interface Policy {
  id:             string;
  name:           string;
  description?:   string | null;
  isDefault:      boolean;
  isActive:       boolean;
  repoIds:        string[];
  branchPatterns: string[];
  rules:          PolicyRule[];
  _count?:        { repositories: number };
}

const RULE_LABELS: Record<RuleType, string> = {
  SEVERITY_THRESHOLD: "Severity threshold",
  BLOCK_ON_NEW_ONLY:  "Block on new-only",
  SLA_DAYS:           "SLA days",
  IGNORE_DEV_DEPS:    "Ignore dev dependencies",
  SCAN_TYPE_REQUIRED: "Scan types required",
};

const RULE_DEFAULTS: Record<RuleType, Record<string, unknown>> = {
  SEVERITY_THRESHOLD: { severity: "CRITICAL", maxCount: 0 },
  BLOCK_ON_NEW_ONLY:  { severity: "HIGH",     maxCount: 0 },
  SLA_DAYS:           { severity: "HIGH",     maxDays: 30 },
  IGNORE_DEV_DEPS:    { enabled: true },
  SCAN_TYPE_REQUIRED: { scanTypes: ["SAST", "SCA"] },
};

async function listPolicies(): Promise<Policy[]> {
  return (await apiClient.get<Policy[]>("/policies")).data;
}

export default function PoliciesTab() {
  const qc = useQueryClient();
  const toast = useToast().toast;
  const [editing, setEditing] = useState<Policy | null>(null);

  const { data: policies = [], isLoading } = useQuery({
    queryKey: ["policies"],
    queryFn:  listPolicies,
  });

  const deleteMut = useMutation({
    mutationFn: (id: string) => apiClient.delete(`/policies/${id}`),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ["policies"] });
      toast.success("Policy deleted");
    },
    onError: () => toast.error("Failed to delete policy"),
  });

  if (editing) {
    return <PolicyEditor policy={editing} onClose={() => setEditing(null)} />;
  }

  return (
    <Can
      role="ADMIN"
      fallback={
        <div className="rounded-md border border-gray-800 bg-gray-900/40 p-6 text-center text-xs text-gray-500">
          Policy editing is restricted to ADMIN+ roles. View-only access
          to applied policies will surface here once that's wired up.
        </div>
      }
    >
    <div>
      <div className="mb-4 flex items-center justify-between">
        <div>
          <h2 className="text-lg font-semibold text-white">Security Policies</h2>
          <p className="text-xs text-gray-500 mt-0.5">
            Policies gate pull-request check runs. Assign per-repo or set a default for the org.
          </p>
        </div>
        <button
          onClick={() => setEditing({
            id: "", name: "", description: "", isDefault: false, isActive: true,
            repoIds: [], branchPatterns: [], rules: [],
          })}
          className="flex items-center gap-1.5 rounded-md bg-indigo-600 px-3 py-1.5 text-xs font-medium text-white hover:bg-indigo-500"
        >
          <Plus className="h-3.5 w-3.5" /> New policy
        </button>
      </div>

      {isLoading ? (
        <p className="text-sm text-gray-500">Loading…</p>
      ) : policies.length === 0 ? (
        <div className="rounded-lg border border-dashed border-gray-700 p-8 text-center">
          <ShieldCheck className="mx-auto mb-2 h-6 w-6 text-gray-600" />
          <p className="text-sm text-gray-400">No policies yet — PR check runs will report a neutral verdict.</p>
        </div>
      ) : (
        <ul className="divide-y divide-gray-800 rounded-lg border border-gray-800 overflow-hidden">
          {policies.map((p) => (
            <li key={p.id} className="flex items-start justify-between gap-3 bg-gray-900 p-3">
              <div className="min-w-0">
                <div className="flex items-center gap-2">
                  <span className="font-medium text-white">{p.name}</span>
                  {p.isDefault && (
                    <span className="rounded bg-indigo-900/60 px-1.5 py-0.5 text-[10px] font-semibold uppercase tracking-wide text-indigo-200">Default</span>
                  )}
                  {!p.isActive && (
                    <span className="rounded bg-gray-800 px-1.5 py-0.5 text-[10px] font-semibold uppercase tracking-wide text-gray-400">Inactive</span>
                  )}
                </div>
                {p.description && (
                  <p className="mt-0.5 text-xs text-gray-500 line-clamp-2">{p.description}</p>
                )}
                <p className="mt-1 text-[11px] text-gray-600">
                  {p.rules.length} rule{p.rules.length === 1 ? "" : "s"} ·
                  {" "}{p._count?.repositories ?? 0} repo{(p._count?.repositories ?? 0) === 1 ? "" : "s"}
                </p>
              </div>
              <div className="flex shrink-0 items-center gap-1">
                <button
                  onClick={() => setEditing(p)}
                  className="rounded p-1.5 text-gray-400 hover:bg-gray-800 hover:text-gray-200"
                  title="Edit"
                >
                  <Edit3 className="h-4 w-4" />
                </button>
                <button
                  onClick={() => {
                    if (confirm(`Delete policy "${p.name}"?`)) deleteMut.mutate(p.id);
                  }}
                  className="rounded p-1.5 text-gray-400 hover:bg-red-950/50 hover:text-red-300"
                  title="Delete"
                >
                  <Trash2 className="h-4 w-4" />
                </button>
              </div>
            </li>
          ))}
        </ul>
      )}
    </div>
    </Can>
  );
}

function PolicyEditor({ policy, onClose }: { policy: Policy; onClose: () => void }) {
  const qc = useQueryClient();
  const toast = useToast().toast;
  const [form, setForm] = useState<Policy>({
    ...policy,
    rules: policy.rules.length > 0 ? policy.rules : [],
  });

  const saveMut = useMutation({
    mutationFn: async () => {
      const body = {
        name: form.name,
        description: form.description ?? undefined,
        isDefault: form.isDefault,
        isActive: form.isActive,
        repoIds: form.repoIds,
        branchPatterns: form.branchPatterns,
        rules: form.rules.map((r) => ({ type: r.type, config: r.config })),
      };
      if (form.id) {
        return apiClient.put(`/policies/${form.id}`, body);
      }
      return apiClient.post("/policies", body);
    },
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ["policies"] });
      toast.success(form.id ? "Policy saved" : "Policy created");
      onClose();
    },
    onError: () => toast.error("Failed to save policy"),
  });

  const updateRule = (idx: number, patch: Partial<PolicyRule>) => {
    setForm((f) => ({
      ...f,
      rules: f.rules.map((r, i) => (i === idx ? { ...r, ...patch } : r)),
    }));
  };

  const addRule = (type: RuleType) => {
    setForm((f) => ({
      ...f,
      rules: [...f.rules, { type, config: { ...RULE_DEFAULTS[type] } }],
    }));
  };

  return (
    <div>
      <button
        onClick={onClose}
        className="mb-4 flex items-center gap-1 text-xs text-gray-400 hover:text-gray-200"
      >
        ← Back to policies
      </button>

      <h2 className="mb-4 text-lg font-semibold text-white">
        {form.id ? "Edit policy" : "New policy"}
      </h2>

      <div className="space-y-4">
        <div>
          <label className="mb-1 block text-xs font-medium text-gray-400">Name</label>
          <input
            value={form.name}
            onChange={(e) => setForm({ ...form, name: e.target.value })}
            className="w-full rounded-md border border-gray-700 bg-gray-950 px-3 py-1.5 text-sm text-white"
          />
        </div>

        <div>
          <label className="mb-1 block text-xs font-medium text-gray-400">Description</label>
          <textarea
            value={form.description ?? ""}
            onChange={(e) => setForm({ ...form, description: e.target.value })}
            rows={2}
            className="w-full rounded-md border border-gray-700 bg-gray-950 px-3 py-1.5 text-sm text-white"
          />
        </div>

        <div className="flex items-center gap-6">
          <label className="flex items-center gap-2 text-sm text-gray-300">
            <input
              type="checkbox"
              checked={form.isDefault}
              onChange={(e) => setForm({ ...form, isDefault: e.target.checked })}
            />
            Default policy
          </label>
          <label className="flex items-center gap-2 text-sm text-gray-300">
            <input
              type="checkbox"
              checked={form.isActive}
              onChange={(e) => setForm({ ...form, isActive: e.target.checked })}
            />
            Active
          </label>
        </div>

        <div>
          <div className="mb-2 flex items-center justify-between">
            <label className="text-xs font-medium text-gray-400">Rules</label>
            <select
              onChange={(e) => { if (e.target.value) { addRule(e.target.value as RuleType); e.target.value = ""; } }}
              defaultValue=""
              className="rounded-md border border-gray-700 bg-gray-950 px-2 py-1 text-xs text-gray-300"
            >
              <option value="" disabled>+ Add rule…</option>
              {(Object.keys(RULE_LABELS) as RuleType[]).map((t) => (
                <option key={t} value={t}>{RULE_LABELS[t]}</option>
              ))}
            </select>
          </div>

          <div className="space-y-2">
            {form.rules.map((rule, idx) => (
              <div key={idx} className="rounded-lg border border-gray-800 bg-gray-950 p-3">
                <div className="mb-2 flex items-center justify-between">
                  <span className="text-xs font-semibold uppercase tracking-wide text-indigo-300">
                    {RULE_LABELS[rule.type]}
                  </span>
                  <button
                    onClick={() => setForm((f) => ({ ...f, rules: f.rules.filter((_, i) => i !== idx) }))}
                    className="text-gray-500 hover:text-red-300"
                  >
                    <X className="h-3.5 w-3.5" />
                  </button>
                </div>
                <RuleConfigEditor rule={rule} onChange={(patch) => updateRule(idx, patch)} />
              </div>
            ))}
            {form.rules.length === 0 && (
              <p className="text-xs text-gray-600">No rules — policy will always pass.</p>
            )}
          </div>
        </div>

        <div className="flex items-center gap-2 pt-2">
          <button
            disabled={saveMut.isPending || !form.name.trim()}
            onClick={() => saveMut.mutate()}
            className="flex items-center gap-1.5 rounded-md bg-indigo-600 px-3 py-1.5 text-sm font-medium text-white hover:bg-indigo-500 disabled:opacity-50"
          >
            <Check className="h-3.5 w-3.5" /> Save
          </button>
          <button
            onClick={onClose}
            className="rounded-md border border-gray-700 px-3 py-1.5 text-sm text-gray-300 hover:bg-gray-800"
          >
            Cancel
          </button>
        </div>
      </div>
    </div>
  );
}

function RuleConfigEditor({
  rule,
  onChange,
}: {
  rule: PolicyRule;
  onChange: (patch: Partial<PolicyRule>) => void;
}) {
  const c = rule.config as Record<string, unknown>;
  const set = (k: string, v: unknown) => onChange({ config: { ...c, [k]: v } });

  if (rule.type === "SEVERITY_THRESHOLD" || rule.type === "BLOCK_ON_NEW_ONLY") {
    return (
      <div className="flex gap-3">
        <label className="flex-1 text-xs text-gray-400">
          Minimum severity
          <select
            value={(c.severity as string) ?? "CRITICAL"}
            onChange={(e) => set("severity", e.target.value)}
            className="mt-1 block w-full rounded border border-gray-700 bg-gray-900 px-2 py-1 text-sm text-white"
          >
            {["CRITICAL", "HIGH", "MEDIUM", "LOW"].map((s) => <option key={s}>{s}</option>)}
          </select>
        </label>
        <label className="flex-1 text-xs text-gray-400">
          Max count
          <input
            type="number" min={0}
            value={(c.maxCount as number) ?? 0}
            onChange={(e) => set("maxCount", Number(e.target.value))}
            className="mt-1 block w-full rounded border border-gray-700 bg-gray-900 px-2 py-1 text-sm text-white"
          />
        </label>
      </div>
    );
  }

  if (rule.type === "SLA_DAYS") {
    return (
      <div className="flex gap-3">
        <label className="flex-1 text-xs text-gray-400">
          Minimum severity
          <select
            value={(c.severity as string) ?? "HIGH"}
            onChange={(e) => set("severity", e.target.value)}
            className="mt-1 block w-full rounded border border-gray-700 bg-gray-900 px-2 py-1 text-sm text-white"
          >
            {["CRITICAL", "HIGH", "MEDIUM", "LOW"].map((s) => <option key={s}>{s}</option>)}
          </select>
        </label>
        <label className="flex-1 text-xs text-gray-400">
          Max open days
          <input
            type="number" min={1}
            value={(c.maxDays as number) ?? 30}
            onChange={(e) => set("maxDays", Number(e.target.value))}
            className="mt-1 block w-full rounded border border-gray-700 bg-gray-900 px-2 py-1 text-sm text-white"
          />
        </label>
      </div>
    );
  }

  if (rule.type === "IGNORE_DEV_DEPS") {
    return (
      <label className="flex items-center gap-2 text-xs text-gray-400">
        <input
          type="checkbox"
          checked={(c.enabled as boolean) ?? true}
          onChange={(e) => set("enabled", e.target.checked)}
        />
        Drop SCA findings under devDependencies / test paths
      </label>
    );
  }

  if (rule.type === "SCAN_TYPE_REQUIRED") {
    const current = (c.scanTypes as string[]) ?? [];
    const types = ["SAST", "SCA", "SECRET", "IAC", "CONTAINER", "DAST"];
    return (
      <div className="flex flex-wrap gap-2">
        {types.map((t) => {
          const active = current.includes(t);
          return (
            <button
              key={t}
              onClick={() =>
                set("scanTypes", active ? current.filter((x) => x !== t) : [...current, t])
              }
              className={`rounded-full border px-2.5 py-0.5 text-xs ${
                active
                  ? "border-indigo-700 bg-indigo-900/40 text-indigo-200"
                  : "border-gray-700 text-gray-400 hover:bg-gray-900"
              }`}
            >
              {t}
            </button>
          );
        })}
      </div>
    );
  }

  return null;
}
