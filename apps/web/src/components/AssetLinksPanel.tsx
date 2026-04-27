/**
 * AssetLinksPanel — Phase 27 Slice A operator-declared asset relations.
 *
 * Renders a small section on Repository / Container / Domain detail screens
 * that lets ADMIN+ users link assets together, building the foundational
 * graph that the Phase 27 correlation engine walks at query time.
 *
 * Three flavours, one UI shape:
 *   • RepoAssetLinksPanel       — free-text chips for container image refs
 *                                 (e.g. "myorg/api:1.2.3"). Refs are strings,
 *                                 not IDs, because they survive Container row
 *                                 recreation and are friendly to type.
 *   • ContainerAssetLinksPanel  — single-select source repo + multi-select
 *                                 serving domains.
 *   • DomainAssetLinksPanel     — multi-select serving containers.
 *
 * Honest UI defaults the panel to its current state; "Save" only enables when
 * the user has actually changed something. Validation errors from the API
 * (cross-org reference, missing ID) surface inline rather than via a toast so
 * the operator can correlate them to the chip that's wrong.
 */
import { useEffect, useMemo, useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { Link2, Plus, X, Save } from "lucide-react";
import { reposApi, containersApi, domainsApi } from "../lib/api";
import Can from "./Can";
import { useToast } from "../hooks/useToast";
import type { Repository, Container, Domain } from "@devsecops/types";

// ── Shared layout ──────────────────────────────────────────────────────────

function PanelShell({
  title,
  description,
  children,
}: {
  title:       string;
  description: string;
  children:    React.ReactNode;
}) {
  return (
    <div className="rounded-xl border border-gray-800 bg-gray-900/40 p-5">
      <div className="mb-3 flex items-start gap-2">
        <Link2 className="mt-0.5 h-4 w-4 text-indigo-400" />
        <div>
          <h3 className="text-sm font-semibold text-white">{title}</h3>
          <p className="mt-0.5 text-xs text-gray-500">{description}</p>
        </div>
      </div>
      {children}
    </div>
  );
}

// ── Free-text chip editor (Repository → image refs) ────────────────────────

function FreeTextChips({
  value,
  onChange,
  placeholder,
  disabled,
}: {
  value:       string[];
  onChange:    (next: string[]) => void;
  placeholder: string;
  disabled?:   boolean;
}) {
  const [draft, setDraft] = useState("");

  const commit = () => {
    const v = draft.trim();
    if (v.length === 0) return;
    if (value.includes(v)) { setDraft(""); return; }
    onChange([...value, v]);
    setDraft("");
  };

  const remove = (v: string) => onChange(value.filter((x) => x !== v));

  return (
    <div>
      <div className="flex flex-wrap items-center gap-1.5">
        {value.length === 0 && (
          <span className="text-xs text-gray-600">No links yet — type a value below to add one.</span>
        )}
        {value.map((v) => (
          <span
            key={v}
            className="inline-flex items-center gap-1 rounded-full border border-gray-700 bg-gray-800 px-2.5 py-0.5 font-mono text-xs text-gray-200"
          >
            {v}
            {!disabled && (
              <button
                type="button"
                onClick={() => remove(v)}
                className="text-gray-500 hover:text-red-400"
                aria-label={`Remove ${v}`}
              >
                <X className="h-3 w-3" />
              </button>
            )}
          </span>
        ))}
      </div>
      {!disabled && (
        <div className="mt-2 flex gap-2">
          <input
            type="text"
            value={draft}
            onChange={(e) => setDraft(e.target.value)}
            onKeyDown={(e) => {
              if (e.key === "Enter") { e.preventDefault(); commit(); }
            }}
            placeholder={placeholder}
            className="flex-1 rounded bg-gray-800 px-3 py-1.5 font-mono text-xs text-gray-200 placeholder-gray-600 focus:outline-none focus:ring-1 focus:ring-indigo-500"
          />
          <button
            type="button"
            onClick={commit}
            disabled={draft.trim().length === 0}
            className="inline-flex items-center gap-1 rounded bg-gray-800 px-3 py-1.5 text-xs text-gray-300 hover:bg-gray-700 disabled:opacity-50"
          >
            <Plus className="h-3 w-3" /> Add
          </button>
        </div>
      )}
    </div>
  );
}

// ── ID multi-select (pick from existing assets) ────────────────────────────

interface AssetOption {
  id:    string;
  label: string;
}

function AssetIdMultiSelect({
  options,
  value,
  onChange,
  emptyLabel,
  disabled,
}: {
  options:    AssetOption[];
  value:      string[];
  onChange:   (next: string[]) => void;
  emptyLabel: string;
  disabled?:  boolean;
}) {
  const selected = useMemo(() => new Set(value), [value]);
  const labelById = useMemo(
    () => new Map(options.map((o) => [o.id, o.label] as const)),
    [options],
  );

  const toggle = (id: string) => {
    if (selected.has(id)) onChange(value.filter((x) => x !== id));
    else onChange([...value, id]);
  };

  return (
    <div>
      <div className="mb-2 flex flex-wrap items-center gap-1.5">
        {value.length === 0 && (
          <span className="text-xs text-gray-600">{emptyLabel}</span>
        )}
        {value.map((id) => (
          <span
            key={id}
            className="inline-flex items-center gap-1 rounded-full border border-gray-700 bg-gray-800 px-2.5 py-0.5 text-xs text-gray-200"
          >
            {labelById.get(id) ?? id}
            {!disabled && (
              <button
                type="button"
                onClick={() => toggle(id)}
                className="text-gray-500 hover:text-red-400"
                aria-label={`Remove ${labelById.get(id) ?? id}`}
              >
                <X className="h-3 w-3" />
              </button>
            )}
          </span>
        ))}
      </div>
      {!disabled && (
        <div className="max-h-40 space-y-0.5 overflow-y-auto rounded border border-gray-800 bg-gray-900/40 p-1">
          {options.length === 0 ? (
            <div className="px-2 py-1.5 text-xs text-gray-600">No options available — add some first on the relevant page.</div>
          ) : (
            options.map((o) => {
              const isSelected = selected.has(o.id);
              return (
                <label
                  key={o.id}
                  className={`flex cursor-pointer items-center gap-2 rounded px-2 py-1 text-xs transition-colors ${
                    isSelected ? "bg-indigo-500/10 text-indigo-200" : "text-gray-300 hover:bg-gray-800"
                  }`}
                >
                  <input
                    type="checkbox"
                    checked={isSelected}
                    onChange={() => toggle(o.id)}
                    className="h-3 w-3 rounded border-gray-600 bg-gray-700 accent-indigo-500"
                  />
                  <span className="truncate">{o.label}</span>
                </label>
              );
            })
          )}
        </div>
      )}
    </div>
  );
}

// ── Single-select (Container → source repository) ──────────────────────────

function AssetIdSingleSelect({
  options,
  value,
  onChange,
  disabled,
}: {
  options:   AssetOption[];
  value:     string | null;
  onChange:  (next: string | null) => void;
  disabled?: boolean;
}) {
  return (
    <select
      value={value ?? ""}
      onChange={(e) => onChange(e.target.value === "" ? null : e.target.value)}
      disabled={disabled}
      className="w-full rounded bg-gray-800 px-3 py-1.5 text-xs text-gray-200 focus:outline-none focus:ring-1 focus:ring-indigo-500 disabled:opacity-50"
    >
      <option value="">— None —</option>
      {options.map((o) => (
        <option key={o.id} value={o.id}>{o.label}</option>
      ))}
    </select>
  );
}

// ── Save bar (shared shell) ────────────────────────────────────────────────

function SaveBar({
  dirty,
  saving,
  error,
  onSave,
  onReset,
}: {
  dirty:   boolean;
  saving:  boolean;
  error:   string | null;
  onSave:  () => void;
  onReset: () => void;
}) {
  return (
    <div className="mt-3 flex items-center gap-2">
      <button
        type="button"
        onClick={onSave}
        disabled={!dirty || saving}
        className="inline-flex items-center gap-1.5 rounded-lg bg-indigo-700 px-3 py-1.5 text-xs font-medium text-white hover:bg-indigo-600 disabled:opacity-50"
      >
        <Save className="h-3 w-3" /> {saving ? "Saving…" : "Save links"}
      </button>
      {dirty && !saving && (
        <button
          type="button"
          onClick={onReset}
          className="rounded px-3 py-1.5 text-xs text-gray-400 hover:text-gray-200"
        >
          Reset
        </button>
      )}
      {error && <span className="text-xs text-red-400">{error}</span>}
    </div>
  );
}

// ── Repository panel ───────────────────────────────────────────────────────

export function RepoAssetLinksPanel({ repo }: { repo: Repository }) {
  const qc = useQueryClient();
  const { toast } = useToast();
  const initial = repo.buildsContainerImages ?? [];
  const [draft, setDraft] = useState<string[]>(initial);
  const [error, setError] = useState<string | null>(null);

  // Reset local state when the parent prop changes (e.g. after an outside refresh)
  useEffect(() => { setDraft(initial); }, [initial.join("|")]);

  const dirty = draft.length !== initial.length || draft.some((v, i) => v !== initial[i]);

  const save = useMutation({
    mutationFn: () => reposApi.updateAssetLinks(repo.id, { buildsContainerImages: draft }),
    onSuccess: (data) => {
      setError(null);
      toast.success("Asset links saved");
      qc.invalidateQueries({ queryKey: ["repos"] });
      qc.invalidateQueries({ queryKey: ["repo", repo.id] });
      // Reflect server-validated/deduped values back into the draft
      setDraft(data.buildsContainerImages ?? []);
    },
    onError: (err: Error & { response?: { data?: { error?: string } } }) => {
      const msg = err.response?.data?.error ?? err.message ?? "Failed to save";
      setError(msg);
    },
  });

  return (
    <PanelShell
      title="Container images this repo builds"
      description="Used by the attack-path correlation engine to bridge findings on this repo to vulnerabilities in the produced containers. Type each image ref (e.g. myorg/api:1.2.3) and press Enter."
    >
      <Can role="ADMIN" fallback={<FreeTextChips value={draft} onChange={() => {}} placeholder="" disabled />}>
        <FreeTextChips
          value={draft}
          onChange={(next) => { setDraft(next); setError(null); }}
          placeholder="myorg/api:latest"
        />
        <SaveBar
          dirty={dirty}
          saving={save.isPending}
          error={error}
          onSave={() => save.mutate()}
          onReset={() => { setDraft(initial); setError(null); }}
        />
      </Can>
    </PanelShell>
  );
}

// ── Container panel ────────────────────────────────────────────────────────

export function ContainerAssetLinksPanel({ container }: { container: Container }) {
  const qc = useQueryClient();
  const { toast } = useToast();
  const initialRepoId  = container.sourceRepositoryId ?? null;
  const initialDomainIds = container.deployedAtDomainIds ?? [];
  const [repoId, setRepoId]   = useState<string | null>(initialRepoId);
  const [domainIds, setDomainIds] = useState<string[]>(initialDomainIds);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => { setRepoId(initialRepoId); }, [initialRepoId]);
  useEffect(() => { setDomainIds(initialDomainIds); }, [initialDomainIds.join("|")]);

  const dirty =
    repoId !== initialRepoId ||
    domainIds.length !== initialDomainIds.length ||
    domainIds.some((v, i) => v !== initialDomainIds[i]);

  // Pull the lists used to populate the dropdowns. Cheap — these are typically
  // small (single-digit to low-100s of resources per org).
  const repos = useQuery({ queryKey: ["repos"], queryFn: reposApi.list });
  const domains = useQuery({ queryKey: ["domains"], queryFn: domainsApi.list });

  const repoOptions: AssetOption[]   = (repos.data   ?? []).map((r) => ({ id: r.id, label: r.fullName }));
  const domainOptions: AssetOption[] = (domains.data ?? []).map((d) => ({ id: d.id, label: d.domain }));

  const save = useMutation({
    mutationFn: () => containersApi.updateAssetLinks(container.id, {
      sourceRepositoryId: repoId,
      deployedAtDomainIds: domainIds,
    }),
    onSuccess: (data) => {
      setError(null);
      toast.success("Asset links saved");
      qc.invalidateQueries({ queryKey: ["containers"] });
      qc.invalidateQueries({ queryKey: ["container", container.id] });
      setRepoId(data.sourceRepositoryId ?? null);
      setDomainIds(data.deployedAtDomainIds ?? []);
    },
    onError: (err: Error & { response?: { data?: { error?: string } } }) => {
      const msg = err.response?.data?.error ?? err.message ?? "Failed to save";
      setError(msg);
    },
  });

  return (
    <PanelShell
      title="Asset relations"
      description="Link this container to the repo that builds it and the domains it serves. Powers attack chains: a finding here can be traced back to source code, and forward to public traffic."
    >
      <div className="space-y-4">
        <div>
          <label className="mb-1 block text-xs font-medium text-gray-400">Source repository</label>
          <Can role="ADMIN" fallback={
            <AssetIdSingleSelect options={repoOptions} value={repoId} onChange={() => {}} disabled />
          }>
            <AssetIdSingleSelect
              options={repoOptions}
              value={repoId}
              onChange={(next) => { setRepoId(next); setError(null); }}
            />
          </Can>
        </div>
        <div>
          <label className="mb-1 block text-xs font-medium text-gray-400">Deployed at domains</label>
          <Can role="ADMIN" fallback={
            <AssetIdMultiSelect options={domainOptions} value={domainIds} onChange={() => {}} emptyLabel="No domains linked." disabled />
          }>
            <AssetIdMultiSelect
              options={domainOptions}
              value={domainIds}
              onChange={(next) => { setDomainIds(next); setError(null); }}
              emptyLabel="No domains linked yet."
            />
          </Can>
        </div>
      </div>
      <Can role="ADMIN">
        <SaveBar
          dirty={dirty}
          saving={save.isPending}
          error={error}
          onSave={() => save.mutate()}
          onReset={() => { setRepoId(initialRepoId); setDomainIds(initialDomainIds); setError(null); }}
        />
      </Can>
    </PanelShell>
  );
}

// ── Domain panel ───────────────────────────────────────────────────────────

export function DomainAssetLinksPanel({ domain }: { domain: Domain }) {
  const qc = useQueryClient();
  const { toast } = useToast();
  const initial = domain.servesContainerIds ?? [];
  const [draft, setDraft] = useState<string[]>(initial);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => { setDraft(initial); }, [initial.join("|")]);

  const dirty = draft.length !== initial.length || draft.some((v, i) => v !== initial[i]);

  const containers = useQuery({ queryKey: ["containers"], queryFn: containersApi.list });
  const containerOptions: AssetOption[] = (containers.data ?? []).map((c) => ({
    id: c.id,
    label: c.imageRef,
  }));

  const save = useMutation({
    mutationFn: () => domainsApi.updateAssetLinks(domain.id, { servesContainerIds: draft }),
    onSuccess: (data) => {
      setError(null);
      toast.success("Asset links saved");
      qc.invalidateQueries({ queryKey: ["domains"] });
      qc.invalidateQueries({ queryKey: ["domain", domain.id] });
      setDraft(data.servesContainerIds ?? []);
    },
    onError: (err: Error & { response?: { data?: { error?: string } } }) => {
      const msg = err.response?.data?.error ?? err.message ?? "Failed to save";
      setError(msg);
    },
  });

  return (
    <PanelShell
      title="Containers serving this domain"
      description="Operator-declared list of container images that answer requests at this hostname. Used by the attack-path engine to chain DAST/PENTEST findings here back to container CVEs and source code."
    >
      <Can role="ADMIN" fallback={
        <AssetIdMultiSelect options={containerOptions} value={draft} onChange={() => {}} emptyLabel="No containers linked." disabled />
      }>
        <AssetIdMultiSelect
          options={containerOptions}
          value={draft}
          onChange={(next) => { setDraft(next); setError(null); }}
          emptyLabel="No containers linked yet."
        />
        <SaveBar
          dirty={dirty}
          saving={save.isPending}
          error={error}
          onSave={() => save.mutate()}
          onReset={() => { setDraft(initial); setError(null); }}
        />
      </Can>
    </PanelShell>
  );
}
