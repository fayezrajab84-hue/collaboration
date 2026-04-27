/**
 * ApplicationPickerPanel — Phase 27.5 per-resource Application binding.
 *
 * Sits at the top of each Repository / Container / Domain edit modal so the
 * operator can quickly answer "which application does this asset belong to?"
 * without navigating away. Single-select dropdown — an asset can belong to
 * at most one Application.
 *
 * Saving here uses the bulk components endpoint on the chosen target app:
 * we add this asset to that app's membership (which automatically un-assigns
 * it from any prior app per the assignComponents service contract).
 */
import { useEffect, useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { Boxes, Save } from "lucide-react";
import { Link } from "react-router-dom";
import { applicationsApi } from "../lib/api";
import Can from "./Can";
import { useToast } from "../hooks/useToast";

type ResourceKind = "repository" | "container" | "domain";

interface Props {
  kind:                  ResourceKind;
  resourceId:            string;
  currentApplicationId:  string | null | undefined;
  onChange?:             (applicationId: string | null) => void;
}

export default function ApplicationPickerPanel({ kind, resourceId, currentApplicationId, onChange }: Props) {
  const qc = useQueryClient();
  const { toast } = useToast();
  const initial = currentApplicationId ?? "";
  const [draft, setDraft] = useState<string>(initial);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => { setDraft(initial); }, [initial]);

  const { data: apps } = useQuery({ queryKey: ["applications"], queryFn: applicationsApi.list });

  const dirty = draft !== initial;

  const save = useMutation({
    mutationFn: async () => {
      // To CHANGE an asset's app: add it to the new app's membership
      // (assignComponents un-assigns from prior app automatically).
      // To CLEAR: assign to no app — which means we have to call the OLD
      // app's components endpoint and remove this asset from its set.
      if (draft === "") {
        if (!initial) return;
        const app = await applicationsApi.get(initial);
        const remaining = arrayForKind(app, kind).filter((id) => id !== resourceId);
        return applicationsApi.assignComponents(initial, payloadForKind(kind, remaining));
      }
      const app = await applicationsApi.get(draft);
      const next = Array.from(new Set([...arrayForKind(app, kind), resourceId]));
      return applicationsApi.assignComponents(draft, payloadForKind(kind, next));
    },
    onSuccess: () => {
      setError(null);
      toast.success("Application updated");
      qc.invalidateQueries({ queryKey: ["applications"] });
      if (initial) qc.invalidateQueries({ queryKey: ["application", initial] });
      if (draft)   qc.invalidateQueries({ queryKey: ["application", draft] });
      qc.invalidateQueries({ queryKey: [`${kind}s` as const] });
      onChange?.(draft || null);
    },
    onError: (err: Error & { response?: { data?: { error?: string } } }) => {
      setError(err.response?.data?.error ?? err.message ?? "Failed to save");
    },
  });

  return (
    <div className="rounded-xl border border-gray-800 bg-gray-900/40 p-5">
      <div className="mb-3 flex items-start gap-2">
        <Boxes className="mt-0.5 h-4 w-4 text-indigo-400" />
        <div>
          <h3 className="text-sm font-semibold text-white">Application</h3>
          <p className="mt-0.5 text-xs text-gray-500">
            Assigning this asset to an Application enables attack-path correlation across its peers.
            Unassigned assets are scanned but their findings don't get chained.
          </p>
        </div>
      </div>
      <Can role="ADMIN" fallback={
        <div className="text-xs text-gray-500">
          {currentApplicationId
            ? <>Belongs to application <code className="text-gray-300">{currentApplicationId}</code> (admin to change)</>
            : "Not assigned to an application (admin to set)"}
        </div>
      }>
        <div className="space-y-2">
          <select
            value={draft}
            onChange={(e) => { setDraft(e.target.value); setError(null); }}
            className="w-full rounded bg-gray-800 px-3 py-1.5 text-xs text-gray-200 focus:outline-none focus:ring-1 focus:ring-indigo-500"
          >
            <option value="">— Unassigned —</option>
            {(apps ?? []).map((a) => (
              <option key={a.id} value={a.id}>{a.name} ({a.environment.toLowerCase()})</option>
            ))}
          </select>
          {(apps ?? []).length === 0 && (
            <p className="text-xs text-gray-500">
              No applications yet. <Link to="/applications" className="text-indigo-400 hover:text-indigo-300">Create one →</Link>
            </p>
          )}
          <div className="flex items-center gap-2">
            <button
              type="button"
              onClick={() => save.mutate()}
              disabled={!dirty || save.isPending}
              className="inline-flex items-center gap-1.5 rounded-lg bg-indigo-700 px-3 py-1.5 text-xs font-medium text-white hover:bg-indigo-600 disabled:opacity-50"
            >
              <Save className="h-3 w-3" /> {save.isPending ? "Saving…" : "Save application"}
            </button>
            {dirty && !save.isPending && (
              <button
                type="button"
                onClick={() => { setDraft(initial); setError(null); }}
                className="rounded px-3 py-1.5 text-xs text-gray-400 hover:text-gray-200"
              >Reset</button>
            )}
            {error && <span className="text-xs text-red-400">{error}</span>}
          </div>
        </div>
      </Can>
    </div>
  );
}

// Helpers — pick the right field on ApplicationDetail.components for a kind.
function arrayForKind(app: { components: { repositories: Array<{ id: string }>; containers: Array<{ id: string }>; domains: Array<{ id: string }> } }, kind: ResourceKind): string[] {
  if (kind === "repository") return app.components.repositories.map((r) => r.id);
  if (kind === "container")  return app.components.containers.map((c) => c.id);
  return app.components.domains.map((d) => d.id);
}

function payloadForKind(kind: ResourceKind, ids: string[]): Record<string, string[]> {
  if (kind === "repository") return { repositoryIds: ids };
  if (kind === "container")  return { containerIds:  ids };
  return { domainIds: ids };
}
