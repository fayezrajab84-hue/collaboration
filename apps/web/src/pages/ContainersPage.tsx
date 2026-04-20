import { useState } from "react";
import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import { Plus, Play, Trash2, Pencil, Box, X } from "lucide-react";
import { containersApi } from "../lib/api";
import type { Container } from "@devsecops/types";
import RiskScoreBadge from "../components/RiskScoreBadge";
import ScanStatusBadge from "../components/ScanStatusBadge";
import FindingCountBadges from "../components/FindingCountBadges";
import ChecksTab from "../components/ChecksTab";
import { useTargetScanStatus } from "../hooks/useTargetScanStatus";
import { formatRelative } from "../lib/utils";
import { CONTAINER_CHECKS } from "../data/checks";

function ScanButton({ containerId }: { containerId: string }) {
  const qc = useQueryClient();
  const { status, isActive } = useTargetScanStatus(containerId);

  const scan = useMutation({
    mutationFn: () => containersApi.triggerScan(containerId),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ["scans"] });
      qc.invalidateQueries({ queryKey: ["scans", "active"] });
    },
  });

  const displayStatus = status ?? (scan.isPending ? "PENDING" : null);
  return (
    <div className="flex items-center gap-2">
      {displayStatus && <ScanStatusBadge status={displayStatus} />}
      <button
        onClick={() => scan.mutate()}
        disabled={scan.isPending || isActive}
        className="flex items-center gap-1.5 rounded bg-indigo-600 px-3 py-1.5 text-xs font-medium text-white hover:bg-indigo-500 disabled:opacity-50"
      >
        <Play className="h-3 w-3" /> Scan
      </button>
    </div>
  );
}

function AddContainerModal({ onClose }: { onClose: () => void }) {
  const [imageRef, setImageRef] = useState("");
  const qc = useQueryClient();
  const add = useMutation({
    mutationFn: () => containersApi.create({ imageRef }),
    onSuccess: () => { qc.invalidateQueries({ queryKey: ["containers"] }); onClose(); },
  });
  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/60">
      <div className="w-full max-w-md rounded-xl border border-gray-700 bg-gray-900 p-6 shadow-2xl">
        <div className="mb-4 flex items-center justify-between">
          <h2 className="text-base font-semibold text-white">Add Container Image</h2>
          <button onClick={onClose} className="text-gray-500 hover:text-gray-200"><X className="h-4 w-4" /></button>
        </div>
        <input
          className="w-full rounded bg-gray-800 px-3 py-2 text-sm text-gray-200 placeholder-gray-500 focus:outline-none focus:ring-1 focus:ring-indigo-500"
          placeholder="nginx:1.25 or registry.example.com/app:latest"
          value={imageRef}
          onChange={(e) => setImageRef(e.target.value)}
          onKeyDown={(e) => e.key === "Enter" && add.mutate()}
        />
        <div className="mt-4 flex justify-end gap-2">
          <button onClick={onClose} className="rounded px-3 py-1.5 text-sm text-gray-400 hover:text-gray-200">Cancel</button>
          <button onClick={() => add.mutate()} disabled={!imageRef || add.isPending}
            className="rounded bg-indigo-600 px-4 py-1.5 text-sm font-medium text-white hover:bg-indigo-500 disabled:opacity-50">
            {add.isPending ? "Adding…" : "Add Image"}
          </button>
        </div>
      </div>
    </div>
  );
}

function EditContainerModal({ container, onClose }: { container: Container; onClose: () => void }) {
  const [imageRef, setImageRef] = useState(container.imageRef);
  const [registry, setRegistry] = useState(container.registry ?? "");
  const qc = useQueryClient();

  const update = useMutation({
    mutationFn: () => containersApi.update(container.id, {
      imageRef,
      registry: registry || undefined,
    }),
    onSuccess: () => { qc.invalidateQueries({ queryKey: ["containers"] }); onClose(); },
  });

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/60">
      <div className="w-full max-w-md rounded-xl border border-gray-700 bg-gray-900 p-6 shadow-2xl">
        <div className="mb-4 flex items-center justify-between">
          <h2 className="text-base font-semibold text-white">Edit Container Image</h2>
          <button onClick={onClose} className="text-gray-500 hover:text-gray-200"><X className="h-4 w-4" /></button>
        </div>
        <div className="space-y-3">
          <div>
            <label className="mb-1 block text-xs font-medium text-gray-400">Image reference</label>
            <input
              className="w-full rounded bg-gray-800 px-3 py-2 text-sm text-gray-200 placeholder-gray-500 focus:outline-none focus:ring-1 focus:ring-indigo-500 font-mono"
              value={imageRef}
              onChange={(e) => setImageRef(e.target.value)}
              placeholder="nginx:1.25"
            />
          </div>
          <div>
            <label className="mb-1 block text-xs font-medium text-gray-400">Registry <span className="text-gray-600">(optional)</span></label>
            <input
              className="w-full rounded bg-gray-800 px-3 py-2 text-sm text-gray-200 placeholder-gray-500 focus:outline-none focus:ring-1 focus:ring-indigo-500"
              value={registry}
              onChange={(e) => setRegistry(e.target.value)}
              placeholder="registry.example.com"
            />
          </div>
        </div>
        {update.error && (
          <p className="mt-2 text-xs text-red-400">{(update.error as Error).message}</p>
        )}
        <div className="mt-4 flex justify-end gap-2">
          <button onClick={onClose} className="rounded px-3 py-1.5 text-sm text-gray-400 hover:text-gray-200">Cancel</button>
          <button
            onClick={() => update.mutate()}
            disabled={!imageRef || update.isPending}
            className="rounded bg-indigo-600 px-4 py-1.5 text-sm font-medium text-white hover:bg-indigo-500 disabled:opacity-50"
          >
            {update.isPending ? "Saving…" : "Save Changes"}
          </button>
        </div>
      </div>
    </div>
  );
}

export default function ContainersPage() {
  const [showAdd, setShowAdd] = useState(false);
  const [editContainer, setEditContainer] = useState<Container | null>(null);
  const [tab, setTab] = useState<"containers" | "checks">("containers");
  const qc = useQueryClient();
  const { data: containers, isLoading } = useQuery({ queryKey: ["containers"], queryFn: containersApi.list });
  const del = useMutation({ mutationFn: (id: string) => containersApi.delete(id), onSuccess: () => qc.invalidateQueries({ queryKey: ["containers"] }) });

  return (
    <div className="p-6">
      <div className="mb-4 flex items-center justify-between">
        <h1 className="text-3xl font-bold text-white">Containers</h1>
        {tab === "containers" && (
          <button onClick={() => setShowAdd(true)} className="flex items-center gap-2 rounded-lg bg-indigo-600 px-4 py-2 text-sm font-medium text-white hover:bg-indigo-500">
            <Plus className="h-4 w-4" /> Add Image
          </button>
        )}
      </div>

      {/* Tabs */}
      <div className="mb-5 flex gap-1 border-b border-gray-800">
        {(["containers", "checks"] as const).map((t) => (
          <button
            key={t}
            onClick={() => setTab(t)}
            className={`px-4 py-2 text-sm font-medium transition-colors border-b-2 -mb-px ${
              tab === t
                ? "border-indigo-500 text-white"
                : "border-transparent text-gray-500 hover:text-gray-300"
            }`}
          >
            {t === "containers" ? "Containers" : "Checks"}
          </button>
        ))}
      </div>

      {tab === "checks" ? (
        <ChecksTab checks={CONTAINER_CHECKS} />
      ) : isLoading ? (
        <div className="flex h-48 items-center justify-center text-gray-500">Loading…</div>
      ) : containers?.length === 0 ? (
        <div className="flex h-48 flex-col items-center justify-center gap-3 text-gray-500">
          <Box className="h-8 w-8" />
          <p>No container images added yet.</p>
        </div>
      ) : (
        <div className="overflow-x-auto rounded-lg border border-gray-800">
          <table className="w-full text-sm">
            <thead className="border-b border-gray-800 bg-gray-900">
              <tr className="text-left text-xs text-gray-500">
                <th className="px-4 py-3 font-medium">Image</th>
                <th className="px-4 py-3 font-medium">Registry</th>
                <th className="px-4 py-3 font-medium">Issues</th>
                <th className="px-4 py-3 font-medium">AI Risk</th>
                <th className="px-4 py-3 font-medium">Last Scanned</th>
                <th className="px-4 py-3 font-medium">Actions</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-gray-800 bg-gray-900/50">
              {containers?.map((c) => (
                <tr key={c.id} className="hover:bg-gray-800/30">
                  <td className="px-4 py-3 font-mono text-sm text-gray-200">{c.imageRef}</td>
                  <td className="px-4 py-3 text-gray-400">{c.registry ?? "Docker Hub"}</td>
                  <td className="px-4 py-3"><FindingCountBadges counts={c.findingCounts} /></td>
                  <td className="px-4 py-3"><RiskScoreBadge score={c.aiRiskScore} reason={c.aiRiskReason} /></td>
                  <td className="px-4 py-3 text-gray-400">{c.lastScannedAt ? formatRelative(c.lastScannedAt) : "Never"}</td>
                  <td className="px-4 py-3">
                    <div className="flex items-center gap-2">
                      <ScanButton containerId={c.id} />
                      <button onClick={() => setEditContainer(c)} className="text-gray-600 hover:text-indigo-400" title="Edit container">
                        <Pencil className="h-4 w-4" />
                      </button>
                      <button onClick={() => del.mutate(c.id)} className="text-gray-600 hover:text-red-400" title="Remove container">
                        <Trash2 className="h-4 w-4" />
                      </button>
                    </div>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
      {showAdd && <AddContainerModal onClose={() => setShowAdd(false)} />}
      {editContainer && <EditContainerModal container={editContainer} onClose={() => setEditContainer(null)} />}
    </div>
  );
}
