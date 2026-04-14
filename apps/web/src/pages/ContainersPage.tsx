import { useState } from "react";
import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import { Plus, Play, Trash2, Box, X } from "lucide-react";
import { containersApi } from "../lib/api";
import ScanStatusBadge from "../components/ScanStatusBadge";
import { useSSE } from "../hooks/useSSE";
import { formatRelative } from "../lib/utils";

function ScanButton({ containerId }: { containerId: string }) {
  const [activeScanId, setActiveScanId] = useState<string | null>(null);
  const { status } = useSSE(activeScanId);
  const qc = useQueryClient();

  const scan = useMutation({
    mutationFn: () => containersApi.triggerScan(containerId),
    onSuccess: (data) => { setActiveScanId(data.scanJobId); qc.invalidateQueries({ queryKey: ["scans"] }); },
  });

  const liveStatus = status ?? (scan.isPending ? "PENDING" : null);
  return (
    <div className="flex items-center gap-2">
      {liveStatus && <ScanStatusBadge status={liveStatus} />}
      <button
        onClick={() => scan.mutate()}
        disabled={scan.isPending || liveStatus === "RUNNING"}
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

export default function ContainersPage() {
  const [showAdd, setShowAdd] = useState(false);
  const qc = useQueryClient();
  const { data: containers, isLoading } = useQuery({ queryKey: ["containers"], queryFn: containersApi.list });
  const del = useMutation({ mutationFn: (id: string) => containersApi.delete(id), onSuccess: () => qc.invalidateQueries({ queryKey: ["containers"] }) });

  return (
    <div className="p-6">
      <div className="mb-6 flex items-center justify-between">
        <h1 className="text-xl font-bold text-white">Containers</h1>
        <button onClick={() => setShowAdd(true)} className="flex items-center gap-2 rounded-lg bg-indigo-600 px-4 py-2 text-sm font-medium text-white hover:bg-indigo-500">
          <Plus className="h-4 w-4" /> Add Image
        </button>
      </div>

      {isLoading ? (
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
                <th className="px-4 py-3 font-medium">Last Scanned</th>
                <th className="px-4 py-3 font-medium">Actions</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-gray-800 bg-gray-900/50">
              {containers?.map((c) => (
                <tr key={c.id} className="hover:bg-gray-800/30">
                  <td className="px-4 py-3 font-mono text-sm text-gray-200">{c.imageRef}</td>
                  <td className="px-4 py-3 text-gray-400">{c.registry ?? "Docker Hub"}</td>
                  <td className="px-4 py-3 text-gray-400">{c.lastScannedAt ? formatRelative(c.lastScannedAt) : "Never"}</td>
                  <td className="px-4 py-3">
                    <div className="flex items-center gap-2">
                      <ScanButton containerId={c.id} />
                      <button onClick={() => del.mutate(c.id)} className="text-gray-600 hover:text-red-400"><Trash2 className="h-4 w-4" /></button>
                    </div>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
      {showAdd && <AddContainerModal onClose={() => setShowAdd(false)} />}
    </div>
  );
}
