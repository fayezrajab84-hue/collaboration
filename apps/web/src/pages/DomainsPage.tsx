import { useState } from "react";
import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import { Plus, Play, Trash2, Pencil, Globe, X } from "lucide-react";
import { domainsApi } from "../lib/api";
import type { Domain } from "@devsecops/types";
import ScanStatusBadge from "../components/ScanStatusBadge";
import FindingCountBadges from "../components/FindingCountBadges";
import { useSSE } from "../hooks/useSSE";
import { formatRelative } from "../lib/utils";

function ScanButton({ domainId }: { domainId: string }) {
  const [activeScanId, setActiveScanId] = useState<string | null>(null);
  const { status } = useSSE(activeScanId);
  const qc = useQueryClient();
  const scan = useMutation({
    mutationFn: () => domainsApi.triggerScan(domainId),
    onSuccess: (data) => { setActiveScanId(data.scanJobId); qc.invalidateQueries({ queryKey: ["scans"] }); },
  });
  const liveStatus = status ?? (scan.isPending ? "PENDING" : null);
  return (
    <div className="flex items-center gap-2">
      {liveStatus && <ScanStatusBadge status={liveStatus} />}
      <button onClick={() => scan.mutate()} disabled={scan.isPending || liveStatus === "RUNNING"}
        className="flex items-center gap-1.5 rounded bg-indigo-600 px-3 py-1.5 text-xs font-medium text-white hover:bg-indigo-500 disabled:opacity-50">
        <Play className="h-3 w-3" /> Scan (DAST)
      </button>
    </div>
  );
}

function AddDomainModal({ onClose }: { onClose: () => void }) {
  const [domain, setDomain] = useState("");
  const qc = useQueryClient();
  const add = useMutation({
    mutationFn: () => domainsApi.create({ domain }),
    onSuccess: () => { qc.invalidateQueries({ queryKey: ["domains"] }); onClose(); },
  });
  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/60">
      <div className="w-full max-w-md rounded-xl border border-gray-700 bg-gray-900 p-6 shadow-2xl">
        <div className="mb-4 flex items-center justify-between">
          <h2 className="text-base font-semibold text-white">Add Domain</h2>
          <button onClick={onClose} className="text-gray-500 hover:text-gray-200"><X className="h-4 w-4" /></button>
        </div>
        <p className="mb-3 text-xs text-gray-500">Add a domain or hostname for DAST and pentest scanning. Only scan targets you own.</p>
        <input
          className="w-full rounded bg-gray-800 px-3 py-2 text-sm text-gray-200 placeholder-gray-500 focus:outline-none focus:ring-1 focus:ring-indigo-500"
          placeholder="example.com"
          value={domain}
          onChange={(e) => setDomain(e.target.value)}
          onKeyDown={(e) => e.key === "Enter" && add.mutate()}
        />
        <div className="mt-4 flex justify-end gap-2">
          <button onClick={onClose} className="rounded px-3 py-1.5 text-sm text-gray-400 hover:text-gray-200">Cancel</button>
          <button onClick={() => add.mutate()} disabled={!domain || add.isPending}
            className="rounded bg-indigo-600 px-4 py-1.5 text-sm font-medium text-white hover:bg-indigo-500 disabled:opacity-50">
            {add.isPending ? "Adding…" : "Add Domain"}
          </button>
        </div>
      </div>
    </div>
  );
}

function EditDomainModal({ domain, onClose }: { domain: Domain; onClose: () => void }) {
  const [value, setValue] = useState(domain.domain);
  const qc = useQueryClient();

  const update = useMutation({
    mutationFn: () => domainsApi.update(domain.id, { domain: value }),
    onSuccess: () => { qc.invalidateQueries({ queryKey: ["domains"] }); onClose(); },
  });

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/60">
      <div className="w-full max-w-md rounded-xl border border-gray-700 bg-gray-900 p-6 shadow-2xl">
        <div className="mb-4 flex items-center justify-between">
          <h2 className="text-base font-semibold text-white">Edit Domain</h2>
          <button onClick={onClose} className="text-gray-500 hover:text-gray-200"><X className="h-4 w-4" /></button>
        </div>
        <label className="mb-1 block text-xs font-medium text-gray-400">Domain</label>
        <input
          className="w-full rounded bg-gray-800 px-3 py-2 text-sm text-gray-200 placeholder-gray-500 focus:outline-none focus:ring-1 focus:ring-indigo-500"
          value={value}
          onChange={(e) => setValue(e.target.value)}
          onKeyDown={(e) => e.key === "Enter" && update.mutate()}
          placeholder="example.com"
        />
        <p className="mt-1.5 text-xs text-gray-600">Only scan domains you are authorized to test.</p>
        {update.error && (
          <p className="mt-2 text-xs text-red-400">{(update.error as Error).message}</p>
        )}
        <div className="mt-4 flex justify-end gap-2">
          <button onClick={onClose} className="rounded px-3 py-1.5 text-sm text-gray-400 hover:text-gray-200">Cancel</button>
          <button
            onClick={() => update.mutate()}
            disabled={!value || update.isPending}
            className="rounded bg-indigo-600 px-4 py-1.5 text-sm font-medium text-white hover:bg-indigo-500 disabled:opacity-50"
          >
            {update.isPending ? "Saving…" : "Save Changes"}
          </button>
        </div>
      </div>
    </div>
  );
}

export default function DomainsPage() {
  const [showAdd, setShowAdd] = useState(false);
  const [editDomain, setEditDomain] = useState<Domain | null>(null);
  const qc = useQueryClient();
  const { data: domains, isLoading } = useQuery({ queryKey: ["domains"], queryFn: domainsApi.list });
  const del = useMutation({ mutationFn: (id: string) => domainsApi.delete(id), onSuccess: () => qc.invalidateQueries({ queryKey: ["domains"] }) });

  return (
    <div className="p-6">
      <div className="mb-6 flex items-center justify-between">
        <h1 className="text-xl font-bold text-white">Domains</h1>
        <button onClick={() => setShowAdd(true)} className="flex items-center gap-2 rounded-lg bg-indigo-600 px-4 py-2 text-sm font-medium text-white hover:bg-indigo-500">
          <Plus className="h-4 w-4" /> Add Domain
        </button>
      </div>
      <p className="mb-4 text-xs text-gray-500">Domains are scanned with OWASP ZAP (DAST) and Nuclei (pentest). Only add domains you are authorized to test.</p>

      {isLoading ? (
        <div className="flex h-48 items-center justify-center text-gray-500">Loading…</div>
      ) : domains?.length === 0 ? (
        <div className="flex h-48 flex-col items-center justify-center gap-3 text-gray-500">
          <Globe className="h-8 w-8" />
          <p>No domains added yet.</p>
        </div>
      ) : (
        <div className="overflow-x-auto rounded-lg border border-gray-800">
          <table className="w-full text-sm">
            <thead className="border-b border-gray-800 bg-gray-900">
              <tr className="text-left text-xs text-gray-500">
                <th className="px-4 py-3 font-medium">Domain</th>
                <th className="px-4 py-3 font-medium">Issues</th>
                <th className="px-4 py-3 font-medium">Last Scanned</th>
                <th className="px-4 py-3 font-medium">Actions</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-gray-800 bg-gray-900/50">
              {domains?.map((d) => (
                <tr key={d.id} className="hover:bg-gray-800/30">
                  <td className="px-4 py-3 font-medium text-gray-200">{d.domain}</td>
                  <td className="px-4 py-3"><FindingCountBadges counts={d.findingCounts} /></td>
                  <td className="px-4 py-3 text-gray-400">{d.lastScannedAt ? formatRelative(d.lastScannedAt) : "Never"}</td>
                  <td className="px-4 py-3">
                    <div className="flex items-center gap-2">
                      <ScanButton domainId={d.id} />
                      <button onClick={() => setEditDomain(d)} className="text-gray-600 hover:text-indigo-400" title="Edit domain">
                        <Pencil className="h-4 w-4" />
                      </button>
                      <button onClick={() => del.mutate(d.id)} className="text-gray-600 hover:text-red-400" title="Remove domain">
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
      {showAdd && <AddDomainModal onClose={() => setShowAdd(false)} />}
      {editDomain && <EditDomainModal domain={editDomain} onClose={() => setEditDomain(null)} />}
    </div>
  );
}
