import { useState } from "react";
import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import { Plus, Play, Trash2, Pencil, GitBranch, X } from "lucide-react";
import { reposApi } from "../lib/api";
import type { Repository } from "@devsecops/types";
import RiskScoreBadge from "../components/RiskScoreBadge";
import ScanStatusBadge from "../components/ScanStatusBadge";
import FindingCountBadges from "../components/FindingCountBadges";
import ChecksTab from "../components/ChecksTab";
import { useTargetScanStatus } from "../hooks/useTargetScanStatus";
import { formatRelative } from "../lib/utils";
import { REPO_CHECKS } from "../data/checks";

function ScanButton({ repoId }: { repoId: string }) {
  const qc = useQueryClient();
  const { status, isActive } = useTargetScanStatus(repoId);

  const scan = useMutation({
    mutationFn: () => reposApi.triggerScan(repoId),
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
        <Play className="h-3 w-3" />
        Scan
      </button>
    </div>
  );
}

function AddRepoModal({ onClose }: { onClose: () => void }) {
  const [url, setUrl] = useState("");
  const qc = useQueryClient();

  const add = useMutation({
    mutationFn: () => reposApi.create({ githubUrl: url }),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ["repos"] });
      onClose();
    },
  });

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/60">
      <div className="w-full max-w-md rounded-xl border border-gray-700 bg-gray-900 p-6 shadow-2xl">
        <div className="mb-4 flex items-center justify-between">
          <h2 className="text-base font-semibold text-white">Add Repository</h2>
          <button onClick={onClose} className="text-gray-500 hover:text-gray-200"><X className="h-4 w-4" /></button>
        </div>
        <input
          className="w-full rounded bg-gray-800 px-3 py-2 text-sm text-gray-200 placeholder-gray-500 focus:outline-none focus:ring-1 focus:ring-indigo-500"
          placeholder="https://github.com/owner/repo"
          value={url}
          onChange={(e) => setUrl(e.target.value)}
          onKeyDown={(e) => e.key === "Enter" && add.mutate()}
        />
        {add.error && (
          <p className="mt-2 text-xs text-red-400">
            {(add.error as Error).message}
          </p>
        )}
        <div className="mt-4 flex justify-end gap-2">
          <button onClick={onClose} className="rounded px-3 py-1.5 text-sm text-gray-400 hover:text-gray-200">Cancel</button>
          <button
            onClick={() => add.mutate()}
            disabled={!url || add.isPending}
            className="rounded bg-indigo-600 px-4 py-1.5 text-sm font-medium text-white hover:bg-indigo-500 disabled:opacity-50"
          >
            {add.isPending ? "Adding…" : "Add Repository"}
          </button>
        </div>
      </div>
    </div>
  );
}

function EditRepoModal({ repo, onClose }: { repo: Repository; onClose: () => void }) {
  const [branch, setBranch] = useState(repo.defaultBranch);
  const qc = useQueryClient();

  const update = useMutation({
    mutationFn: () => reposApi.update(repo.id, { defaultBranch: branch }),
    onSuccess: () => { qc.invalidateQueries({ queryKey: ["repos"] }); onClose(); },
  });

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/60">
      <div className="w-full max-w-md rounded-xl border border-gray-700 bg-gray-900 p-6 shadow-2xl">
        <div className="mb-4 flex items-center justify-between">
          <h2 className="text-base font-semibold text-white">Edit Repository</h2>
          <button onClick={onClose} className="text-gray-500 hover:text-gray-200"><X className="h-4 w-4" /></button>
        </div>
        <p className="mb-3 text-xs text-gray-500 font-mono">{repo.fullName}</p>
        <label className="mb-1 block text-xs font-medium text-gray-400">Default branch</label>
        <input
          className="w-full rounded bg-gray-800 px-3 py-2 text-sm text-gray-200 placeholder-gray-500 focus:outline-none focus:ring-1 focus:ring-indigo-500"
          value={branch}
          onChange={(e) => setBranch(e.target.value)}
          onKeyDown={(e) => e.key === "Enter" && update.mutate()}
          placeholder="main"
        />
        {update.error && (
          <p className="mt-2 text-xs text-red-400">{(update.error as Error).message}</p>
        )}
        <div className="mt-4 flex justify-end gap-2">
          <button onClick={onClose} className="rounded px-3 py-1.5 text-sm text-gray-400 hover:text-gray-200">Cancel</button>
          <button
            onClick={() => update.mutate()}
            disabled={!branch || update.isPending}
            className="rounded bg-indigo-600 px-4 py-1.5 text-sm font-medium text-white hover:bg-indigo-500 disabled:opacity-50"
          >
            {update.isPending ? "Saving…" : "Save Changes"}
          </button>
        </div>
      </div>
    </div>
  );
}

export default function RepositoriesPage() {
  const [showAdd, setShowAdd] = useState(false);
  const [editRepo, setEditRepo] = useState<Repository | null>(null);
  const [tab, setTab] = useState<"repos" | "checks">("repos");
  const qc = useQueryClient();
  const { data: repos, isLoading } = useQuery({ queryKey: ["repos"], queryFn: reposApi.list });

  const deleteRepo = useMutation({
    mutationFn: (id: string) => reposApi.delete(id),
    onSuccess: () => qc.invalidateQueries({ queryKey: ["repos"] }),
  });

  return (
    <div className="p-6">
      <div className="mb-4 flex items-center justify-between">
        <h1 className="text-3xl font-bold text-white">Repositories</h1>
        {tab === "repos" && (
          <button
            onClick={() => setShowAdd(true)}
            className="flex items-center gap-2 rounded-lg bg-indigo-600 px-4 py-2 text-sm font-medium text-white hover:bg-indigo-500"
          >
            <Plus className="h-4 w-4" /> Add Repository
          </button>
        )}
      </div>

      {/* Tabs */}
      <div className="mb-5 flex gap-1 border-b border-gray-800">
        {(["repos", "checks"] as const).map((t) => (
          <button
            key={t}
            onClick={() => setTab(t)}
            className={`px-4 py-2 text-sm font-medium transition-colors border-b-2 -mb-px ${
              tab === t
                ? "border-indigo-500 text-white"
                : "border-transparent text-gray-500 hover:text-gray-300"
            }`}
          >
            {t === "repos" ? "Repositories" : "Checks"}
          </button>
        ))}
      </div>

      {tab === "checks" ? (
        <ChecksTab checks={REPO_CHECKS} />
      ) : isLoading ? (
        <div className="flex h-48 items-center justify-center text-gray-500">Loading…</div>
      ) : repos?.length === 0 ? (
        <div className="flex h-48 flex-col items-center justify-center gap-3 text-gray-500">
          <GitBranch className="h-8 w-8" />
          <p>No repositories added yet.</p>
          <button onClick={() => setShowAdd(true)} className="text-indigo-400 hover:underline text-sm">Add your first repository</button>
        </div>
      ) : (
        <div className="overflow-x-auto rounded-lg border border-gray-800">
          <table className="w-full text-sm">
            <thead className="border-b border-gray-800 bg-gray-900">
              <tr className="text-left text-xs text-gray-500">
                <th className="px-4 py-3 font-medium">Repository</th>
                <th className="px-4 py-3 font-medium">Language</th>
                <th className="px-4 py-3 font-medium">Issues</th>
                <th className="px-4 py-3 font-medium">AI Risk</th>
                <th className="px-4 py-3 font-medium">Last Scanned</th>
                <th className="px-4 py-3 font-medium">Actions</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-gray-800 bg-gray-900/50">
              {repos?.map((repo) => (
                <tr key={repo.id} className="hover:bg-gray-800/40">
                  <td className="px-4 py-3">
                    <div className="font-medium text-gray-200">{repo.fullName}</div>
                    <div className="text-xs text-gray-500">
                      {repo.isPrivate ? "Private" : "Public"} · {repo.defaultBranch}
                    </div>
                  </td>
                  <td className="px-4 py-3 text-gray-400">{repo.language ?? "—"}</td>
                  <td className="px-4 py-3"><FindingCountBadges counts={repo.findingCounts} targetType="repo" targetId={repo.id} /></td>
                  <td className="px-4 py-3">
                    <RiskScoreBadge score={repo.aiRiskScore} reason={repo.aiRiskReason} />
                    {repo.aiRiskScore == null && repo.lastScannedAt && (
                      <span className="text-[10px] text-gray-600">—</span>
                    )}
                  </td>
                  <td className="px-4 py-3 text-gray-400">
                    {repo.lastScannedAt ? formatRelative(repo.lastScannedAt) : "Never"}
                  </td>
                  <td className="px-4 py-3">
                    <div className="flex items-center gap-2">
                      <ScanButton repoId={repo.id} />
                      <button
                        onClick={() => setEditRepo(repo)}
                        className="text-gray-600 hover:text-indigo-400"
                        title="Edit repository"
                      >
                        <Pencil className="h-4 w-4" />
                      </button>
                      <button
                        onClick={() => deleteRepo.mutate(repo.id)}
                        className="text-gray-600 hover:text-red-400"
                        title="Remove repository"
                      >
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

      {showAdd && <AddRepoModal onClose={() => setShowAdd(false)} />}
      {editRepo && <EditRepoModal repo={editRepo} onClose={() => setEditRepo(null)} />}
    </div>
  );
}
