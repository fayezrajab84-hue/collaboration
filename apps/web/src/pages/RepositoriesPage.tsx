import { useState } from "react";
import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import { Plus, Play, Trash2, Pencil, GitBranch, X, FileDown, Lock, Globe, Check, Search } from "lucide-react";
import { reposApi, sbomApi } from "../lib/api";
import Can from "../components/Can";
import type { Repository } from "@devsecops/types";
import RiskScoreBadge from "../components/RiskScoreBadge";
import ScanStatusBadge from "../components/ScanStatusBadge";
import FindingCountBadges from "../components/FindingCountBadges";
import ChecksTab from "../components/ChecksTab";
import { RepoAssetLinksPanel } from "../components/AssetLinksPanel";
import ApplicationPickerPanel from "../components/ApplicationPickerPanel";
import { useTargetScanStatus } from "../hooks/useTargetScanStatus";
import { useToast } from "../hooks/useToast";
import { formatRelative } from "../lib/utils";
import { REPO_CHECKS } from "../data/checks";

function ScanButton({ repoId }: { repoId: string }) {
  const qc = useQueryClient();
  const { toast } = useToast();
  const { status, isActive } = useTargetScanStatus(repoId);

  const scan = useMutation({
    mutationFn: () => reposApi.triggerScan(repoId),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ["scans"] });
      qc.invalidateQueries({ queryKey: ["scans", "active"] });
      toast.success("Scan queued — findings will appear as they are discovered");
    },
    onError: (err: Error) => toast.error(err.message || "Failed to queue scan"),
  });

  // Only show status when it's something to act on — COMPLETED next to a
  // "2h ago" timestamp is noise.
  const rawStatus = status ?? (scan.isPending ? "PENDING" : null);
  const displayStatus = rawStatus && rawStatus !== "COMPLETED" ? rawStatus : null;

  return (
    <div className="flex items-center gap-2">
      {displayStatus && <ScanStatusBadge status={displayStatus} />}
      <button
        onClick={() => scan.mutate()}
        disabled={scan.isPending || isActive}
        className="flex items-center gap-1.5 rounded bg-indigo-700 px-3 py-1.5 text-xs font-medium text-white hover:bg-indigo-700 disabled:opacity-50"
      >
        <Play className="h-3 w-3" />
        Scan
      </button>
    </div>
  );
}

function AddRepoModal({ onClose }: { onClose: () => void }) {
  const [mode, setMode] = useState<"github" | "url">("github");
  const [url, setUrl] = useState("");
  const [search, setSearch] = useState("");
  const [pendingFullName, setPendingFullName] = useState<string | null>(null);
  const qc = useQueryClient();

  const { data: ghRepos, isLoading: ghLoading, error: ghError } = useQuery({
    queryKey: ["repos", "github"],
    queryFn:  () => reposApi.listGitHub(1),
    enabled:  mode === "github",
    staleTime: 60_000,
  });

  const add = useMutation({
    mutationFn: (githubUrl: string) => reposApi.create({ githubUrl }),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ["repos"] });
      qc.invalidateQueries({ queryKey: ["repos", "github"] });
      setPendingFullName(null);
      if (mode === "url") onClose();
    },
    onError: () => setPendingFullName(null),
  });

  const filtered = (ghRepos ?? []).filter((r) =>
    search.trim() === "" || r.fullName.toLowerCase().includes(search.toLowerCase()),
  );

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/60">
      <div className="w-full max-w-2xl rounded-xl border border-gray-700 bg-gray-900 shadow-2xl flex flex-col max-h-[85vh]">
        <div className="flex items-center justify-between border-b border-gray-800 px-6 py-4">
          <h2 className="text-base font-semibold text-white">Add Repository</h2>
          <button onClick={onClose} className="text-gray-500 hover:text-gray-200"><X className="h-4 w-4" /></button>
        </div>

        {/* Tabs */}
        <div className="flex gap-1 border-b border-gray-800 px-6">
          {(["github", "url"] as const).map((m) => (
            <button
              key={m}
              onClick={() => setMode(m)}
              className={`px-4 py-2.5 text-sm font-medium transition-colors border-b-2 -mb-px ${
                mode === m
                  ? "border-indigo-500 text-white"
                  : "border-transparent text-gray-500 hover:text-gray-300"
              }`}
            >
              {m === "github" ? "From my GitHub" : "By URL"}
            </button>
          ))}
        </div>

        {/* Body */}
        <div className="flex-1 overflow-y-auto px-6 py-4">
          {mode === "github" ? (
            <>
              <div className="relative mb-3">
                <Search className="absolute left-2.5 top-1/2 h-3.5 w-3.5 -translate-y-1/2 text-gray-500" />
                <input
                  className="w-full rounded bg-gray-800 pl-8 pr-3 py-2 text-sm text-gray-200 placeholder-gray-500 focus:outline-none focus:ring-1 focus:ring-indigo-500"
                  placeholder="Filter your repositories…"
                  value={search}
                  onChange={(e) => setSearch(e.target.value)}
                  autoFocus
                />
              </div>
              {ghLoading ? (
                <div className="flex h-40 items-center justify-center text-sm text-gray-500">Loading your GitHub repositories…</div>
              ) : ghError ? (
                <div className="rounded border border-red-900/60 bg-red-950/30 p-4 text-sm text-red-300">
                  Failed to load GitHub repos. Make sure you granted the <code className="rounded bg-red-900/40 px-1">repo</code> scope when signing in.
                </div>
              ) : filtered.length === 0 ? (
                <div className="flex h-40 items-center justify-center text-sm text-gray-500">
                  {search ? "No repositories match." : "No repositories found on your GitHub account."}
                </div>
              ) : (
                <ul className="divide-y divide-gray-800 rounded border border-gray-800">
                  {filtered.map((r) => {
                    const adding = add.isPending && pendingFullName === r.fullName;
                    return (
                      <li key={r.id} className="flex items-center gap-3 px-3 py-2.5 hover:bg-gray-800/40">
                        <span className="shrink-0" title={r.isPrivate ? "Private" : "Public"}>
                          {r.isPrivate ? <Lock className="h-3.5 w-3.5 text-amber-400" /> : <Globe className="h-3.5 w-3.5 text-gray-500" />}
                        </span>
                        <div className="flex-1 min-w-0">
                          <div className="truncate font-medium text-gray-200">{r.fullName}</div>
                          <div className="text-xs text-gray-500">
                            {r.language ?? "—"} · default branch <code className="rounded bg-gray-800 px-1">{r.defaultBranch}</code>
                          </div>
                        </div>
                        {r.added ? (
                          <span className="flex items-center gap-1 rounded bg-indigo-900/30 border border-indigo-800/50 px-2 py-1 text-xs text-indigo-400">
                            <Check className="h-3 w-3" /> Added
                          </span>
                        ) : (
                          <button
                            onClick={() => { setPendingFullName(r.fullName); add.mutate(r.url); }}
                            disabled={add.isPending}
                            className="rounded bg-indigo-700 px-3 py-1 text-xs font-medium text-white hover:bg-indigo-600 disabled:opacity-50"
                          >
                            {adding ? "Adding…" : "Add"}
                          </button>
                        )}
                      </li>
                    );
                  })}
                </ul>
              )}
              {add.error && (
                <p className="mt-3 text-xs text-red-400">{(add.error as Error).message}</p>
              )}
            </>
          ) : (
            <>
              <label className="mb-1 block text-xs font-medium text-gray-400">GitHub URL</label>
              <input
                className="w-full rounded bg-gray-800 px-3 py-2 text-sm text-gray-200 placeholder-gray-500 focus:outline-none focus:ring-1 focus:ring-indigo-500"
                placeholder="https://github.com/owner/repo"
                value={url}
                onChange={(e) => setUrl(e.target.value)}
                onKeyDown={(e) => e.key === "Enter" && url && add.mutate(url)}
                autoFocus
              />
              <p className="mt-2 text-xs text-gray-500">Works for any repo your GitHub token can access, including private ones.</p>
              {add.error && (
                <p className="mt-2 text-xs text-red-400">{(add.error as Error).message}</p>
              )}
            </>
          )}
        </div>

        <div className="flex justify-end gap-2 border-t border-gray-800 px-6 py-3">
          <button onClick={onClose} className="rounded px-3 py-1.5 text-sm text-gray-400 hover:text-gray-200">
            {mode === "github" ? "Done" : "Cancel"}
          </button>
          {mode === "url" && (
            <button
              onClick={() => add.mutate(url)}
              disabled={!url || add.isPending}
              className="rounded bg-indigo-700 px-4 py-1.5 text-sm font-medium text-white hover:bg-indigo-600 disabled:opacity-50"
            >
              {add.isPending ? "Adding…" : "Add Repository"}
            </button>
          )}
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
      <div className="max-h-[90vh] w-full max-w-2xl overflow-y-auto rounded-xl border border-gray-700 bg-gray-900 p-6 shadow-2xl">
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
            className="rounded bg-indigo-700 px-4 py-1.5 text-sm font-medium text-white hover:bg-indigo-600 disabled:opacity-50"
          >
            {update.isPending ? "Saving…" : "Save Changes"}
          </button>
        </div>
        {/* Phase 27.5 — Application binding sits at the top because it's the
            higher-leverage decision: pick which app this asset belongs to,
            then declare the per-asset relations within that app. */}
        <div className="mt-6 space-y-4">
          <ApplicationPickerPanel
            kind="repository"
            resourceId={repo.id}
            currentApplicationId={repo.applicationId}
          />
          <RepoAssetLinksPanel repo={repo} />
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
            className="flex items-center gap-2 rounded-lg bg-indigo-700 px-4 py-2 text-sm font-medium text-white hover:bg-indigo-600"
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
                <th className="px-4 py-3 font-medium" aria-label="Actions"></th>
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
                      <div className="flex items-center rounded border border-gray-700 bg-gray-800 text-xs text-gray-300 hover:border-indigo-600">
                        <a
                          href={sbomApi.repoUrl(repo.id, "cyclonedx")}
                          className="flex items-center gap-1 px-2 py-1 hover:bg-indigo-900/30 hover:text-indigo-300"
                          title="Download CycloneDX SBOM (software bill of materials, JSON)"
                          download
                        >
                          <FileDown className="h-3 w-3" />
                          SBOM
                        </a>
                        <span className="h-3.5 w-px bg-gray-700" />
                        <a
                          href={sbomApi.repoUrl(repo.id, "spdx")}
                          className="px-2 py-1 text-[10px] uppercase tracking-wide text-gray-500 hover:bg-indigo-900/30 hover:text-indigo-300"
                          title="Download SPDX SBOM (ISO/IEC 5962, JSON)"
                          download
                        >
                          spdx
                        </a>
                      </div>
                      <Can role="DEVELOPER">
                        <button
                          onClick={() => setEditRepo(repo)}
                          className="text-gray-600 hover:text-indigo-400"
                          title="Edit repository"
                        >
                          <Pencil className="h-4 w-4" />
                        </button>
                      </Can>
                      <Can role="ADMIN">
                        <button
                          onClick={() => deleteRepo.mutate(repo.id)}
                          className="text-gray-600 hover:text-red-400"
                          title="Remove repository"
                        >
                          <Trash2 className="h-4 w-4" />
                        </button>
                      </Can>
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
