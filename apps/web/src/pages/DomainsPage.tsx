import { useState } from "react";
import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import { Plus, Trash2, Pencil, Globe, X, Lock, LockOpen, FileJson, Radio, ScanSearch, Rocket } from "lucide-react";
import { domainsApi } from "../lib/api";
import DomainAuthPanel from "../components/DomainAuthPanel";
import DomainApiSpecPanel from "../components/DomainApiSpecPanel";
import RecordingPanel from "../components/RecordingPanel";
import { DomainAssetLinksPanel } from "../components/AssetLinksPanel";
import ApplicationPickerPanel from "../components/ApplicationPickerPanel";
import RiskScoreBadge from "../components/RiskScoreBadge";
import type { Domain } from "@devsecops/types";
import ScanStatusBadge from "../components/ScanStatusBadge";
import Can from "../components/Can";
import FindingCountBadges from "../components/FindingCountBadges";
import PentestWizard from "../components/PentestWizard";
import ChecksTab from "../components/ChecksTab";
import { useTargetScanStatus } from "../hooks/useTargetScanStatus";
import { useToast } from "../hooks/useToast";
import { formatRelative } from "../lib/utils";
import { DOMAIN_CHECKS, PENTEST_CHECKS } from "../data/checks";

function DastScanButton({ domainId }: { domainId: string }) {
  const qc = useQueryClient();
  const { toast } = useToast();
  const { status, isActive } = useTargetScanStatus(domainId);

  const scan = useMutation({
    mutationFn: () => domainsApi.triggerScan(domainId),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ["scans"] });
      qc.invalidateQueries({ queryKey: ["scans", "active"] });
      toast.success("Domain scan queued");
    },
    onError: (err: Error) => toast.error(err.message || "Failed to queue scan"),
  });

  // Only surface status when it's something the user should act on —
  // COMPLETED next to a "15h ago" timestamp is noise.
  const rawStatus = status ?? (scan.isPending ? "PENDING" : null);
  const displayStatus =
    rawStatus && rawStatus !== "COMPLETED" ? rawStatus : null;
  return (
    <div className="flex items-center gap-2">
      {displayStatus && <ScanStatusBadge status={displayStatus} />}
      <button
        onClick={() => scan.mutate()}
        disabled={scan.isPending || isActive}
        title="Run DAST — ZAP crawl + active attack (~10 min)"
        className="flex items-center gap-1.5 rounded-md border border-gray-800 bg-gray-900/60 px-2.5 py-1.5 text-xs font-medium text-gray-300 hover:border-sky-700/70 hover:bg-sky-950/30 hover:text-sky-200 disabled:opacity-50 transition-colors"
      >
        <ScanSearch className="h-3.5 w-3.5" /> DAST
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
        <p className="mb-3 text-xs text-gray-500">Add a domain, hostname, or internal service for DAST and pentest scanning. Examples: <span className="font-mono text-gray-400">example.com</span>, <span className="font-mono text-gray-400">localhost:4280</span>, <span className="font-mono text-gray-400">dvwa</span>.</p>
        <input
          className="w-full rounded bg-gray-800 px-3 py-2 text-sm text-gray-200 placeholder-gray-500 focus:outline-none focus:ring-1 focus:ring-indigo-500"
          placeholder="example.com or localhost:4280"
          value={domain}
          onChange={(e) => setDomain(e.target.value)}
          onKeyDown={(e) => e.key === "Enter" && add.mutate()}
        />
        <div className="mt-4 flex justify-end gap-2">
          <button onClick={onClose} className="rounded px-3 py-1.5 text-sm text-gray-400 hover:text-gray-200">Cancel</button>
          <button onClick={() => add.mutate()} disabled={!domain || add.isPending}
            className="rounded bg-indigo-700 px-4 py-1.5 text-sm font-medium text-white hover:bg-indigo-600 disabled:opacity-50">
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
      <div className="max-h-[90vh] w-full max-w-2xl overflow-y-auto rounded-xl border border-gray-700 bg-gray-900 p-6 shadow-2xl">
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
          placeholder="example.com or localhost:4280"
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
            className="rounded bg-indigo-700 px-4 py-1.5 text-sm font-medium text-white hover:bg-indigo-600 disabled:opacity-50"
          >
            {update.isPending ? "Saving…" : "Save Changes"}
          </button>
        </div>
        {/* Phase 27.5 — Application binding above the per-asset relations. */}
        <div className="mt-6 space-y-4">
          <ApplicationPickerPanel
            kind="domain"
            resourceId={domain.id}
            currentApplicationId={domain.applicationId}
          />
          <DomainAssetLinksPanel domain={domain} />
        </div>
      </div>
    </div>
  );
}

function DomainsEmptyState({ onAdd }: { onAdd: () => void }) {
  const workflows = [
    {
      icon:  <ScanSearch className="h-5 w-5 text-sky-400" />,
      title: "DAST",
      time:  "~10 min",
      desc:  "ZAP crawls the site, then attacks every URL it finds — fastest way to get a security read on a public domain.",
    },
    {
      icon:  <Radio className="h-5 w-5 text-rose-400" />,
      title: "Interactive DAST",
      time:  "~10 min + browse time",
      desc:  "Record a session by proxying your browser through ZAP, then scan only the URLs you actually visited. Reaches authenticated pages no crawler can.",
    },
    {
      icon:  <Rocket className="h-5 w-5 text-indigo-400" />,
      title: "Full Pentest",
      time:  "~25 min",
      desc:  "Runs nuclei, nikto, testssl, and targeted checks (CORS, SSRF, IDOR, SSTI). Optional AGGRESSIVE depth adds sqlmap + XSStrike.",
    },
  ];
  return (
    <div className="rounded-lg border border-dashed border-gray-800 bg-gray-900/30 p-8">
      <div className="mx-auto max-w-2xl text-center">
        <Globe className="mx-auto h-10 w-10 text-indigo-400/70" />
        <h2 className="mt-3 text-lg font-semibold text-white">Add your first domain</h2>
        <p className="mt-1 text-sm text-gray-400">
          Domains are the target for DAST, Interactive DAST, and Full Pentest scans.
          Add one below to get started.
        </p>
        <button
          onClick={onAdd}
          className="mt-4 inline-flex items-center gap-2 rounded-lg bg-indigo-700 px-4 py-2 text-sm font-medium text-white hover:bg-indigo-600"
        >
          <Plus className="h-4 w-4" /> Add Domain
        </button>
      </div>

      <div className="mx-auto mt-8 grid max-w-4xl gap-3 sm:grid-cols-3">
        {workflows.map((w) => (
          <div key={w.title} className="rounded border border-gray-800 bg-gray-900/60 p-4">
            <div className="mb-2 flex items-center justify-between">
              <div className="flex items-center gap-2">
                {w.icon}
                <span className="text-sm font-semibold text-white">{w.title}</span>
              </div>
              <span className="rounded-full bg-gray-800 px-2 py-0.5 text-[10px] text-gray-400">{w.time}</span>
            </div>
            <p className="text-xs leading-relaxed text-gray-400">{w.desc}</p>
          </div>
        ))}
      </div>

      <p className="mx-auto mt-6 max-w-2xl text-center text-[11px] text-gray-600">
        Only scan domains you own or have explicit authorization to test.
      </p>
    </div>
  );
}

export default function DomainsPage() {
  const [showAdd, setShowAdd] = useState(false);
  const [editDomain, setEditDomain] = useState<Domain | null>(null);
  const [pentestDomain, setPentestDomain] = useState<Domain | null>(null);
  const [authOpenId, setAuthOpenId] = useState<string | null>(null);
  const [apiSpecOpenId, setApiSpecOpenId] = useState<string | null>(null);
  const [recordingOpenId, setRecordingOpenId] = useState<string | null>(null);
  const [tab, setTab] = useState<"domains" | "dast-checks" | "pentest-checks">("domains");
  const qc = useQueryClient();
  const { data: domains, isLoading } = useQuery({ queryKey: ["domains"], queryFn: domainsApi.list });
  const del = useMutation({ mutationFn: (id: string) => domainsApi.delete(id), onSuccess: () => qc.invalidateQueries({ queryKey: ["domains"] }) });

  return (
    <div className="p-6">
      <div className="mb-4 flex items-center justify-between">
        <h1 className="text-3xl font-bold text-white">Domains</h1>
        {tab === "domains" && (
          <button onClick={() => setShowAdd(true)} className="flex items-center gap-2 rounded-lg bg-indigo-700 px-4 py-2 text-sm font-medium text-white hover:bg-indigo-600">
            <Plus className="h-4 w-4" /> Add Domain
          </button>
        )}
      </div>

      {/* Tabs */}
      <div className="mb-5 flex gap-1 border-b border-gray-800">
        {([
          { key: "domains",        label: "Domains" },
          { key: "dast-checks",    label: "DAST & API Checks" },
          { key: "pentest-checks", label: "Full Pentest Checks" },
        ] as const).map(({ key, label }) => (
          <button
            key={key}
            onClick={() => setTab(key)}
            className={`px-4 py-2 text-sm font-medium transition-colors border-b-2 -mb-px ${
              tab === key
                ? "border-indigo-500 text-white"
                : "border-transparent text-gray-500 hover:text-gray-300"
            }`}
          >
            {label}
          </button>
        ))}
      </div>

      {tab === "dast-checks" ? (
        <ChecksTab checks={DOMAIN_CHECKS} />
      ) : tab === "pentest-checks" ? (
        <ChecksTab checks={PENTEST_CHECKS} />
      ) : (
        <>
      {isLoading ? (
        <div className="flex h-48 items-center justify-center text-gray-500">Loading…</div>
      ) : domains?.length === 0 ? (
        <DomainsEmptyState onAdd={() => setShowAdd(true)} />
      ) : (
        <div className="overflow-x-auto rounded-lg border border-gray-800">
          <table className="w-full text-sm">
            <thead className="border-b border-gray-800 bg-gray-900">
              <tr className="text-left text-xs text-gray-500">
                <th className="px-4 py-3 font-medium">Domain</th>
                <th className="px-4 py-3 font-medium">Issues</th>
                <th className="px-4 py-3 font-medium">AI Risk</th>
                <th className="px-4 py-3 font-medium">Last Scanned</th>
                <th className="px-4 py-3 font-medium" aria-label="Actions"></th>
              </tr>
            </thead>
            <tbody className="divide-y divide-gray-800 bg-gray-900/50">
              {domains?.map((d) => (
                <>
                  <tr key={d.id} className="hover:bg-gray-800/40">
                    <td className="px-4 py-3 font-medium text-gray-200">{d.domain}</td>
                    <td className="px-4 py-3"><FindingCountBadges counts={d.findingCounts} targetType="domain" targetId={d.id} /></td>
                    <td className="px-4 py-3"><RiskScoreBadge score={d.aiRiskScore} reason={d.aiRiskReason} /></td>
                    <td className="px-4 py-3 text-gray-400">{d.lastScannedAt ? formatRelative(d.lastScannedAt) : "Never"}</td>
                    <td className="px-4 py-3">
                      <div className="flex flex-wrap items-center gap-1.5">
                        {/* ── Scan actions: three equal-weight, colour-coded buttons ── */}
                        <DastScanButton domainId={d.id} />

                        <button
                          onClick={() => setRecordingOpenId(recordingOpenId === d.id ? null : d.id)}
                          title={
                            d.activeRecordingUrls !== null && d.activeRecordingUrls !== undefined
                              ? `Interactive DAST — recording active (${d.activeRecordingUrls} URLs captured)`
                              : "Interactive DAST — record a browser session, then scan what you visited"
                          }
                          className={`flex items-center gap-1.5 rounded-md border px-2.5 py-1.5 text-xs font-medium transition-colors ${
                            recordingOpenId === d.id
                              ? "border-rose-700/70 bg-rose-950/30 text-rose-200"
                              : "border-gray-800 bg-gray-900/60 text-gray-300 hover:border-rose-700/70 hover:bg-rose-950/30 hover:text-rose-200"
                          }`}
                        >
                          <Radio
                            className={`h-3.5 w-3.5 ${
                              d.activeRecordingUrls !== null && d.activeRecordingUrls !== undefined
                                ? "text-rose-400 animate-pulse"
                                : ""
                            }`}
                          />
                          Interactive
                        </button>

                        <button
                          onClick={() => setPentestDomain(d)}
                          title="Full Pentest — nuclei + nikto + testssl + targeted checks (~25 min)"
                          className="flex items-center gap-1.5 rounded-md border border-gray-800 bg-gray-900/60 px-2.5 py-1.5 text-xs font-medium text-gray-300 hover:border-indigo-700/70 hover:bg-indigo-950/30 hover:text-indigo-200 transition-colors"
                        >
                          <Rocket className="h-3.5 w-3.5" /> Pentest
                        </button>

                        {/* ── Divider ── */}
                        <span className="mx-1 h-6 w-px bg-gray-800" aria-hidden />

                        {/* ── Config chips: icon + label + status hint ── */}
                        <button
                          onClick={() => setAuthOpenId(authOpenId === d.id ? null : d.id)}
                          title={d.hasAuthConfig ? "Scan credentials configured" : "No scan credentials set"}
                          className={`flex items-center gap-1.5 rounded-md border px-2 py-1.5 text-xs transition-colors ${
                            authOpenId === d.id
                              ? "border-indigo-700/70 bg-indigo-950/30 text-indigo-200"
                              : "border-gray-800 bg-gray-900/60 text-gray-400 hover:border-gray-600 hover:text-gray-200"
                          }`}
                        >
                          {d.hasAuthConfig ? (
                            <Lock className="h-3.5 w-3.5 text-indigo-400" />
                          ) : (
                            <LockOpen className="h-3.5 w-3.5 text-gray-600" />
                          )}
                          Auth
                        </button>

                        <button
                          onClick={() => setApiSpecOpenId(apiSpecOpenId === d.id ? null : d.id)}
                          title={d.hasApiSpec ? "OpenAPI/Swagger spec imported" : "No API spec imported"}
                          className={`flex items-center gap-1.5 rounded-md border px-2 py-1.5 text-xs transition-colors ${
                            apiSpecOpenId === d.id
                              ? "border-indigo-700/70 bg-indigo-950/30 text-indigo-200"
                              : "border-gray-800 bg-gray-900/60 text-gray-400 hover:border-gray-600 hover:text-gray-200"
                          }`}
                        >
                          <FileJson
                            className={`h-3.5 w-3.5 ${
                              d.hasApiSpec ? "text-indigo-400" : "text-gray-600"
                            }`}
                          />
                          Spec
                        </button>

                        {/* ── Meta icons: housekeeping, faded ── */}
                        <span className="ml-auto flex items-center gap-1">
                          <button onClick={() => setEditDomain(d)} className="rounded p-1 text-gray-600 hover:text-indigo-400" title="Edit domain">
                            <Pencil className="h-3.5 w-3.5" />
                          </button>
                          <Can role="ADMIN">
                            <button onClick={() => del.mutate(d.id)} className="rounded p-1 text-gray-600 hover:text-red-400" title="Remove domain (ADMIN only)">
                              <Trash2 className="h-3.5 w-3.5" />
                            </button>
                          </Can>
                        </span>
                      </div>
                    </td>
                  </tr>
                  {authOpenId === d.id && (
                    <tr key={`${d.id}-auth`} className="bg-gray-800/20">
                      <td colSpan={5} className="px-4 py-2">
                        <DomainAuthPanel domainId={d.id} />
                      </td>
                    </tr>
                  )}
                  {apiSpecOpenId === d.id && (
                    <tr key={`${d.id}-apispec`} className="bg-gray-800/20">
                      <td colSpan={5} className="px-4 py-2">
                        <DomainApiSpecPanel domainId={d.id} />
                      </td>
                    </tr>
                  )}
                  {recordingOpenId === d.id && (
                    <tr key={`${d.id}-recording`} className="bg-gray-800/20">
                      <td colSpan={5} className="px-4 py-2">
                        <RecordingPanel domainId={d.id} />
                      </td>
                    </tr>
                  )}
                </>
              ))}
            </tbody>
          </table>
        </div>
      )}
        </>
      )}
      {showAdd && <AddDomainModal onClose={() => setShowAdd(false)} />}
      {editDomain && <EditDomainModal domain={editDomain} onClose={() => setEditDomain(null)} />}
      {pentestDomain && (
        <PentestWizard
          domain={pentestDomain}
          onClose={() => setPentestDomain(null)}
          onLaunched={() => {
            qc.invalidateQueries({ queryKey: ["scans", "active"] });
            setPentestDomain(null);
          }}
        />
      )}
    </div>
  );
}
