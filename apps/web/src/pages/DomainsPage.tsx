import { useState } from "react";
import { useNavigate } from "react-router-dom";
import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import {
  Plus, Globe, X, Radio, ScanSearch, Rocket, ChevronRight, Lock, FileJson,
  Network as NetworkIcon,
} from "lucide-react";
import { domainsApi } from "../lib/api";
import RiskScoreBadge from "../components/RiskScoreBadge";
import ScanStatusBadge from "../components/ScanStatusBadge";
import FindingCountBadges from "../components/FindingCountBadges";
import ChecksTab from "../components/ChecksTab";
import { useTargetScanStatus } from "../hooks/useTargetScanStatus";
import { formatRelative } from "../lib/utils";
import { DOMAIN_CHECKS, PENTEST_CHECKS } from "../data/checks";

/**
 * Tiny status pip — read-only "this domain has X configured" hint, used
 * on the simplified row. Replaces the chip-cluster pattern; the actual
 * config lives on the Domain detail page now.
 */
function ConfigPip({ active, label, icon: Icon }: {
  active: boolean | undefined;
  label:  string;
  icon:   typeof Lock;
}) {
  return (
    <span
      title={`${label}: ${active ? "configured" : "not set"}`}
      className={`inline-flex items-center gap-1 text-[10px] ${
        active ? "text-indigo-300" : "text-gray-700"
      }`}
    >
      <Icon className="h-3 w-3" />
      {active && <span className="text-[9px]">{label}</span>}
    </span>
  );
}

/**
 * Status indicator for a row when a scan is mid-flight. Reads the live
 * scan-status hook so the row shows "RUNNING" without the operator
 * needing to refresh.
 */
function RowScanStatus({ domainId }: { domainId: string }) {
  const { status } = useTargetScanStatus(domainId);
  if (!status || status === "COMPLETED") return null;
  return <ScanStatusBadge status={status} />;
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

// EditDomainModal was removed in Phase 27 UI refactor — domain rename
// + asset-links + application picker now live on /domains/:id (the detail
// page). Single source of truth, less context-switching for the operator.

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
  const [tab, setTab] = useState<"domains" | "dast-checks" | "pentest-checks">("domains");
  const navigate = useNavigate();
  const { data: domains, isLoading } = useQuery({ queryKey: ["domains"], queryFn: domainsApi.list });

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
                <th className="px-4 py-3 font-medium">Status</th>
                <th className="px-4 py-3 font-medium" aria-label="Open"></th>
              </tr>
            </thead>
            <tbody className="divide-y divide-gray-800 bg-gray-900/50">
              {/*
                Row UX (post-refactor):
                  - Whole row is a single click → navigate("/domains/:id").
                    No more chip-cluster, no more inline-expanding panels —
                    config + scan launcher both live on the detail page.
                  - Read-only "config pips" surface what's set (Auth / Spec
                    / Recording / URL count) so the operator can see at a
                    glance which domains have what without drilling in.
                  - Running scans show a status badge in the row's status
                    column so the operator doesn't have to open the detail
                    page to know "is it scanning right now".
              */}
              {domains?.map((d) => (
                <tr
                  key={d.id}
                  onClick={() => navigate(`/domains/${d.id}`)}
                  className="cursor-pointer transition-colors hover:bg-gray-800/40"
                >
                  <td className="px-4 py-3">
                    <div className="flex items-center gap-2">
                      <Globe className="h-3.5 w-3.5 flex-shrink-0 text-indigo-400" />
                      <span className="font-medium text-gray-200">{d.domain}</span>
                    </div>
                    <div className="mt-1 flex items-center gap-3 pl-5 text-[11px] text-gray-600">
                      <ConfigPip active={d.hasAuthConfig} label="Auth"      icon={Lock}        />
                      <ConfigPip active={d.hasApiSpec}    label="API Spec"  icon={FileJson}    />
                      <ConfigPip
                        active={(d.activeRecordingUrls ?? 0) > 0}
                        label={(d.activeRecordingUrls ?? 0) > 0 ? `${d.activeRecordingUrls} URLs` : "URLs"}
                        icon={NetworkIcon}
                      />
                    </div>
                  </td>
                  <td className="px-4 py-3">
                    <FindingCountBadges counts={d.findingCounts} targetType="domain" targetId={d.id} />
                  </td>
                  <td className="px-4 py-3">
                    <RiskScoreBadge score={d.aiRiskScore} reason={d.aiRiskReason} />
                  </td>
                  <td className="px-4 py-3 text-gray-400">
                    {d.lastScannedAt ? formatRelative(d.lastScannedAt) : "Never"}
                  </td>
                  <td className="px-4 py-3">
                    <RowScanStatus domainId={d.id} />
                  </td>
                  <td className="px-4 py-3">
                    <span className="inline-flex items-center gap-1 text-xs text-gray-500 group-hover:text-indigo-300">
                      Open
                      <ChevronRight className="h-3.5 w-3.5" />
                    </span>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
        </>
      )}
      {showAdd && <AddDomainModal onClose={() => setShowAdd(false)} />}
    </div>
  );
}
