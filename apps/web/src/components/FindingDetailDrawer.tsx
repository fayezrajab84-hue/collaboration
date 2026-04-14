import { useState } from "react";
import { X, ChevronDown, ChevronUp, ExternalLink } from "lucide-react";
import { useMutation, useQueryClient } from "@tanstack/react-query";
import type { Finding } from "@devsecops/types";
import { findingsApi, ticketsApi } from "../lib/api";
import SeverityBadge from "./SeverityBadge";
import { formatDate } from "../lib/utils";

interface Props {
  finding: Finding | null;
  onClose: () => void;
}

export default function FindingDetailDrawer({ finding, onClose }: Props) {
  const [showRaw, setShowRaw] = useState(false);
  const qc = useQueryClient();

  const updateStatus = useMutation({
    mutationFn: (status: string) =>
      findingsApi.update(finding!.id, { status: status as never }),
    onSuccess: () => qc.invalidateQueries({ queryKey: ["findings"] }),
  });

  const createTicket = useMutation({
    mutationFn: () =>
      ticketsApi.create({
        findingId: finding!.id,
        title: finding!.title,
        priority: finding!.severity as never,
        createJiraIssue: false,
      }),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ["tickets"] });
      qc.invalidateQueries({ queryKey: ["findings"] });
    },
  });

  if (!finding) return null;

  return (
    <div className="fixed inset-0 z-50 flex justify-end">
      {/* Backdrop */}
      <div className="absolute inset-0 bg-black/60" onClick={onClose} />

      {/* Drawer */}
      <div className="relative z-10 flex h-full w-full max-w-xl flex-col bg-gray-900 shadow-2xl">
        {/* Header */}
        <div className="flex items-start justify-between border-b border-gray-800 p-5">
          <div className="flex-1 pr-4">
            <div className="mb-2 flex flex-wrap items-center gap-2">
              <SeverityBadge severity={finding.severity} />
              <span className="rounded bg-gray-800 px-2 py-0.5 text-xs text-gray-400">
                {finding.scanType}
              </span>
              <span className="rounded bg-gray-800 px-2 py-0.5 text-xs text-gray-400">
                {finding.scanner}
              </span>
            </div>
            <h2 className="text-base font-semibold text-white">{finding.title}</h2>
          </div>
          <button onClick={onClose} className="text-gray-500 hover:text-gray-200">
            <X className="h-5 w-5" />
          </button>
        </div>

        {/* Body */}
        <div className="flex-1 overflow-y-auto p-5 space-y-5">
          {/* Description */}
          <div>
            <h3 className="mb-1.5 text-xs font-semibold uppercase tracking-wider text-gray-500">
              Description
            </h3>
            <p className="text-sm text-gray-300 leading-relaxed">{finding.description}</p>
          </div>

          {/* Location */}
          {finding.filePath && (
            <div>
              <h3 className="mb-1.5 text-xs font-semibold uppercase tracking-wider text-gray-500">
                Location
              </h3>
              <code className="rounded bg-gray-800 px-3 py-1.5 text-xs text-indigo-300">
                {finding.filePath}
                {finding.lineStart ? `:${finding.lineStart}` : ""}
                {finding.lineEnd && finding.lineEnd !== finding.lineStart ? `–${finding.lineEnd}` : ""}
              </code>
            </div>
          )}

          {/* Vulnerability info */}
          {(finding.cveId || finding.cvssScore || finding.packageName) && (
            <div>
              <h3 className="mb-2 text-xs font-semibold uppercase tracking-wider text-gray-500">
                Vulnerability Details
              </h3>
              <dl className="grid grid-cols-2 gap-2 text-sm">
                {finding.cveId && (
                  <>
                    <dt className="text-gray-500">CVE</dt>
                    <dd className="font-mono text-gray-200">{finding.cveId}</dd>
                  </>
                )}
                {finding.cvssScore !== null && finding.cvssScore !== undefined && (
                  <>
                    <dt className="text-gray-500">CVSS Score</dt>
                    <dd className="font-semibold text-gray-200">{finding.cvssScore.toFixed(1)}</dd>
                  </>
                )}
                {finding.packageName && (
                  <>
                    <dt className="text-gray-500">Package</dt>
                    <dd className="font-mono text-gray-200">
                      {finding.packageName}
                      {(finding as unknown as { packageVersion?: string }).packageVersion
                        ? `@${(finding as unknown as { packageVersion?: string }).packageVersion}`
                        : ""}
                    </dd>
                  </>
                )}
                {(finding as unknown as { fixVersion?: string }).fixVersion && (
                  <>
                    <dt className="text-gray-500">Fix version</dt>
                    <dd className="font-mono text-green-400">
                      {(finding as unknown as { fixVersion?: string }).fixVersion}
                    </dd>
                  </>
                )}
              </dl>
            </div>
          )}

          {/* Remediation */}
          {finding.remediation && (
            <div>
              <h3 className="mb-1.5 text-xs font-semibold uppercase tracking-wider text-gray-500">
                Remediation
              </h3>
              <p className="text-sm text-gray-300">{finding.remediation}</p>
            </div>
          )}

          {/* Metadata */}
          <div>
            <h3 className="mb-2 text-xs font-semibold uppercase tracking-wider text-gray-500">
              Metadata
            </h3>
            <dl className="grid grid-cols-2 gap-2 text-sm">
              <dt className="text-gray-500">First seen</dt>
              <dd className="text-gray-300">{formatDate(finding.firstSeen)}</dd>
              <dt className="text-gray-500">Last seen</dt>
              <dd className="text-gray-300">{formatDate(finding.lastSeen)}</dd>
              <dt className="text-gray-500">Status</dt>
              <dd className="text-gray-300">{finding.status}</dd>
              {finding.ruleId && (
                <>
                  <dt className="text-gray-500">Rule ID</dt>
                  <dd className="truncate font-mono text-xs text-gray-400">{finding.ruleId}</dd>
                </>
              )}
            </dl>
          </div>

          {/* Raw output */}
          <div>
            <button
              onClick={() => setShowRaw((v) => !v)}
              className="flex items-center gap-1 text-xs font-medium text-gray-500 hover:text-gray-300"
            >
              {showRaw ? <ChevronUp className="h-3.5 w-3.5" /> : <ChevronDown className="h-3.5 w-3.5" />}
              Raw scanner output
            </button>
            {showRaw && (
              <pre className="mt-2 max-h-48 overflow-auto rounded bg-gray-950 p-3 text-xs text-gray-400 scrollbar-thin">
                {JSON.stringify(finding.rawOutput, null, 2)}
              </pre>
            )}
          </div>
        </div>

        {/* Footer actions */}
        <div className="flex items-center gap-3 border-t border-gray-800 p-4">
          <select
            value={finding.status}
            onChange={(e) => updateStatus.mutate(e.target.value)}
            className="flex-1 rounded bg-gray-800 px-3 py-1.5 text-sm text-gray-200 focus:outline-none focus:ring-1 focus:ring-indigo-500"
          >
            <option value="OPEN">Open</option>
            <option value="ACKNOWLEDGED">Acknowledged</option>
            <option value="FALSE_POSITIVE">False Positive</option>
            <option value="FIXED">Fixed</option>
          </select>

          <button
            onClick={() => createTicket.mutate()}
            disabled={createTicket.isPending || !!(finding as unknown as { ticket?: unknown }).ticket}
            className="rounded bg-indigo-600 px-3 py-1.5 text-sm font-medium text-white hover:bg-indigo-500 disabled:opacity-50"
          >
            {(finding as unknown as { ticket?: unknown }).ticket ? "Ticket exists" : "Create Ticket"}
          </button>
        </div>
      </div>
    </div>
  );
}
