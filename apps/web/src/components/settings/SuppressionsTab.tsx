/**
 * Suppressions tab — org-level audit + revoke for accepted-risk records.
 *
 * Surfaces the same data SECURITY+ users have always been able to manage
 * inline in FindingDetailDrawer, but at the org level so admins can scan
 * the whole accepted-risk list without drilling into each finding.
 *
 * Tab visibility is gated on SECURITY by SettingsPage's tab filter (the
 * tab simply doesn't render for VIEWER/DEVELOPER). The Revoke button is
 * additionally wrapped in <Can role="SECURITY"> for defense-in-depth in
 * case the tab is ever displayed via deep-link.
 */
import { useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { Shield, X } from "lucide-react";
import { suppressionsApi } from "../../lib/api";
import { useToast } from "../../hooks/useToast";
import Can from "../Can";
import { formatDate } from "../../lib/utils";

export default function SuppressionsTab() {
  const qc = useQueryClient();
  const { toast } = useToast();
  const [showAll, setShowAll] = useState(false);

  // active=true → only currently-effective records (not yet expired or
  // revoked). Toggle reveals historical entries too — useful for auditors
  // verifying "this risk was accepted between dates X and Y".
  const { data: rows = [], isLoading, refetch } = useQuery({
    queryKey: ["suppressions", { active: !showAll }],
    queryFn:  () => suppressionsApi.list(!showAll),
  });

  const revoke = useMutation({
    mutationFn: (id: string) => suppressionsApi.revoke(id),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ["suppressions"] });
      toast.success("Suppression revoked");
    },
    onError: (err: Error) => toast.error(err.message || "Failed to revoke suppression"),
  });

  function fmtExpiry(expiresAt: string | Date | null): string {
    if (!expiresAt) return "Never";
    const d = new Date(expiresAt);
    const now = Date.now();
    if (d.getTime() < now) return `Expired ${formatDate(d)}`;
    return formatDate(d);
  }

  return (
    <div className="space-y-6">
      <div className="flex items-start justify-between">
        <div>
          <div className="flex items-center gap-2">
            <Shield className="h-3.5 w-3.5 text-indigo-400" />
            <h2 className="text-base font-semibold text-white">Accepted-Risk Suppressions</h2>
          </div>
          <p className="mt-1 text-xs text-gray-400">
            Findings that have been deliberately suppressed with a written
            justification. Required for compliance evidence — every entry
            shows who approved it and when it expires.
          </p>
        </div>
        <label className="flex items-center gap-2 text-xs text-gray-400">
          <input
            type="checkbox"
            checked={showAll}
            onChange={(e) => setShowAll(e.target.checked)}
            className="rounded border-gray-700 bg-gray-800 text-indigo-600 focus:ring-indigo-500"
          />
          Include revoked / expired
        </label>
      </div>

      {isLoading ? (
        <div className="rounded-lg border border-gray-800 bg-gray-900/40 p-6 text-center text-xs text-gray-500">
          Loading suppressions…
        </div>
      ) : rows.length === 0 ? (
        <div className="rounded-lg border border-gray-800 bg-gray-900/40 p-8 text-center">
          <Shield className="mx-auto h-6 w-6 text-gray-700" />
          <p className="mt-2 text-xs text-gray-500">
            {showAll
              ? "No suppression records on file."
              : "No active suppressions. Findings can be suppressed individually from the finding detail panel."}
          </p>
        </div>
      ) : (
        <div className="overflow-hidden rounded-lg border border-gray-800">
          <table className="w-full text-xs">
            <thead className="bg-gray-900/60 text-left text-[10px] font-semibold uppercase tracking-wider text-gray-500">
              <tr>
                <th className="px-3 py-2">Fingerprint</th>
                <th className="px-3 py-2">Reason</th>
                <th className="px-3 py-2">Approved by</th>
                <th className="px-3 py-2">Created</th>
                <th className="px-3 py-2">Expires</th>
                <th className="px-3 py-2">Status</th>
                <th className="px-3 py-2 text-right" />
              </tr>
            </thead>
            <tbody className="divide-y divide-gray-800 text-gray-300">
              {rows.map((s) => {
                const isRevoked = !!s.revokedAt;
                const isExpired =
                  !isRevoked &&
                  s.expiresAt !== null &&
                  new Date(s.expiresAt).getTime() < Date.now();
                const status =
                  isRevoked ? "Revoked"
                  : isExpired ? "Expired"
                  : "Active";
                const statusColor =
                  status === "Active"
                    ? "bg-indigo-900/40 border-indigo-800/40 text-indigo-300"
                    : "bg-gray-800/60 border-gray-700 text-gray-400";

                return (
                  <tr key={s.id} className="hover:bg-gray-900/30">
                    <td className="px-3 py-2 font-mono text-[11px] text-gray-400" title={s.fingerprint}>
                      {s.fingerprint.slice(0, 12)}…
                    </td>
                    <td className="px-3 py-2 text-gray-200">{s.reason}</td>
                    <td className="px-3 py-2 text-gray-400">
                      {s.approvedBy?.username ?? s.approvedById.slice(0, 8) + "…"}
                    </td>
                    <td className="px-3 py-2 text-gray-500">{formatDate(s.createdAt)}</td>
                    <td className="px-3 py-2 text-gray-400">{fmtExpiry(s.expiresAt)}</td>
                    <td className="px-3 py-2">
                      <span className={`inline-flex rounded-full border px-2 py-0.5 text-[10px] ${statusColor}`}>
                        {status}
                      </span>
                    </td>
                    <td className="px-3 py-2 text-right">
                      {status === "Active" && (
                        <Can role="SECURITY">
                          <button
                            type="button"
                            onClick={() => {
                              if (window.confirm(`Revoke suppression for ${s.fingerprint.slice(0, 8)}…? The finding will reappear as OPEN on the next scan.`)) {
                                revoke.mutate(s.id);
                              }
                            }}
                            disabled={revoke.isPending}
                            className="inline-flex items-center gap-1 rounded border border-indigo-900/50 bg-indigo-950/30 px-2 py-1 text-[11px] text-indigo-300 hover:bg-indigo-950/60 disabled:opacity-40"
                          >
                            <X className="h-3 w-3" />
                            Revoke
                          </button>
                        </Can>
                      )}
                    </td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        </div>
      )}

      {!isLoading && rows.length > 0 && (
        <button
          type="button"
          onClick={() => refetch()}
          className="text-xs text-indigo-400 hover:text-indigo-300"
        >
          Refresh
        </button>
      )}
    </div>
  );
}
