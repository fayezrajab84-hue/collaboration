import { Lock } from "lucide-react";
import type { CheckDefinition, CheckSeverity } from "../data/checks";
import { SEVERITY_RING, ROW_HOVER } from "../lib/colors";

function SeverityDot({ severity }: { severity: CheckSeverity }) {
  const s = SEVERITY_RING[severity] ?? SEVERITY_RING["INFO"];
  return (
    <span className={`inline-flex items-center gap-1.5 rounded-full px-2 py-0.5 text-xs font-medium ring-1 ${s.badge}`}>
      <span className={`h-1.5 w-1.5 rounded-full ${s.dot}`} />
      {s.label}
    </span>
  );
}

interface Props {
  checks: CheckDefinition[];
  emptyMessage?: string;
}

export default function ChecksTab({ checks, emptyMessage }: Props) {
  if (checks.length === 0) {
    return (
      <div className="flex h-48 items-center justify-center text-gray-500 text-sm">
        {emptyMessage ?? "No checks defined."}
      </div>
    );
  }

  return (
    <div className="overflow-x-auto rounded-lg border border-gray-800">
      <table className="w-full text-sm">
        <thead className="border-b border-gray-800 bg-gray-900">
          <tr className="text-left text-xs text-gray-500">
            <th className="px-4 py-3 font-medium w-36">Severity</th>
            <th className="px-4 py-3 font-medium">Check</th>
            <th className="px-4 py-3 font-medium hidden lg:table-cell">Description</th>
          </tr>
        </thead>
        <tbody className="divide-y divide-gray-800 bg-gray-900/50">
          {checks.map((check) => (
            <tr key={check.id} className={ROW_HOVER}>
              {/* Severity */}
              <td className="px-4 py-4 align-top">
                <SeverityDot severity={check.severity} />
              </td>

              {/* Check name + mobile description */}
              <td className="px-4 py-4 align-top">
                <div className="flex flex-col gap-1">
                  <div className="flex items-center gap-2 flex-wrap">
                    <span className="font-medium text-gray-200">{check.name}</span>
                    {check.authenticatedOnly && (
                      <span className="inline-flex items-center gap-1 rounded bg-gray-800 px-1.5 py-0.5 text-xs text-gray-500 ring-1 ring-gray-700">
                        <Lock className="h-2.5 w-2.5" />
                        Authenticated only
                      </span>
                    )}
                    {check.scanner && (
                      <span className="rounded bg-indigo-950/50 px-1.5 py-0.5 text-xs text-indigo-400 ring-1 ring-indigo-900/60">
                        {check.scanner}
                      </span>
                    )}
                  </div>
                  {/* Description visible on small screens inline */}
                  <p className="text-xs text-gray-500 leading-relaxed lg:hidden">{check.description}</p>
                </div>
              </td>

              {/* Description — hidden on small screens, shown on lg+ */}
              <td className="px-4 py-4 align-top hidden lg:table-cell">
                <p className="text-xs text-gray-500 leading-relaxed max-w-xl">{check.description}</p>
              </td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}
