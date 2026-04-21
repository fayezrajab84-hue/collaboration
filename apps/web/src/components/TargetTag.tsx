import { GitBranch, Box, Globe } from "lucide-react";
import type { Finding } from "@devsecops/types";

/**
 * Coloured tag showing which target (repository / container / domain) a
 * finding belongs to.  Used on the Findings page, the Dashboard recent
 * findings table, and anywhere else a Finding is listed outside its
 * target-specific view.
 *
 * `maxWidth` controls the max-width of the truncated label so different
 * densities (wide Findings table vs compact Dashboard card) look right.
 */
export default function TargetTag({
  finding,
  maxWidth = "max-w-[160px]",
}: {
  finding: Finding;
  maxWidth?: string;
}) {
  if (finding.repository) {
    return (
      <span className={`inline-flex items-center gap-1 rounded bg-indigo-900/50 px-2 py-0.5 text-xs text-indigo-300 ${maxWidth} truncate`}>
        <GitBranch className="h-3 w-3 shrink-0" />
        <span className="truncate">{finding.repository.fullName}</span>
      </span>
    );
  }
  if (finding.container) {
    return (
      <span className={`inline-flex items-center gap-1 rounded bg-cyan-900/50 px-2 py-0.5 text-xs text-cyan-300 ${maxWidth} truncate`}>
        <Box className="h-3 w-3 shrink-0" />
        <span className="truncate">{finding.container.imageRef}</span>
      </span>
    );
  }
  if (finding.domain) {
    return (
      <span className={`inline-flex items-center gap-1 rounded bg-emerald-900/50 px-2 py-0.5 text-xs text-emerald-300 ${maxWidth} truncate`}>
        <Globe className="h-3 w-3 shrink-0" />
        <span className="truncate">{finding.domain.domain}</span>
      </span>
    );
  }
  return <span className="text-gray-600">—</span>;
}
