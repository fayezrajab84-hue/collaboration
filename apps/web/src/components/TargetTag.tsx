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
// Unified target-type tag — neutral gray body. Repo and container icons keep
// their slate/blue tints (they're the dominant target types and the colour
// helps scan a long list); the domain icon uses gray-300 (light silver) so
// web targets match the same Globe shade used everywhere else (dashboard
// tabs, stats cards, recent scans, top targets).
export default function TargetTag({
  finding,
  maxWidth = "max-w-[160px]",
}: {
  finding: Finding;
  maxWidth?: string;
}) {
  const chip = `inline-flex items-center gap-1 rounded bg-gray-800/80 border border-gray-700/60 px-2 py-0.5 text-xs text-gray-300 ${maxWidth} truncate`;

  if (finding.repository) {
    return (
      <span className={chip}>
        <GitBranch className="h-3 w-3 shrink-0 text-slate-400" />
        <span className="truncate">{finding.repository.fullName}</span>
      </span>
    );
  }
  if (finding.container) {
    return (
      <span className={chip}>
        <Box className="h-3 w-3 shrink-0 text-blue-400" />
        <span className="truncate">{finding.container.imageRef}</span>
      </span>
    );
  }
  if (finding.domain) {
    return (
      <span className={chip}>
        <Globe className="h-3 w-3 shrink-0 text-gray-300" />
        <span className="truncate">{finding.domain.domain}</span>
      </span>
    );
  }
  return <span className="text-gray-600">—</span>;
}
