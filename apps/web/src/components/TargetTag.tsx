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
// Unified target-type tag — neutral gray body, type distinguished by a small
// icon tinted from a harmonious cool-family palette (slate / blue / teal).
// Previously indigo/cyan/emerald all competed with each other and with the
// primary indigo action accent elsewhere.
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
        <Globe className="h-3 w-3 shrink-0 text-teal-400" />
        <span className="truncate">{finding.domain.domain}</span>
      </span>
    );
  }
  return <span className="text-gray-600">—</span>;
}
