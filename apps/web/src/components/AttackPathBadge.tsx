/**
 * AttackPathBadge — Phase 27 Slice C.
 *
 * Surfaces on a Finding row when it's part of a chained attack path. Click
 * navigates to /attack-paths/:groupId. Honest UI: only renders when the
 * finding actually has correlationGroupId — a missing badge means the
 * correlation engine hasn't grouped this finding yet (or it's standalone).
 */
import { Link } from "react-router-dom";
import { Network } from "lucide-react";

interface AttackPathBadgeProps {
  /** The finding's correlationGroupId. Falsy = badge hidden. */
  groupId:    string | null | undefined;
  /** Number of nodes in the chain — drives the "N hops" suffix. */
  pathLength: number | null | undefined;
  /** True when any node in the chain has confidence=CONFIRMED. */
  confirmed?: boolean;
}

export default function AttackPathBadge({ groupId, pathLength, confirmed }: AttackPathBadgeProps) {
  if (!groupId || !pathLength || pathLength < 2) return null;
  return (
    <Link
      to={`/attack-paths/${encodeURIComponent(groupId)}`}
      title={confirmed ? "Confirmed exploitation observed in this chain" : "Part of a correlated attack path"}
      className={
        "inline-flex items-center gap-1 rounded-full border px-2 py-0.5 text-[10px] font-medium transition-colors " +
        (confirmed
          ? "border-red-700 bg-red-950/30 text-red-300 hover:border-red-500"
          : "border-indigo-800 bg-indigo-950/30 text-indigo-300 hover:border-indigo-500")
      }
    >
      <Network className="h-3 w-3" />
      Attack path · {pathLength} hops
    </Link>
  );
}
