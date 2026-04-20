import { useQuery } from "@tanstack/react-query";
import { scansApi } from "../lib/api";
import { useSSE } from "./useSSE";
import type { ScanJob } from "@devsecops/types";

/**
 * Returns the latest scan job for a given target (repo/container/domain ID)
 * and its live status.
 *
 * Status is derived from the server so it survives page navigation.
 * SSE is layered on top for real-time updates while the user is on the page.
 */
export function useTargetScanStatus(targetId: string): {
  latestScan: ScanJob | undefined;
  status: string | null;
  isActive: boolean;
} {
  const { data } = useQuery({
    queryKey: ["scans", "active"],
    queryFn: () => scansApi.list(1, 50),
    // Poll every 3 s while any scan is active; stop when all are done
    refetchInterval: (query) => {
      const d = query.state.data;
      if (!d) return false;
      return d.data.some(
        (s) => s.status === "PENDING" || s.status === "RUNNING"
      )
        ? 3000
        : false;
    },
    staleTime: 2000,
  });

  // Scans are ordered newest-first — first match is the latest scan for this target
  const latestScan = data?.data.find(
    (s) =>
      s.repository?.id === targetId ||
      s.container?.id === targetId ||
      s.domain?.id === targetId
  );

  const isServerActive =
    latestScan?.status === "PENDING" || latestScan?.status === "RUNNING";

  // Layer SSE for real-time updates when the scan is active and the user is on the page
  const { status: sseStatus } = useSSE(isServerActive ? (latestScan?.id ?? null) : null);

  const status = sseStatus ?? latestScan?.status ?? null;
  const isActive = status === "PENDING" || status === "RUNNING";

  return { latestScan, status, isActive };
}
