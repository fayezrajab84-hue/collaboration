/**
 * scanProvenance — small helpers that describe HOW a ScanJob was dispatched.
 *
 * Provenance (recording-driven vs crawl-driven) used to be baked into the
 * ScanType enum via a dedicated `DAST_INTERACTIVE` value. That conflated two
 * orthogonal axes — *what* the scanner does, and *where* the URL seed list
 * came from — making downstream rules, dashboards, and merging logic branch
 * on both. We now store provenance as an attribute of the ScanJob
 * (`recordingSessionId`) and read it through these helpers.
 *
 * Rule of thumb: if a caller wants to know "what engines ran?" it should
 * look at `scanType`. If it wants to know "was this kicked off from a
 * recorded browser session?" it should call `isInteractiveScan()`.
 */

export interface ScanProvenanceFields {
  recordingSessionId: string | null;
  scanType?: string;      // optional — only used by label helpers
  scanTypes?: string[];   // some callers pass ScanJob with the scanTypes array
}

/**
 * True when the ScanJob was started from a user-recorded ZAP proxy session.
 * Works for both DAST (runScan) and PENTEST_FULL (promote) interactive
 * flows — both stash `recordingSessionId` on the ScanJob row.
 */
export function isInteractiveScan(job: ScanProvenanceFields | null | undefined): boolean {
  return Boolean(job?.recordingSessionId);
}

/**
 * Human-friendly label for UIs that want to surface the provenance alongside
 * the scan type. Returns e.g. "DAST (Interactive)", "Pentest (Interactive)",
 * or just "DAST" / "Pentest" for crawl-driven runs.
 */
export function scanTypeLabel(job: ScanProvenanceFields): string {
  const type   = job.scanType ?? job.scanTypes?.[0] ?? "";
  const pretty =
    type === "DAST"         ? "DAST" :
    type === "PENTEST_FULL" ? "Pentest" :
    type === "PENTEST"      ? "Pentest" :
    type;
  return isInteractiveScan(job) ? `${pretty} (Interactive)` : pretty;
}
