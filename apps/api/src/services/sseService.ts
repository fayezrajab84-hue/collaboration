import type { Response } from "express";
import type { ScanStatus } from "@devsecops/types";

interface SseClient {
  res: Response;
  scanJobId: string;
}

// In-memory SSE registry (single-instance only; post-MVP: use Redis pub/sub)
const clients = new Map<string, Set<Response>>();

// Latest known phase/pct per scan, kept so a fresh page load (or an SSE
// reconnect after a drop) can hydrate the progress bar immediately instead
// of staring at "Scanning…" until the *next* progress event fires. Phases
// like Nuclei sit silent for ~25 min, so without this the UI looked dead.
// Cleared when the scan reaches a terminal status; an API restart wipes it,
// in which case the UI just falls back to the coarse `completedScans/total`
// counter until the next emit. Acceptable trade-off vs. a DB migration.
const latestProgress = new Map<string, { phase: string; pct: number; ts: number }>();

export function setLatestProgress(scanJobId: string, phase: string, pct: number): void {
  latestProgress.set(scanJobId, { phase, pct, ts: Date.now() });
}

export function getLatestProgress(
  scanJobId: string,
): { phase: string; pct: number; ts: number } | null {
  return latestProgress.get(scanJobId) ?? null;
}

export function clearLatestProgress(scanJobId: string): void {
  latestProgress.delete(scanJobId);
}

export function addClient(scanJobId: string, res: Response): void {
  if (!clients.has(scanJobId)) {
    clients.set(scanJobId, new Set());
  }
  clients.get(scanJobId)!.add(res);
}

export function removeClient(scanJobId: string, res: Response): void {
  const set = clients.get(scanJobId);
  if (set) {
    set.delete(res);
    if (set.size === 0) clients.delete(scanJobId);
  }
}

export function emit(scanJobId: string, event: Record<string, unknown>): void {
  const set = clients.get(scanJobId);
  if (!set || set.size === 0) return;
  const payload = `data: ${JSON.stringify({ ...event, scanJobId, timestamp: new Date().toISOString() })}\n\n`;
  for (const res of set) {
    try {
      res.write(payload);
    } catch {
      set.delete(res);
    }
  }
}

export function emitStatusChange(scanJobId: string, status: ScanStatus, extra?: Record<string, unknown>): void {
  emit(scanJobId, { type: "STATUS_CHANGE", status, ...extra });
  // A terminal status means progress is done — drop the cache so the in-memory
  // map doesn't grow unbounded across the lifetime of the API process.
  if (status === "COMPLETED" || status === "FAILED" || status === "CANCELLED") {
    clearLatestProgress(scanJobId);
  }
}

export function emitFindingsBatch(
  scanJobId: string,
  scanType: string,
  count: number,
  severityBreakdown: Record<string, number>
): void {
  emit(scanJobId, { type: "FINDINGS_BATCH", scanType, count, severityBreakdown });
}
