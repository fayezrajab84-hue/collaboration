import type { Response } from "express";
import type { ScanStatus } from "@devsecops/types";

interface SseClient {
  res: Response;
  scanJobId: string;
}

// In-memory SSE registry (single-instance only; post-MVP: use Redis pub/sub)
const clients = new Map<string, Set<Response>>();

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
}

export function emitFindingsBatch(
  scanJobId: string,
  scanType: string,
  count: number,
  severityBreakdown: Record<string, number>
): void {
  emit(scanJobId, { type: "FINDINGS_BATCH", scanType, count, severityBreakdown });
}
