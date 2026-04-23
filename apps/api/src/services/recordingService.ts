/**
 * Interactive DAST recording orchestration.
 *
 * Lifecycle (per Domain):
 *   1. start()     → create ZAP context via scanner, persist RecordingSession (ACTIVE)
 *   2. status()    → poll scanner for live URL/alert counts (touches lastActivityAt)
 *   3. runScan()   → enqueue DAST_INTERACTIVE ScanJob bound to the recorded context
 *   4. stop()      → tell scanner to remove the ZAP context, mark STOPPED
 *
 * Single-session policy: only one ACTIVE/SCANNING recording per org at a time
 * (ZAP is a shared singleton — concurrent sessions would interleave proxy
 * traffic into each other's contexts).
 */
import axios from "axios";
import prisma from "../db.js";
import { config } from "../config.js";
import { logger } from "../logger.js";
import { triggerScan } from "./scanService.js";

interface StartArgs {
  orgId:    string;
  domainId: string;
  userId:   string;
}

interface StartResult {
  sessionId:    string;
  contextId:    string;
  contextName:  string;
  targetUrl:    string;
  proxyHost:    string;
  proxyPort:    number;
  caUrl:        string;     // proxied through API
  status:       string;
}

const PROXY_HOST = "127.0.0.1";
const PROXY_PORT = 8090;

function scanner(path: string): string {
  return `${config.SCANNER_URL}${path}`;
}

export async function start(args: StartArgs): Promise<StartResult> {
  const { orgId, domainId, userId } = args;

  // Single-session lock — refuse if any ACTIVE/SCANNING session exists in this org.
  const existing = await prisma.recordingSession.findFirst({
    where: { orgId, status: { in: ["ACTIVE", "SCANNING"] } },
  });
  if (existing) {
    const e: Error & { code?: string } = new Error(
      "A recording session is already active. Stop it before starting a new one.",
    );
    e.code = "RECORDING_BUSY";
    throw e;
  }

  const domain = await prisma.domain.findFirst({ where: { id: domainId, orgId } });
  if (!domain) {
    const e: Error & { code?: string } = new Error("Domain not found");
    e.code = "NOT_FOUND";
    throw e;
  }

  // Context name must be unique across ZAP — prefix with org+domain+timestamp.
  const contextName = `rec-${orgId.slice(-6)}-${domainId.slice(-6)}-${Date.now()}`;

  const resp = await axios.post(
    scanner("/dast/recording/start"),
    { domain: domain.domain, contextName },
    { timeout: 30_000 },
  );
  const { contextId, targetUrl } = resp.data as {
    contextId: string; targetUrl: string;
  };

  const session = await prisma.recordingSession.create({
    data: {
      orgId,
      domainId,
      startedById:    userId,
      zapContextId:   String(contextId),
      zapContextName: contextName,
      status:         "ACTIVE",
    },
  });

  logger.info("[recording] started", { sessionId: session.id, domainId, contextName });

  return {
    sessionId:   session.id,
    contextId:   String(contextId),
    contextName,
    targetUrl,
    proxyHost:   PROXY_HOST,
    proxyPort:   PROXY_PORT,
    caUrl:       "/api/domains/_recording/zap-ca.cer",
    status:      session.status,
  };
}

export async function status(orgId: string, domainId: string) {
  const session = await prisma.recordingSession.findFirst({
    where:    { orgId, domainId, status: { in: ["ACTIVE", "SCANNING"] } },
    orderBy:  { startedAt: "desc" },
    include:  { scanJob: { select: { id: true, status: true } } },
  });
  if (!session) return null;

  // Poll scanner for live counts. Resolve targetUrl by re-asking scanner from
  // the domain field — avoids storing/normalizing it twice.
  const domain = await prisma.domain.findUnique({ where: { id: domainId } });
  if (!domain) return null;

  // Probe scheme the same way scanner did at start (cheap)
  const targetUrl = await resolveTargetUrl(domain.domain);

  let urlCount = session.urlCount;
  let alertCount = session.alertCount;
  try {
    const r = await axios.post(
      scanner("/dast/recording/stats"),
      { contextName: session.zapContextName, targetUrl },
      { timeout: 10_000 },
    );
    const liveUrls   = Number(r.data.urlCount   ?? 0);
    const liveAlerts = Number(r.data.alertCount ?? 0);

    // Guard against ZAP returning a transient zero while another scan is
    // hammering it — these endpoints (core/view/urls, numberOfAlerts) can
    // briefly return empty lists under load.  Counters are monotonic within
    // a recording session (ZAP doesn't drop URLs/alerts once captured), so
    // a drop from >0 → 0 is always a read error, never real.  Fall back to
    // the persisted value in that case.
    urlCount   = (liveUrls   === 0 && session.urlCount   > 0) ? session.urlCount   : liveUrls;
    alertCount = (liveAlerts === 0 && session.alertCount > 0) ? session.alertCount : liveAlerts;

    // Persist when the counters move — also bump lastActivityAt for idle timer.
    if (urlCount !== session.urlCount || alertCount !== session.alertCount) {
      await prisma.recordingSession.update({
        where: { id: session.id },
        data:  { urlCount, alertCount, lastActivityAt: new Date() },
      });
    }
  } catch (err) {
    logger.warn("[recording] stats poll failed", {
      sessionId: session.id, error: (err as Error).message,
    });
  }

  return {
    sessionId:      session.id,
    contextId:      session.zapContextId,
    contextName:    session.zapContextName,
    targetUrl,
    proxyHost:      PROXY_HOST,
    proxyPort:      PROXY_PORT,
    caUrl:          "/api/domains/_recording/zap-ca.cer",
    status:         session.status,
    urlCount,
    alertCount,
    startedAt:      session.startedAt,
    lastActivityAt: session.lastActivityAt,
    scanJobId:      session.scanJobId,
    scanJobStatus:  session.scanJob?.status ?? null,
  };
}

export async function runScan(orgId: string, domainId: string) {
  const session = await prisma.recordingSession.findFirst({
    where:   { orgId, domainId, status: "ACTIVE" },
    orderBy: { startedAt: "desc" },
  });
  if (!session) {
    const e: Error & { code?: string } = new Error("No active recording session for this domain");
    e.code = "NO_SESSION";
    throw e;
  }

  const domain = await prisma.domain.findUniqueOrThrow({
    where: { id: domainId },
    include: { authConfig: true },
  });
  const targetUrl = await resolveTargetUrl(domain.domain);

  const result = await triggerScan({
    orgId,
    targetType:  "DOMAIN",
    targetId:    domainId,
    scanTypes:   ["DAST_INTERACTIVE"],
    domain:      domain.domain,
    domainAuthConfigId:   domain.authConfig?.id,
    recordingContextId:   session.zapContextId,
    recordingContextName: session.zapContextName,
    recordingTargetUrl:   targetUrl,
    recordingSessionId:   session.id,
  });

  await prisma.recordingSession.update({
    where: { id: session.id },
    data:  { status: "SCANNING", scanJobId: result.scanJobId },
  });

  logger.info("[recording] scan triggered", {
    sessionId: session.id, scanJobId: result.scanJobId,
  });
  return result;
}

export async function stop(orgId: string, domainId: string) {
  const session = await prisma.recordingSession.findFirst({
    where:   { orgId, domainId, status: { in: ["ACTIVE", "SCANNING"] } },
    orderBy: { startedAt: "desc" },
  });
  if (!session) return { ok: true, alreadyStopped: true };

  try {
    await axios.post(
      scanner("/dast/recording/stop"),
      { contextName: session.zapContextName },
      { timeout: 10_000 },
    );
  } catch (err) {
    // Non-fatal: maybe ZAP already lost it. Mark STOPPED anyway so UI clears.
    logger.warn("[recording] scanner stop failed", {
      sessionId: session.id, error: (err as Error).message,
    });
  }

  await prisma.recordingSession.update({
    where: { id: session.id },
    data:  { status: "STOPPED", endedAt: new Date() },
  });
  logger.info("[recording] stopped", { sessionId: session.id });
  return { ok: true };
}

/**
 * Stream ZAP's CA root cert through the API so the user's browser sees it
 * coming from our origin (the scanner is internal and not reachable directly).
 */
export async function fetchZapCaBytes(): Promise<Buffer> {
  const r = await axios.get(scanner("/dast/recording/zap-ca"), { timeout: 5_000 });
  const url = (r.data as { caUrl: string }).caUrl;
  const cert = await axios.get<ArrayBuffer>(url, {
    responseType: "arraybuffer",
    timeout:      10_000,
  });
  return Buffer.from(cert.data);
}

// ── helpers ────────────────────────────────────────────────────────────────

// ── Idle sweeper ───────────────────────────────────────────────────────────
//
// ZAP holds context state in memory. If a user starts a recording and walks
// away, the context lingers and the per-org single-session lock prevents new
// sessions until they explicitly Stop. Sweep ACTIVE sessions on two rules:
//   • lastActivityAt older than 60 min (no proxy traffic recently)
//   • startedAt       older than  4 hr (hard cap regardless of activity)
const IDLE_MINUTES   = 60;
const HARD_CAP_HOURS = 4;
const SWEEP_INTERVAL_MS = 5 * 60 * 1000;

let sweeperHandle: NodeJS.Timeout | null = null;

export function startRecordingIdleSweeper(): void {
  if (sweeperHandle) return; // idempotent
  sweeperHandle = setInterval(() => { void sweepIdleSessions(); }, SWEEP_INTERVAL_MS);
  // Run once immediately on boot so post-restart stale rows are cleaned up.
  void sweepIdleSessions();
  logger.info("[recording] idle sweeper started", {
    idleMinutes: IDLE_MINUTES, hardCapHours: HARD_CAP_HOURS,
  });
}

async function sweepIdleSessions(): Promise<void> {
  const idleCutoff    = new Date(Date.now() - IDLE_MINUTES   * 60 * 1000);
  const hardCapCutoff = new Date(Date.now() - HARD_CAP_HOURS * 60 * 60 * 1000);

  const stale = await prisma.recordingSession.findMany({
    where: {
      status: "ACTIVE",  // never auto-stop SCANNING — let the scan finish
      OR: [
        { lastActivityAt: { lt: idleCutoff } },
        { startedAt:      { lt: hardCapCutoff } },
      ],
    },
  });
  if (stale.length === 0) return;

  for (const s of stale) {
    try {
      await axios.post(
        scanner("/dast/recording/stop"),
        { contextName: s.zapContextName },
        { timeout: 10_000 },
      );
    } catch {
      // non-fatal; mark STOPPED below regardless
    }
    await prisma.recordingSession.update({
      where: { id: s.id },
      data:  { status: "STOPPED", endedAt: new Date(), errorMessage: "Auto-stopped (idle)" },
    });
    logger.info("[recording] auto-stopped idle session", {
      sessionId: s.id, lastActivityAt: s.lastActivityAt, startedAt: s.startedAt,
    });
  }
}

/** Probe https→http; mirrors the scanner's resolution logic. */
async function resolveTargetUrl(domain: string): Promise<string> {
  for (const scheme of ["https", "http"]) {
    try {
      const r = await axios.get(`${scheme}://${domain}`, {
        timeout: 5_000,
        validateStatus: () => true,
      });
      if (r.status < 500) return `${scheme}://${domain}`;
    } catch {
      // try next scheme
    }
  }
  return `http://${domain}`;
}
