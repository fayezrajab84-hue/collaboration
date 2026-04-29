import { Router } from "express";
import { requireAuth } from "../../middleware/requireAuth.js";
import prisma from "../../db.js";
import { getActiveMembership } from "../../services/activeOrgService.js";
import { addClient, removeClient, emitStatusChange, emit, setLatestProgress, getLatestProgress } from "../../services/sseService.js";
import { scanQueues } from "../../queues/definitions.js";
import { generateScanSummary } from "../../services/scanSummaryService.js";
import * as audit from "../../services/auditService.js";
import type { ScanType } from "@devsecops/types";

const router = Router();

// ── Internal phase-progress callback (no user auth — scanner calls this over internal network)
router.post("/:id/progress", async (req, res) => {
  const { pct, phase } = req.body as { pct?: number; phase?: string };
  if (typeof pct === "number") {
    const clampedPct = Math.min(100, Math.max(0, Math.round(pct)));
    const phaseName  = phase ?? "scanning";
    // Persist last-known progress so a fresh page load (or SSE reconnect)
    // can hydrate the bar without waiting for the next phase boundary.
    setLatestProgress(req.params["id"]!, phaseName, clampedPct);
    emit(req.params["id"], {
      type: "PHASE_PROGRESS",
      phase: phaseName,
      pct: clampedPct,
    });
  }
  res.json({ ok: true });
});

// ── Crawler-progress callback (Phase 5) ──────────────────────────────────────
// The Playwright crawler sidecar posts live crawl stats here during a DAST
// scan's pre-crawl phase. The API fans them out over the existing SSE stream
// so the frontend can show "pages crawled: 42, XHR found: 19, current URL…"
// without polling.
router.post("/:id/crawler-progress", async (req, res) => {
  const b = req.body as {
    pages_visited?: number;
    pages_queued?: number;
    xhr_observed?: number;
    forms_found?: number;
    current_url?: string | null;
    elapsed_secs?: number;
  };
  emit(req.params["id"], {
    type: "CRAWLER_PROGRESS",
    pagesVisited: Math.max(0, b.pages_visited ?? 0),
    pagesQueued:  Math.max(0, b.pages_queued ?? 0),
    xhrObserved:  Math.max(0, b.xhr_observed ?? 0),
    formsFound:   Math.max(0, b.forms_found ?? 0),
    currentUrl:   b.current_url ?? null,
    elapsedSecs:  b.elapsed_secs ?? 0,
  });
  res.json({ ok: true });
});

router.use(requireAuth);

// ── Phase A7 — repo-id-less scan trigger from CI workflow context ─────────
//
// POST /api/scans/from-github
//   Body: { githubFullName, commitSha?, branch?, prNumber?, scanTypes? }
//
// The "Snyk-shape" workflow: the CI runner has the GitHub repo full
// name in `${{ github.repository }}` and doesn't need to know about
// BreachLens-side repo IDs. The Action just sends the GitHub context;
// BreachLens auto-discovers the Repository row (creating it on first
// call) and triggers a scan.
//
// Auto-discovery rules:
//   1. Look up Repository by (orgId, fullName). Fast path for re-scans.
//   2. If absent, fetch metadata from GitHub (verifies the calling
//      user has access AND gives us the numeric githubId we need).
//   3. Create the Repository row + return.
//
// Auth model:
//   - Requires Bearer token with scope `scans:trigger` (enforced by
//     requireScope below). Sessions also work — useful for the UI but
//     CI uses Bearer.
//   - The token's creator must have stored GitHub OAuth credentials
//     (any user who's logged into BreachLens via GitHub OAuth at
//     least once has them). For private-repo discovery, that user
//     must have access to the target repo.
router.post("/from-github", async (req, res, next) => {
  try {
    const { z } = await import("zod");
    const body = z.object({
      githubFullName: z.string().regex(/^[\w.-]+\/[\w.-]+$/, "Must be 'owner/repo' format"),
      commitSha:      z.string().min(1).optional(),
      branch:         z.string().min(1).optional(),
      prNumber:       z.number().int().nonnegative().optional(),
      scanTypes:      z.array(z.string()).min(1).optional(),
    }).parse(req.body);

    const user = req.user as { id: string };
    const member = await getActiveMembership(req);
    if (!member) { res.status(403).json({ error: "No active org for this token" }); return; }

    // Scope check for Bearer-authed requests (sessions bypass).
    if ((req as { apiToken?: { scopes: string[] } }).apiToken) {
      const tok = (req as { apiToken: { scopes: string[] } }).apiToken;
      if (!tok.scopes.includes("scans:trigger")) {
        res.status(403).json({
          error: "API token missing required scope",
          required: "scans:trigger",
          granted:  tok.scopes,
        });
        return;
      }
    }

    const { findOrCreateRepository } = await import("../../services/repoAutoDiscoveryService.js");
    const discovered = await findOrCreateRepository({
      orgId:          member.orgId,
      userId:         user.id,
      githubFullName: body.githubFullName,
    });

    const dbUser = await prisma.user.findUnique({
      where:  { id: user.id },
      select: { accessToken: true },
    });
    if (!dbUser?.accessToken) {
      res.status(400).json({
        error: "Token owner has no stored GitHub OAuth credentials",
        detail: "Operator must log into BreachLens via GitHub OAuth before minting an API token for CI.",
      });
      return;
    }

    const defaultScanTypes: ScanType[] = ["SAST", "SCA", "SECRET", "IAC"];
    const scanTypes = (body.scanTypes as ScanType[] | undefined) ?? defaultScanTypes;

    const { triggerScan } = await import("../../services/scanService.js");
    const result = await triggerScan({
      orgId:             member.orgId,
      targetType:        "REPOSITORY",
      targetId:          discovered.repository.id,
      scanTypes,
      repoUrl:           `https://github.com/${discovered.repository.fullName}`,
      branch:            body.branch ?? discovered.repository.defaultBranch,
      encryptedGitToken: dbUser.accessToken,
      // CI context — surfaces in /scans UI as "PR #N" / "commit abc" tags
      triggerType:       body.prNumber != null ? "PULL_REQUEST" : "PUSH",
      commitSha:         body.commitSha,
      prNumber:          body.prNumber,
    });

    res.status(202).json({
      ...result,
      repository: {
        id:           discovered.repository.id,
        fullName:     discovered.repository.fullName,
        newlyCreated: discovered.newlyCreated,
      },
    });
  } catch (err) { next(err); }
});

// List scan jobs
router.get("/", async (req, res, next) => {
  try {
    const user = req.user as { id: string };
    const member = await getActiveMembership(req);
    if (!member) { res.json({ data: [], total: 0 }); return; }

    const page = Math.max(1, parseInt(req.query["page"] as string || "1"));
    const limit = Math.min(50, parseInt(req.query["limit"] as string || "20"));
    const skip = (page - 1) * limit;

    const [data, total] = await Promise.all([
      prisma.scanJob.findMany({
        where: { orgId: member.orgId },
        orderBy: { createdAt: "desc" },
        skip,
        take: limit,
        include: {
          repository: { select: { id: true, fullName: true } },
          container:  { select: { id: true, imageRef: true } },
          domain:     { select: { id: true, domain: true } },
        },
      }),
      prisma.scanJob.count({ where: { orgId: member.orgId } }),
    ]);

    // Hydrate active scans with the API's in-memory phase progress so each
    // row's <ScanProgressBar/> can render the live label/% on first paint
    // (otherwise a page reload mid-scan shows "Scanning…" until the next
    // emit, which during Nuclei is up to 25 minutes away).
    const dataWithProgress = data.map((scan) => {
      if (scan.status !== "RUNNING" && scan.status !== "PENDING") return scan;
      const live = getLatestProgress(scan.id);
      return {
        ...scan,
        currentPhase:    live?.phase ?? null,
        currentPhasePct: live?.pct   ?? null,
      };
    });

    res.json({ data: dataWithProgress, total, page, limit, totalPages: Math.ceil(total / limit) });
  } catch (err) { next(err); }
});

// Get scan job
router.get("/:id", async (req, res, next) => {
  try {
    const user = req.user as { id: string };
    const member = await getActiveMembership(req);
    const scan = await prisma.scanJob.findFirst({
      where: { id: req.params["id"], orgId: member?.orgId },
      include: {
        repository: { select: { fullName: true } },
        container:  { select: { imageRef: true } },
        domain:     { select: { domain: true } },
      },
    });
    if (!scan) { res.status(404).json({ error: "Scan job not found" }); return; }

    // Attach computed "confirmed" count — findings that existed before this
    // scan ran AND were re-observed in it.  Computed on the fly to avoid a
    // schema migration; the fact that upsertFindings bumps `lastSeen` inside
    // the scan's time window is our truth source.
    // "New"       = firstSeen between startedAt and completedAt
    // "Confirmed" = firstSeen < startedAt, lastSeen >= startedAt
    const scanTargetFilter =
      scan.targetType === "REPOSITORY" ? { repositoryId: scan.repositoryId }
      : scan.targetType === "CONTAINER" ? { containerId: scan.containerId }
      : { domainId: scan.domainId };

    let confirmedCount = 0;
    let newThisScan   = 0;
    if (scan.startedAt) {
      const windowEnd = scan.completedAt ?? new Date();
      [confirmedCount, newThisScan] = await Promise.all([
        prisma.finding.count({
          where: {
            orgId:    scan.orgId,
            scanType: { in: scan.scanTypes },
            ...scanTargetFilter,
            firstSeen: { lt: scan.startedAt },
            lastSeen:  { gte: scan.startedAt, lte: windowEnd },
          },
        }),
        prisma.finding.count({
          where: {
            orgId:    scan.orgId,
            scanType: { in: scan.scanTypes },
            ...scanTargetFilter,
            firstSeen: { gte: scan.startedAt, lte: windowEnd },
          },
        }),
      ]);
    }

    // Attach last-known phase progress so the UI can hydrate the progress bar
    // on a fresh page load — phase emits sit silent for ~25 min during Nuclei,
    // and without this the frontend fell back to "Scanning…" with no %.
    const liveProgress = getLatestProgress(scan.id);
    res.json({
      ...scan,
      confirmedCount,
      newThisScan,
      currentPhase:    liveProgress?.phase ?? null,
      currentPhasePct: liveProgress?.pct   ?? null,
    });
  } catch (err) { next(err); }
});

// ── SARIF 2.1.0 export — Phase A1 CI integration ───────────────────────────
// GET /api/scans/:id/export.sarif → SARIF 2.1.0 JSON for the scan's findings.
//
// Drop-in for GitHub Code Scanning, GitLab, Bitbucket, Azure DevOps. CI
// pipelines fetch this after a scan completes and either upload it to
// the platform's security tab OR exit non-zero based on the severity
// distribution.
//
// Output is the FULL set of findings on the scan's target — not just
// the ones discovered in this specific scan. Reasoning: a CI pipeline
// asking "what's the security state of this commit?" wants the
// complete picture (including findings discovered in earlier scans
// that are still present). To get only the new-this-scan slice, use
// the existing GET /:id/diff endpoint.
//
// Auth: same session-cookie auth as the rest of /api/scans. CI pipelines
// supply a long-lived session cookie via env var. Proper API tokens
// land in Phase A2 (CLI session).
router.get("/:id/export.sarif", async (req, res, next) => {
  try {
    const member = await getActiveMembership(req);
    if (!member) { res.status(404).json({ error: "Scan job not found" }); return; }

    const scan = await prisma.scanJob.findFirst({
      where: { id: req.params["id"], orgId: member.orgId },
    });
    if (!scan) { res.status(404).json({ error: "Scan job not found" }); return; }

    // Same target-scoping pattern the GET /:id handler uses — pull all
    // findings on the scan's target across the scanTypes that ran.
    const targetFilter =
      scan.targetType === "REPOSITORY" ? { repositoryId: scan.repositoryId }
      : scan.targetType === "CONTAINER" ? { containerId:  scan.containerId  }
      : { domainId: scan.domainId };

    const findings = await prisma.finding.findMany({
      where: {
        orgId:    scan.orgId,
        scanType: { in: scan.scanTypes },
        status:   { not: "FALSE_POSITIVE" },
        ...targetFilter,
      },
    });

    const { findingsToSarif } = await import("../../services/sarifExport.js");
    const { config } = await import("../../config.js");
    const sarif = findingsToSarif(findings, {
      scan,
      apiBaseUrl: config.FRONTEND_URL ?? "http://localhost:5173",
    });

    // The official MIME type is application/sarif+json. GitHub Code
    // Scanning's uploader tolerates either application/sarif+json or
    // application/json; we send the official one for spec correctness.
    res.setHeader("Content-Type", "application/sarif+json");
    res.setHeader(
      "Content-Disposition",
      `attachment; filename="breachlens-scan-${scan.id}.sarif"`,
    );
    res.json(sarif);
  } catch (err) { next(err); }
});

// ── Diff two scans of the same target ────────────────────────────────────────
// GET /scans/:id/diff            → compare against the immediately-previous
//                                    COMPLETED scan of the same target
// GET /scans/:id/diff?compareTo=X → compare against a specific scan
//
// "Added"    = fingerprints observed in B but not A (firstSeen > A.completedAt)
// "Removed"  = fingerprints observed in A but not B (lastSeen  < B.startedAt)
// "Unchanged"= fingerprints in both windows
//
// IMPORTANT — scan-type scoping:
//   The diff is computed only over scanTypes that ran AND succeeded in BOTH
//   scans. Without this, comparing a SAST-only scan to a SAST+DAST scan would
//   make every DAST finding look "added" or "removed". And a failed sub-scan
//   produces zero findings — without filtering, the prior run's findings
//   would all look "removed/fixed" (which is what triggered the bogus
//   auto-fix display the user saw on scan cypa35pcbh2b).
router.get("/:id/diff", async (req, res, next) => {
  try {
    const user = req.user as { id: string };
    const member = await getActiveMembership(req);
    if (!member) { res.status(403).json({ error: "Forbidden" }); return; }

    const scanB = await prisma.scanJob.findFirst({
      where: { id: req.params["id"], orgId: member.orgId },
    });
    if (!scanB) { res.status(404).json({ error: "Scan not found" }); return; }
    if (!scanB.startedAt) { res.status(409).json({ error: "Scan has not started" }); return; }

    // Diffing a fully-failed scan is meaningless: every comparison reduces to
    // "B has no findings → everything in A looks removed". Bail with a clear
    // reason so the UI can show "no comparison available" instead of a
    // misleading "11 findings removed/fixed" panel.
    if (scanB.status === "FAILED") {
      res.json({
        scanA: null,
        scanB: {
          id: scanB.id,
          startedAt: scanB.startedAt,
          completedAt: scanB.completedAt,
          scanTypes: scanB.scanTypes,
          status: scanB.status,
          failedScanTypes: scanB.failedScanTypes,
        },
        added: [],
        removed: [],
        unchangedCount: 0,
        reason: "Cannot diff against a failed scan — no findings were collected.",
      });
      return;
    }

    // Resolve scanA — either the explicit ?compareTo or the previous scan of the
    // same target. Must share targetType + targetId and be COMPLETED before B started.
    const targetMatch =
      scanB.targetType === "REPOSITORY" ? { repositoryId: scanB.repositoryId }
      : scanB.targetType === "CONTAINER" ? { containerId:  scanB.containerId }
      : { domainId: scanB.domainId };

    // PENTEST and PENTEST_FULL are aliases — the latter superseded the former
    // during a refactor, but old ScanJob/Finding rows still carry "PENTEST".
    // Normalize to a canonical symbol so a {PENTEST_FULL} scan can be diffed
    // against an older {PENTEST} run on the same target without the strict
    // intersection collapsing to ∅. Add new aliases here when scan types
    // get renamed in the future.
    const normalizeType = (t: string): string =>
      t === "PENTEST" ? "PENTEST_FULL" : t;
    // Reverse mapping for the DB query — when "PENTEST_FULL" survives the
    // intersection, look up findings written under either label so the
    // legacy/canonical boundary doesn't drop rows. Anything not aliased
    // returns just itself.
    const expandType = (t: string): string[] =>
      t === "PENTEST_FULL" ? ["PENTEST", "PENTEST_FULL"] : [t];

    const normalizedB = new Set(scanB.scanTypes.map(normalizeType));

    const compareToId = req.query["compareTo"] as string | undefined;
    let scanA;
    if (compareToId) {
      scanA = await prisma.scanJob.findFirst({
        where: { id: compareToId, orgId: member.orgId, ...targetMatch },
      });
    } else {
      // Auto-pick: prefer the most recent COMPLETED scan that shares at least
      // one normalized scan type with scanB. The naive "previous COMPLETED"
      // pick used to land on a chronologically-prior run with no overlap
      // (e.g. a DAST-only scan before a PENTEST_FULL one), which then bailed
      // with "no shared scan types" even though an older comparable run
      // existed earlier in history. Cap the lookback so we don't scan the
      // entire scan history for a target that's been around forever.
      const candidates = await prisma.scanJob.findMany({
        where: {
          orgId: member.orgId,
          id: { not: scanB.id },
          status: "COMPLETED",
          completedAt: { lt: scanB.startedAt, not: null },
          ...targetMatch,
        },
        orderBy: { completedAt: "desc" },
        take: 20,
      });
      scanA =
        candidates.find((c) =>
          c.scanTypes.some((t) => normalizedB.has(normalizeType(t))),
        ) ?? candidates[0] ?? null;
    }
    if (!scanA || !scanA.startedAt || !scanA.completedAt) {
      res.status(404).json({ error: "No earlier scan available to compare against" });
      return;
    }

    const windowEndB = scanB.completedAt ?? new Date();

    // Effective scan types = (A.scanTypes ∩ B.scanTypes) − (A.failed ∪ B.failed),
    // computed in the *normalized* space so PENTEST↔PENTEST_FULL collapses
    // to one symbol. A failed sub-scan returns zero findings, so including
    // its type in the diff would falsely classify all of the OTHER scan's
    // findings of that type as "removed". Same logic for non-overlap: a
    // SAST scan can't say anything about DAST findings.
    const failedUnion = new Set<string>([
      ...scanA.failedScanTypes.map(normalizeType),
      ...scanB.failedScanTypes.map(normalizeType),
    ]);
    const sharedNormalized = [
      ...new Set(
        scanA.scanTypes
          .map(normalizeType)
          .filter((t) => normalizedB.has(t)),
      ),
    ];
    const effectiveTypes = sharedNormalized.filter((t) => !failedUnion.has(t));
    // Expand back to concrete DB enum values for the Finding query — the
    // canonical symbol may map to multiple stored labels (PENTEST_FULL →
    // ["PENTEST", "PENTEST_FULL"]).
    const dbScanTypes = [...new Set(effectiveTypes.flatMap(expandType))];

    if (effectiveTypes.length === 0) {
      res.json({
        scanA: {
          id: scanA.id, startedAt: scanA.startedAt, completedAt: scanA.completedAt,
          scanTypes: scanA.scanTypes, failedScanTypes: scanA.failedScanTypes,
        },
        scanB: {
          id: scanB.id, startedAt: scanB.startedAt, completedAt: windowEndB,
          scanTypes: scanB.scanTypes, failedScanTypes: scanB.failedScanTypes,
        },
        added: [],
        removed: [],
        unchangedCount: 0,
        reason:
          sharedNormalized.length === 0
            ? "These scans don't share any scan types — nothing comparable."
            : "All shared scan types failed in one of the two scans — diff would be misleading.",
      });
      return;
    }

    // Fingerprint sets in each scan's window (target-scoped + scan-type-scoped).
    // "Present in X" = firstSeen <= X.completedAt AND lastSeen >= X.startedAt
    const presentIn = async (sa: Date, sb: Date) => {
      const rows = await prisma.finding.findMany({
        where: {
          orgId: member.orgId,
          ...targetMatch,
          scanType:  { in: dbScanTypes as ScanType[] },
          firstSeen: { lte: sb },
          lastSeen:  { gte: sa },
        },
        select: { fingerprint: true },
      });
      return new Set(rows.map((r) => r.fingerprint));
    };

    const [setA, setB] = await Promise.all([
      presentIn(scanA.startedAt, scanA.completedAt),
      presentIn(scanB.startedAt, windowEndB),
    ]);

    const addedFps     = [...setB].filter((fp) => !setA.has(fp));
    const removedFps   = [...setA].filter((fp) => !setB.has(fp));
    const unchangedFps = [...setA].filter((fp) =>  setB.has(fp));

    // Hydrate added/removed with finding details (unchanged returns count only to
    // keep payload small — the UI rarely needs the full list of stable findings).
    // Type the function explicitly so the empty-fps short circuit doesn't
    // collapse to never[] — the scope-aware classifier below depends on
    // this concrete row shape to push into the in-scope / out-of-scope
    // buckets.
    type HydratedFinding = {
      id:          string;
      fingerprint: string;
      title:       string;
      severity:    Awaited<ReturnType<typeof prisma.finding.findMany>>[number]["severity"];
      scanType:    Awaited<ReturnType<typeof prisma.finding.findMany>>[number]["scanType"];
      status:      Awaited<ReturnType<typeof prisma.finding.findMany>>[number]["status"];
      confidence:  Awaited<ReturnType<typeof prisma.finding.findMany>>[number]["confidence"];
      ruleId:      string | null;
      cveId:       string | null;
      filePath:    string | null;
      lineStart:   number | null;
      firstSeen:   Date;
      lastSeen:    Date;
    };
    const hydrate = (fps: string[]): Promise<HydratedFinding[]> =>
      fps.length === 0
        ? Promise.resolve([] as HydratedFinding[])
        : prisma.finding.findMany({
            where: { orgId: member.orgId, fingerprint: { in: fps } },
            select: {
              id: true, fingerprint: true, title: true, severity: true, scanType: true,
              status: true, confidence: true, ruleId: true, cveId: true,
              filePath: true, lineStart: true, firstSeen: true, lastSeen: true,
            },
            orderBy: [{ severity: "asc" }, { firstSeen: "desc" }],
            take: 500,
          });

    const [addedHydrated, removedHydrated] = await Promise.all([
      hydrate(addedFps),
      hydrate(removedFps),
    ]);

    // ── Scope-aware classification ────────────────────────────────────────
    // A finding "removed" between A → B has two very different meanings:
    //   1. Genuinely fixed   — the URL was re-scanned in B and the vuln is gone
    //   2. Out of scope       — B never visited that URL, so we can't claim
    //                            the vuln is fixed (the crawler may have
    //                            walked a different path, login may have
    //                            broken, recording may have skipped pages)
    //
    // Same logic in reverse for "added": a brand-new URL that wasn't in
    // scope of A means the finding could have existed all along — A just
    // didn't look there.
    //
    // To distinguish them we use the per-scan targetUrls list (populated
    // by PENTEST_FULL crawler / DAST recording). Scans that don't carry
    // a URL surface (SAST / SCA / SECRET / IAC / CONTAINER) leave
    // targetUrls null, in which case we fall back to the legacy behavior
    // (classify everything as in-scope) — code findings don't have an
    // analogous "this file wasn't visited" concept yet.
    //
    // Matching is path-prefix sensitive: the Finding's filePath holds the
    // full URL (e.g. http://dvwa/login.php?id=1) for pentest findings.
    // We compare exact strings first (cheap), then fall back to prefix
    // matching to tolerate trailing-slash and query-string variation.
    const scanAUrls: string[] | null = Array.isArray(scanA.targetUrls)
      ? (scanA.targetUrls as unknown as string[])
      : null;
    const scanBUrls: string[] | null = Array.isArray(scanB.targetUrls)
      ? (scanB.targetUrls as unknown as string[])
      : null;

    const buildUrlIndex = (urls: string[] | null) => {
      if (!urls || urls.length === 0) return null;
      const exact   = new Set<string>();
      const noQuery = new Set<string>();
      for (const u of urls) {
        exact.add(u);
        const idx = u.indexOf("?");
        noQuery.add(idx >= 0 ? u.slice(0, idx) : u);
      }
      return { exact, noQuery };
    };
    const urlsAIdx = buildUrlIndex(scanAUrls);
    const urlsBIdx = buildUrlIndex(scanBUrls);

    // A URL is "in scope" of a scan if either the exact URL or its
    // path-only form (query-string stripped) appears in that scan's
    // recorded URL list. Findings without a filePath (or non-pentest
    // findings) are assumed in-scope — see comment above.
    const isInScope = (
      filePath: string | null,
      scanType: string,
      idx: ReturnType<typeof buildUrlIndex>,
    ): boolean => {
      if (!idx) return true; // no URL list captured → can't classify, treat as in-scope
      // Code-level scan types don't operate on URLs; the filePath is a
      // source path, never a URL. Always in-scope for them.
      if (
        scanType === "SAST" || scanType === "SCA" || scanType === "SECRET" ||
        scanType === "IAC"  || scanType === "CONTAINER"
      ) return true;
      if (!filePath) return true; // pentest finding without a URL field — can't classify
      if (idx.exact.has(filePath)) return true;
      const q = filePath.indexOf("?");
      const noQ = q >= 0 ? filePath.slice(0, q) : filePath;
      return idx.noQuery.has(noQ);
    };

    const removed: HydratedFinding[]         = [];
    const outOfScopeRemoved: HydratedFinding[] = [];
    for (const f of removedHydrated) {
      // For "removed" we ask: was the URL visited in scanB? If yes, the
      // vuln is genuinely gone. If no, scanB never looked there — out of
      // scope, can't claim fixed.
      if (isInScope(f.filePath, f.scanType, urlsBIdx)) {
        removed.push(f);
      } else {
        outOfScopeRemoved.push(f);
      }
    }

    const added: HydratedFinding[]             = [];
    const outOfScopeAdded: HydratedFinding[]   = [];
    for (const f of addedHydrated) {
      // For "added" we ask: was the URL visited in scanA? If yes, the
      // vuln is genuinely new. If no, scanA never looked there — could
      // have existed all along, just newly discovered.
      if (isInScope(f.filePath, f.scanType, urlsAIdx)) {
        added.push(f);
      } else {
        outOfScopeAdded.push(f);
      }
    }

    res.json({
      scanA: {
        id: scanA.id, startedAt: scanA.startedAt, completedAt: scanA.completedAt,
        scanTypes: scanA.scanTypes, failedScanTypes: scanA.failedScanTypes,
        targetUrlCount: scanAUrls?.length ?? null,
      },
      scanB: {
        id: scanB.id, startedAt: scanB.startedAt, completedAt: scanB.completedAt,
        scanTypes: scanB.scanTypes, failedScanTypes: scanB.failedScanTypes,
        targetUrlCount: scanBUrls?.length ?? null,
      },
      effectiveScanTypes: effectiveTypes,
      added,
      removed,
      // Scope-aware additions: empty arrays when neither scan has a URL
      // list (legacy / code scans). Always present in the response so
      // clients don't have to feature-detect.
      outOfScopeAdded,
      outOfScopeRemoved,
      scopeAware: Boolean(urlsAIdx || urlsBIdx),
      unchangedCount: unchangedFps.length,
    });
  } catch (err) { next(err); }
});

// Cancel a scan job
router.post("/:id/cancel", async (req, res, next) => {
  try {
    const user = req.user as { id: string };
    const member = await getActiveMembership(req);
    const scan = await prisma.scanJob.findFirst({
      where: { id: req.params["id"], orgId: member?.orgId },
    });
    if (!scan) { res.status(404).json({ error: "Scan job not found" }); return; }
    if (!["PENDING", "RUNNING"].includes(scan.status)) {
      res.status(409).json({ error: `Cannot cancel a scan in ${scan.status} state` });
      return;
    }

    // Remove any waiting BullMQ jobs (active jobs will finish but DB marks them cancelled)
    const jobIds = (scan.bullJobIds ?? {}) as Record<string, string>;
    await Promise.allSettled(
      Object.entries(jobIds).map(async ([scanType, jobId]) => {
        const queue = scanQueues[scanType as ScanType];
        if (!queue || !jobId) return;
        try {
          const job = await queue.getJob(jobId);
          if (job) await job.remove();
        } catch {
          // Job may already be active or completed — ignore
        }
      })
    );

    await prisma.scanJob.update({
      where: { id: scan.id },
      data: { status: "CANCELLED", completedAt: new Date() },
    });

    emitStatusChange(scan.id, "CANCELLED");

    if (member?.orgId) {
      await audit.log({
        orgId: member.orgId, userId: user.id,
        action: "scan.cancel", resourceType: "ScanJob", resourceId: scan.id,
        metadata: { previousStatus: scan.status, scanTypes: scan.scanTypes },
      });
    }

    res.json({ success: true });
  } catch (err) { next(err); }
});

// Delete a scan job (and its findings)
router.delete("/:id", async (req, res, next) => {
  try {
    const user   = req.user as { id: string };
    const member = await getActiveMembership(req);
    const scan   = await prisma.scanJob.findFirst({
      where: { id: req.params["id"], orgId: member?.orgId },
    });
    if (!scan) { res.status(404).json({ error: "Scan job not found" }); return; }

    await prisma.scanJob.delete({ where: { id: scan.id } });

    if (member?.orgId) {
      await audit.log({
        orgId: member.orgId, userId: user.id,
        action: "scan.delete", resourceType: "ScanJob", resourceId: scan.id,
        metadata: { status: scan.status, scanTypes: scan.scanTypes },
      });
    }

    res.json({ success: true });
  } catch (err) { next(err); }
});

// Delete all failed scan jobs for the org
router.delete("/", async (req, res, next) => {
  try {
    if (req.query["status"] !== "FAILED") {
      res.status(400).json({ error: "Only bulk-delete of FAILED scans is supported" });
      return;
    }
    const user   = req.user as { id: string };
    const member = await getActiveMembership(req);
    if (!member) { res.json({ count: 0 }); return; }

    const { count } = await prisma.scanJob.deleteMany({
      where: { orgId: member.orgId, status: "FAILED" },
    });

    if (count > 0) {
      await audit.log({
        orgId: member.orgId, userId: user.id,
        action: "scan.bulk_delete", resourceType: "ScanJob", resourceId: `bulk:${count}`,
        metadata: { count, status: "FAILED" },
      });
    }

    res.json({ count });
  } catch (err) { next(err); }
});

// On-demand AI summary generation (for old scans or manual refresh)
router.post("/:id/summary", async (req, res, next) => {
  try {
    const user   = req.user as { id: string };
    const member = await getActiveMembership(req);
    const scan   = await prisma.scanJob.findFirst({
      where: { id: req.params["id"], orgId: member?.orgId },
    });
    if (!scan) { res.status(404).json({ error: "Scan job not found" }); return; }
    if (scan.status !== "COMPLETED") {
      res.status(409).json({ error: "Summary only available for completed scans" });
      return;
    }

    // Reset so generateScanSummary doesn't short-circuit on existing value
    await prisma.scanJob.update({
      where: { id: scan.id },
      data: { aiSummary: null, aiSummarisedAt: null },
    });

    // Run in background — client polls GET /:id for the result
    generateScanSummary(scan.id).catch(() => {});
    res.json({ queued: true });
  } catch (err) { next(err); }
});

// SSE stream for real-time scan progress
router.get("/:id/events", async (req, res, next) => {
  try {
    const user = req.user as { id: string };
    const member = await getActiveMembership(req);
    const scan = await prisma.scanJob.findFirst({
      where: { id: req.params["id"], orgId: member?.orgId },
    });
    if (!scan) { res.status(404).json({ error: "Scan job not found" }); return; }

    const scanJobId = req.params["id"] as string;

    res.setHeader("Content-Type", "text/event-stream");
    res.setHeader("Cache-Control", "no-cache");
    res.setHeader("Connection", "keep-alive");
    res.setHeader("X-Accel-Buffering", "no");
    res.flushHeaders();

    // Send current status immediately
    res.write(`data: ${JSON.stringify({ type: "INITIAL", status: scan.status, scanJobId })}\n\n`);

    addClient(scanJobId, res);

    req.on("close", () => {
      removeClient(scanJobId, res);
    });
  } catch (err) { next(err); }
});

export default router;
