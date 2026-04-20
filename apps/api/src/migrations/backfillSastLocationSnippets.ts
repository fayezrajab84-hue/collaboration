/**
 * One-time migration: replace "requires login" placeholder snippets inside
 * rawOutput.locations[] for merged SAST findings.
 *
 * Merged SAST findings store per-location data (filePath, lineStart, snippet)
 * inside rawOutput.locations[]. When Semgrep ran under a non-Pro account those
 * snippets were set to "requires login". This migration fetches the real code
 * from GitHub and writes it back into the JSON blob.
 *
 * Safe to re-run — only updates locations whose snippet is the placeholder.
 *
 * Run:
 *   docker exec admiring-hertz-api-1 sh -c \
 *     "node --import tsx/esm /app/apps/api/src/migrations/backfillSastLocationSnippets.ts"
 */

import axios from "axios";
import prisma from "../db.js";
import { logger } from "../logger.js";
import { decrypt } from "../services/encryptionService.js";

interface SastLocation {
  filePath:  string | null;
  lineStart: number | null;
  lineEnd:   number | null;
  severity:  string;
  message:   string;
  snippet:   string | null;
}

interface MergedRawOutput {
  merged:    boolean;
  locations: SastLocation[];
  [key: string]: unknown;
}

const REQUIRES_LOGIN = /^requires?\s+login$/i;

async function fetchLines(
  rawUrl: string,
  token: string | null,
  lineStart: number,
  lineEnd: number,
): Promise<string | null> {
  try {
    const resp = await axios.get<string>(rawUrl, {
      headers: {
        Accept: "application/vnd.github.raw+json",
        ...(token ? { Authorization: `Bearer ${token}` } : {}),
      },
      timeout: 10_000,
    });
    const allLines = resp.data.split("\n");
    // ±2 lines of context around the vulnerable range
    const ctxStart = Math.max(0, lineStart - 3);
    const ctxEnd   = Math.min(allLines.length, lineEnd + 2);
    const slice    = allLines.slice(ctxStart, ctxEnd);
    return slice
      .map((line, i) => `${ctxStart + i + 1}: ${line}`)
      .join("\n")
      .slice(0, 1000);
  } catch {
    return null;
  }
}

async function run() {
  logger.info("[backfill-sast-locs] starting location snippet backfill");

  // Find merged SAST findings that have at least one "requires login" location
  const findings = await prisma.finding.findMany({
    where: {
      scanType:     "SAST",
      scanner:      "semgrep",
      repositoryId: { not: null },
    },
    select: {
      id:           true,
      repositoryId: true,
      rawOutput:    true,
    },
  });

  // Filter to those that actually have the placeholder
  const needsBackfill = findings.filter((f) => {
    const raw = f.rawOutput as MergedRawOutput | null;
    if (!raw?.merged || !Array.isArray(raw.locations)) return false;
    return (raw.locations as SastLocation[]).some(
      (loc) => loc.snippet && REQUIRES_LOGIN.test(loc.snippet.trim()),
    );
  });

  logger.info(`[backfill-sast-locs] ${needsBackfill.length} merged SAST findings need location snippet backfill`);

  // Repo cache: repoId → { fullName, branch, token }
  const repoCache = new Map<string, { fullName: string; branch: string; token: string | null }>();

  let updatedFindings = 0;
  let updatedLocations = 0;
  let skippedLocations = 0;

  for (const f of needsBackfill) {
    const repoId = f.repositoryId!;

    if (!repoCache.has(repoId)) {
      const repo = await prisma.repository.findUnique({
        where: { id: repoId },
        select: { fullName: true, defaultBranch: true },
      });
      const member = await prisma.organizationMember.findFirst({
        where: { org: { repositories: { some: { id: repoId } } } },
        select: { user: { select: { accessToken: true } } },
      });
      let token: string | null = null;
      try {
        token = member?.user?.accessToken ? decrypt(member.user.accessToken) : null;
      } catch { /* ignore */ }
      repoCache.set(repoId, {
        fullName: repo?.fullName ?? "",
        branch:   repo?.defaultBranch ?? "main",
        token,
      });
    }

    const { fullName, branch, token } = repoCache.get(repoId)!;
    if (!fullName) continue;

    const raw       = f.rawOutput as MergedRawOutput;
    const locations = [...(raw.locations as SastLocation[])];
    let   changed   = false;

    for (let i = 0; i < locations.length; i++) {
      const loc = locations[i]!;
      if (!loc.snippet || !REQUIRES_LOGIN.test(loc.snippet.trim())) continue;
      if (!loc.filePath || loc.lineStart == null) { skippedLocations++; continue; }

      const cleanPath = loc.filePath.replace(/^\/+/, "");
      const rawUrl    = `https://raw.githubusercontent.com/${fullName}/${branch}/${cleanPath}`;
      const snippet   = await fetchLines(rawUrl, token, loc.lineStart, loc.lineEnd ?? loc.lineStart);

      if (!snippet) { skippedLocations++; continue; }

      locations[i] = { ...loc, snippet };
      updatedLocations++;
      changed = true;
    }

    if (!changed) continue;

    // Write the updated locations back into rawOutput
    const updatedRaw: MergedRawOutput = { ...raw, locations };
    await prisma.finding.update({
      where: { id: f.id },
      data:  { rawOutput: updatedRaw as object },
    });
    updatedFindings++;
  }

  logger.info(
    `[backfill-sast-locs] done — ${updatedFindings} findings updated, ` +
    `${updatedLocations} locations backfilled, ${skippedLocations} skipped`,
  );
}

run()
  .then(() => process.exit(0))
  .catch((err) => { console.error(err); process.exit(1); });
