/**
 * SAST snippet backfill — populates `codeSnippet` (and merged
 * `rawOutput.locations[].snippet`) by fetching the raw file from GitHub.
 *
 * Called automatically by scanWorker after every SAST scan on a repository,
 * so users never see "snippet missing" findings even when Semgrep returns
 * empty `extra.lines` (Pro-paywall placeholder, parser fallback, etc.).
 *
 * Migrations `backfillSastSnippets.ts` and `backfillSastLocationSnippets.ts`
 * remain available as one-shot retroactive fixes for historical data.
 */

import axios from "axios";
import prisma from "../db.js";
import { logger } from "../logger.js";
import { decrypt } from "./encryptionService.js";

const REQUIRES_LOGIN = /^requires?\s+login$/i;

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

function snippetMissing(s: string | null | undefined): boolean {
  if (!s) return true;
  return REQUIRES_LOGIN.test(s.trim());
}

/**
 * Fetch ±2 lines of context around `[lineStart, lineEnd]` from the raw file.
 * Returns clean code (no "N: " prefix) so SyntaxHighlight can render its own
 * line gutter. Caps at 1000 chars to keep the JSON column small.
 */
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
    const ctxStart = Math.max(0, lineStart - 3);
    const ctxEnd   = Math.min(allLines.length, lineEnd + 2);
    return allLines.slice(ctxStart, ctxEnd).join("\n").slice(0, 1000);
  } catch {
    return null;
  }
}

interface RepoCtx {
  fullName: string;
  branch:   string;
  token:    string | null;
}

async function loadRepoContext(repoId: string): Promise<RepoCtx | null> {
  const repo = await prisma.repository.findUnique({
    where: { id: repoId },
    select: { fullName: true, defaultBranch: true },
  });
  if (!repo?.fullName) return null;

  const member = await prisma.organizationMember.findFirst({
    where: { org: { repositories: { some: { id: repoId } } } },
    select: { user: { select: { accessToken: true } } },
  });

  let token: string | null = null;
  try {
    token = member?.user?.accessToken ? decrypt(member.user.accessToken) : null;
  } catch { /* ignore decrypt failures, fall back to anon GitHub */ }

  return { fullName: repo.fullName, branch: repo.defaultBranch || "main", token };
}

/**
 * Backfill snippets for every SAST finding in a single scan job.
 *
 * Handles two shapes:
 *   1. Plain finding with empty `codeSnippet` → fetch + UPDATE codeSnippet
 *   2. Merged finding with `rawOutput.locations[].snippet` empty / "requires
 *      login" → fetch each missing location and rewrite the JSON blob
 *
 * Designed to be called fire-and-forget from scanWorker — never throws,
 * skips silently if no GitHub token is available or the repo isn't linked.
 */
export async function backfillSnippetsForScanJob(opts: {
  scanJobId: string;
  repositoryId: string;
}): Promise<{ updatedFindings: number; updatedLocations: number }> {
  const { scanJobId, repositoryId } = opts;

  const repoCtx = await loadRepoContext(repositoryId);
  if (!repoCtx) {
    logger.debug("[sast-snippet] no repo context, skipping backfill", { scanJobId, repositoryId });
    return { updatedFindings: 0, updatedLocations: 0 };
  }

  const findings = await prisma.finding.findMany({
    where: { scanJobId, scanType: "SAST", repositoryId },
    select: {
      id: true, codeSnippet: true, filePath: true, lineStart: true, lineEnd: true,
      rawOutput: true,
    },
  });

  if (findings.length === 0) return { updatedFindings: 0, updatedLocations: 0 };

  let updatedFindings  = 0;
  let updatedLocations = 0;

  for (const f of findings) {
    const raw    = f.rawOutput as MergedRawOutput | null;
    const merged = raw?.merged === true && Array.isArray(raw.locations);

    // ── Case 1: merged finding — rewrite per-location snippets ──────────────
    if (merged) {
      const locations = [...(raw!.locations as SastLocation[])];
      let changed = false;

      for (let i = 0; i < locations.length; i++) {
        const loc = locations[i]!;
        if (!snippetMissing(loc.snippet)) continue;
        if (!loc.filePath || loc.lineStart == null) continue;

        const path    = loc.filePath.replace(/^\/+/, "");
        const url     = `https://raw.githubusercontent.com/${repoCtx.fullName}/${repoCtx.branch}/${path}`;
        const snippet = await fetchLines(url, repoCtx.token, loc.lineStart, loc.lineEnd ?? loc.lineStart);
        if (!snippet) continue;

        locations[i] = { ...loc, snippet };
        updatedLocations++;
        changed = true;
      }

      if (changed) {
        await prisma.finding.update({
          where: { id: f.id },
          data:  { rawOutput: { ...raw, locations } as object },
        });
        updatedFindings++;
      }
      continue;
    }

    // ── Case 2: plain finding — fill top-level codeSnippet ─────────────────
    if (!snippetMissing(f.codeSnippet)) continue;
    if (!f.filePath || f.lineStart == null) continue;

    const path    = f.filePath.replace(/^\/+/, "");
    const url     = `https://raw.githubusercontent.com/${repoCtx.fullName}/${repoCtx.branch}/${path}`;
    const snippet = await fetchLines(url, repoCtx.token, f.lineStart, f.lineEnd ?? f.lineStart);
    if (!snippet) continue;

    await prisma.finding.update({
      where: { id: f.id },
      data:  { codeSnippet: snippet },
    });
    updatedFindings++;
  }

  return { updatedFindings, updatedLocations };
}
