/**
 * One-time migration: backfill codeSnippet for SAST findings that were
 * scanned when Semgrep returned "requires login" (a Pro paywall placeholder)
 * instead of the actual code, or when the snippet was otherwise missing.
 *
 * Strategy: fetch the raw file from GitHub using the repo's stored access
 * token, then slice out the vulnerable line range (same approach as IAC backfill).
 *
 * Safe to re-run — idempotent (skips findings that already have a snippet).
 *
 * Run:
 *   docker exec admiring-hertz-api-1 sh -c \
 *     "node --import tsx/esm /app/apps/api/src/migrations/backfillSastSnippets.ts"
 */

import axios from "axios";
import prisma from "../db.js";
import { logger } from "../logger.js";
import { decrypt } from "../services/encryptionService.js";

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
    // lineStart / lineEnd are 1-based; show ±2 lines of context
    const ctxStart = Math.max(0, lineStart - 3);
    const ctxEnd   = Math.min(allLines.length, lineEnd + 2);
    const slice = allLines.slice(ctxStart, ctxEnd);
    return slice
      .map((line, i) => `${ctxStart + i + 1}: ${line}`)
      .join("\n")
      .slice(0, 1000);
  } catch {
    return null;
  }
}

async function run() {
  logger.info("[backfill-sast] starting SAST snippet backfill from GitHub");

  const findings = await prisma.finding.findMany({
    where: {
      scanType:     "SAST",
      codeSnippet:  null,
      filePath:     { not: null },
      lineStart:    { not: null },
      repositoryId: { not: null },
    },
    select: {
      id:           true,
      filePath:     true,
      lineStart:    true,
      lineEnd:      true,
      repositoryId: true,
    },
  });

  logger.info(`[backfill-sast] ${findings.length} SAST findings to backfill`);

  // Cache: repoId → { fullName, defaultBranch, token }
  const repoCache = new Map<string, { fullName: string; branch: string; token: string | null }>();

  let updated = 0;
  let skipped = 0;

  for (const f of findings) {
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
    if (!fullName) { skipped++; continue; }

    const cleanPath = (f.filePath ?? "").replace(/^\/+/, "");
    const lineStart = f.lineStart ?? 1;
    const lineEnd   = f.lineEnd   ?? lineStart;

    const rawUrl = `https://raw.githubusercontent.com/${fullName}/${branch}/${cleanPath}`;
    const snippet = await fetchLines(rawUrl, token, lineStart, lineEnd);

    if (!snippet) { skipped++; continue; }

    await prisma.finding.update({
      where: { id: f.id },
      data:  { codeSnippet: snippet },
    });
    updated++;
  }

  logger.info(`[backfill-sast] done — ${updated} updated, ${skipped} skipped`);
}

run()
  .then(() => process.exit(0))
  .catch((err) => { console.error(err); process.exit(1); });
