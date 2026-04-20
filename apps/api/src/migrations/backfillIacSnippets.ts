/**
 * One-time migration: backfill codeSnippet for IAC findings that were
 * scanned before --compact was removed from Checkov (code_block was null).
 *
 * Strategy: fetch the raw file from GitHub using the repo's stored access
 * token, then slice out the vulnerable line range.
 *
 * Safe to re-run — idempotent (skips findings that already have a snippet).
 *
 * Run:
 *   docker exec admiring-hertz-api-1 sh -c \
 *     "node --import tsx/esm /app/apps/api/src/migrations/backfillIacSnippets.ts"
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
    // lineStart / lineEnd are 1-based
    const slice = allLines.slice(lineStart - 1, lineEnd);
    return slice
      .map((line, i) => `${lineStart + i}: ${line}`)
      .join("\n")
      .slice(0, 1000);
  } catch {
    return null;
  }
}

async function run() {
  logger.info("[backfill-iac] starting IAC snippet backfill from GitHub");

  const findings = await prisma.finding.findMany({
    where: {
      scanType:     "IAC",
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

  logger.info(`[backfill-iac] ${findings.length} IAC findings to backfill`);

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
      // Get the owner's decrypted GitHub token
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

    // Strip leading slash from stored filePath
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

  logger.info(`[backfill-iac] done — ${updated} updated, ${skipped} skipped`);
}

run()
  .then(() => process.exit(0))
  .catch((err) => { console.error(err); process.exit(1); });
