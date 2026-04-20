/**
 * One-time migration: backfill codeSnippet for SECRET findings that have a
 * filePath + lineStart but no codeSnippet stored.
 *
 * TruffleHog does not embed code in its JSON output; Semgrep-sourced SECRET
 * findings had "requires login" placeholders that were cleared to null.
 * This migration fetches the real code from GitHub raw API and writes it back.
 *
 * Safe to re-run — only updates findings where codeSnippet IS NULL.
 *
 * Run:
 *   docker exec admiring-hertz-api-1 sh -c \
 *     "node --import tsx/esm /app/apps/api/src/migrations/backfillSecretSnippets.ts"
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
    // ±2 lines of context around the finding line
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
  logger.info("[backfill-secret-snippets] starting SECRET finding snippet backfill");

  // SECRET findings that have a file + line but no snippet yet
  const findings = await prisma.finding.findMany({
    where: {
      scanType:     "SECRET",
      repositoryId: { not: null },
      filePath:     { not: null },
      lineStart:    { not: null },
      codeSnippet:  null,
    },
    select: {
      id:           true,
      repositoryId: true,
      filePath:     true,
      lineStart:    true,
      lineEnd:      true,
    },
  });

  logger.info(`[backfill-secret-snippets] ${findings.length} SECRET findings need snippet backfill`);

  // Repo cache: repoId → { fullName, branch, token }
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

    const cleanPath = (f.filePath as string).replace(/^\/+/, "");
    const lineStart = f.lineStart as number;
    const lineEnd   = (f.lineEnd as number | null) ?? lineStart;
    const rawUrl    = `https://raw.githubusercontent.com/${fullName}/${branch}/${cleanPath}`;

    const snippet = await fetchLines(rawUrl, token, lineStart, lineEnd);
    if (!snippet) { skipped++; continue; }

    await prisma.finding.update({
      where: { id: f.id },
      data:  { codeSnippet: snippet },
    });
    updated++;
  }

  logger.info(
    `[backfill-secret-snippets] done — ${updated} findings updated, ${skipped} skipped`,
  );
}

run()
  .then(() => process.exit(0))
  .catch((err) => { console.error(err); process.exit(1); });
