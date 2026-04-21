/**
 * One-time migration: fetch code snippets from GitHub for SECRET finding
 * occurrences that have null snippets, and strip legacy "N: code" line-number
 * prefixes left by an earlier version of the scanner.
 *
 * Applies to rawOutput.occurrences[] inside merged SECRET findings.
 *
 * Safe to re-run — only touches occurrences whose snippet is null or has
 * legacy "N: " prefixes.
 *
 * Run:
 *   docker exec admiring-hertz-api-1 sh -c \
 *     "node --import tsx/esm /app/apps/api/src/migrations/backfillSecretSnippets.ts"
 */

import axios from "axios";
import prisma from "../db.js";
import { logger } from "../logger.js";
import { decrypt } from "../services/encryptionService.js";

interface SecretOccurrence {
  filePath:  string | null;
  lineStart: number | null;
  snippet:   string | null;
  verified:  boolean;
  severity:  string;
  scanner:   string;
}

interface SecretMergedRawOutput {
  merged:      boolean;
  count:       number;
  ruleId:      string;
  scanner:     string;
  occurrences: SecretOccurrence[];
  [key: string]: unknown;
}

// ── Helpers ───────────────────────────────────────────────────────────────────

const WORKSPACE_RE = /^\/tmp\/scan_workspace\/[^/]+\/repo\//;

function cleanPath(p: string): string {
  return p.replace(WORKSPACE_RE, "").replace(/^\/+/, "");
}

/** Strip legacy "42: code" line-number prefixes from a snippet. */
function stripLinePrefixes(snippet: string): string {
  const lines = snippet.split("\n");
  const allHavePrefix = lines.every((l) => l.trim() === "" || /^\s*\d+:\s?/.test(l));
  if (!allHavePrefix) return snippet;
  return lines.map((l) => l.replace(/^\s*\d+:\s?/, "")).join("\n");
}

/** True when an occurrence needs a fresh snippet (null) or has legacy "N: " prefixes. */
function needsSnippet(occ: SecretOccurrence): boolean {
  if (!occ.snippet) return true;
  const lines = occ.snippet.split("\n");
  return lines.every((l) => l.trim() === "" || /^\s*\d+:\s/.test(l));
}

async function fetchLines(
  rawUrl:    string,
  token:     string | null,
  lineStart: number,
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
    // ±2 lines of context — clean code, no line-number prefixes
    const ctxStart = Math.max(0, lineStart - 3);
    const ctxEnd   = Math.min(allLines.length, lineStart + 2);
    return allLines.slice(ctxStart, ctxEnd).join("\n").slice(0, 1000) || null;
  } catch {
    return null;
  }
}

// ── Main ──────────────────────────────────────────────────────────────────────

async function run() {
  logger.info("[backfill-secret-snippets] starting");

  const findings = await prisma.finding.findMany({
    where: { scanType: "SECRET", repositoryId: { not: null } },
    select: { id: true, repositoryId: true, rawOutput: true },
  });

  // Only merged findings that have occurrences needing work
  const candidates = findings.filter((f) => {
    const raw = f.rawOutput as SecretMergedRawOutput | null;
    if (!raw?.merged || !Array.isArray(raw.occurrences)) return false;
    return (raw.occurrences as SecretOccurrence[]).some(needsSnippet);
  });

  logger.info(`[backfill-secret-snippets] ${candidates.length} merged SECRET findings need work`);

  // Repo cache: repoId → { fullName, branch, token }
  const repoCache = new Map<string, { fullName: string; branch: string; token: string | null }>();

  let updatedFindings = 0;
  let updatedOccs     = 0;
  let skippedOccs     = 0;

  for (const f of candidates) {
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

    const raw  = f.rawOutput as SecretMergedRawOutput;
    const occs = [...(raw.occurrences as SecretOccurrence[])];
    let   changed = false;

    for (let i = 0; i < occs.length; i++) {
      const occ = occs[i]!;
      if (!needsSnippet(occ)) continue;

      // Has snippet with legacy N: prefixes — strip them in-place
      if (occ.snippet) {
        occs[i] = { ...occ, snippet: stripLinePrefixes(occ.snippet) };
        updatedOccs++;
        changed = true;
        continue;
      }

      // Null snippet — fetch from GitHub
      if (!occ.filePath || occ.lineStart == null) { skippedOccs++; continue; }

      const path   = cleanPath(occ.filePath);
      const rawUrl = `https://raw.githubusercontent.com/${fullName}/${branch}/${path}`;
      const snippet = await fetchLines(rawUrl, token, occ.lineStart);

      if (!snippet) { skippedOccs++; continue; }

      occs[i] = { ...occ, snippet };
      updatedOccs++;
      changed = true;
    }

    if (!changed) continue;

    await prisma.finding.update({
      where: { id: f.id },
      data:  { rawOutput: { ...raw, occurrences: occs } as object },
    });
    updatedFindings++;
  }

  logger.info(
    `[backfill-secret-snippets] done — ${updatedFindings} findings updated, ` +
    `${updatedOccs} occurrences fixed, ${skippedOccs} skipped`,
  );
}

run()
  .then(() => process.exit(0))
  .catch((err) => { console.error(err); process.exit(1); });
