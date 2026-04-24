/**
 * PR Check Run publisher — creates / updates a GitHub Check Run for a scan and
 * posts inline review comments for each finding on the PR's changed lines.
 *
 * Lifecycle mirrors the ScanJob:
 *   • scan enqueued  → createQueuedCheck()      status=queued
 *   • worker starts  → markInProgress()         status=in_progress
 *   • scan finishes  → completeCheck()          status=completed + conclusion
 *
 * Conclusion maps from the policy verdict (policyService.evaluatePolicy):
 *   • verdict=success → conclusion=success
 *   • verdict=failure → conclusion=failure   (blocks PR when required)
 *   • verdict=neutral → conclusion=neutral   (no policy configured)
 */
import type { Finding } from "@prisma/client";
import prisma from "../db.js";
import { logger } from "../logger.js";
import { installationClient } from "../github/app.js";
import { generateFixSuggestion } from "./fixSuggestionService.js";
import { resolvePolicy, evaluatePolicy } from "./policyService.js";
import type { PolicyEvaluation } from "./policyService.js";

const APP_NAME = "DevSecOps Platform";

type Verdict = PolicyEvaluation["verdict"];

interface CreateArgs {
  scanJobId:    string;
  repositoryId: string;
  installationId: number;
  owner:        string;
  repo:         string;
  prNumber:     number;
  headSha:      string;
  baseSha:      string;
}

export async function createQueuedCheck(args: CreateArgs): Promise<void> {
  const client = await installationClient(args.installationId);
  if (!client) {
    logger.warn("prCheckService: no installation client — skipping check run");
    return;
  }

  try {
    const res = await client.post(`/repos/${args.owner}/${args.repo}/check-runs`, {
      name: APP_NAME,
      head_sha: args.headSha,
      status: "queued",
      output: {
        title: "Security scan queued",
        summary: `Scanning ${args.headSha.slice(0, 7)} — results will appear here shortly.`,
      },
    });
    const checkRunId = BigInt(res.data.id);

    await prisma.prCheckRun.create({
      data: {
        scanJobId:    args.scanJobId,
        repositoryId: args.repositoryId,
        prNumber:     args.prNumber,
        headSha:      args.headSha,
        baseSha:      args.baseSha,
        checkRunId,
        status:       "queued",
      },
    });
    logger.info("prCheckService: queued check run", { checkRunId: checkRunId.toString() });
  } catch (err) {
    logger.error("prCheckService.createQueuedCheck failed", { error: (err as Error).message });
  }
}

export async function markInProgress(scanJobId: string): Promise<void> {
  const row = await prisma.prCheckRun.findUnique({
    where: { scanJobId },
    include: { repository: true },
  });
  if (!row || !row.repository.githubAppInstallationId) return;
  const client = await installationClient(row.repository.githubAppInstallationId);
  if (!client) return;
  const [owner, repo] = row.repository.fullName.split("/");
  try {
    await client.patch(`/repos/${owner}/${repo}/check-runs/${row.checkRunId}`, {
      status: "in_progress",
      output: {
        title: "Security scan running",
        summary: "Running Semgrep, Trivy, TruffleHog, and Checkov on PR changes…",
      },
    });
    await prisma.prCheckRun.update({
      where: { scanJobId },
      data:  { status: "in_progress" },
    });
  } catch (err) {
    logger.error("prCheckService.markInProgress failed", { error: (err as Error).message });
  }
}

/**
 * Complete the check run and post inline comments for each finding
 * whose file+line intersect the PR diff.
 */
export async function completeCheck(
  scanJobId: string,
  findings:  Finding[],
  evaluation: PolicyEvaluation
): Promise<void> {
  const row = await prisma.prCheckRun.findUnique({
    where: { scanJobId },
    include: { repository: true },
  });
  if (!row || !row.repository.githubAppInstallationId) return;
  const client = await installationClient(row.repository.githubAppInstallationId);
  if (!client) return;
  const [owner, repo] = row.repository.fullName.split("/");

  const verdict    = evaluation.verdict as Verdict;
  const conclusion =
    verdict === "success" ? "success" :
    verdict === "failure" ? "failure" : "neutral";

  // ── Inline review comments (capped at 30 per run to avoid rate-limits) ──
  let commentsPosted = 0;
  const commentable = findings
    .filter((f) => f.status === "OPEN" && f.filePath && f.lineStart)
    .slice(0, 30);

  for (const f of commentable) {
    // Generate AI-fix suggestion and inline it as a ```suggestion block so
    // GitHub renders a "Commit suggestion" button directly in the comment.
    const body = await buildCommentBodyWithFix(f);
    try {
      await client.post(`/repos/${owner}/${repo}/pulls/${row.prNumber}/comments`, {
        body,
        commit_id: row.headSha,
        path:      f.filePath,
        line:      f.lineStart,
        side:      "RIGHT",
      });
      commentsPosted += 1;
    } catch (err) {
      // Most common: line not in diff → GitHub 422. Silent skip.
      const status = (err as { response?: { status?: number } })?.response?.status;
      if (status !== 422) {
        logger.warn("prCheckService: inline comment failed", {
          path: f.filePath, line: f.lineStart, status,
        });
      }
    }
  }

  try {
    await client.patch(`/repos/${owner}/${repo}/check-runs/${row.checkRunId}`, {
      status:     "completed",
      conclusion,
      completed_at: new Date().toISOString(),
      output:     buildCheckOutput(findings, evaluation),
    });
  } catch (err) {
    logger.error("prCheckService.completeCheck patch failed", { error: (err as Error).message });
  }

  await prisma.prCheckRun.update({
    where: { scanJobId },
    data:  { status: "completed", conclusion, commentsPosted },
  });
  logger.info("prCheckService: completed check run", {
    scanJobId, conclusion, commentsPosted, findings: findings.length,
  });
}

function buildCheckOutput(findings: Finding[], evaluation: PolicyEvaluation) {
  const bySev = findings.reduce<Record<string, number>>((acc, f) => {
    if (f.status === "OPEN") acc[f.severity] = (acc[f.severity] ?? 0) + 1;
    return acc;
  }, {});

  const sevLine =
    `**Critical:** ${bySev.CRITICAL ?? 0}  ` +
    `**High:** ${bySev.HIGH ?? 0}  ` +
    `**Medium:** ${bySev.MEDIUM ?? 0}  ` +
    `**Low:** ${bySev.LOW ?? 0}`;

  const violationsBlock = evaluation.violations.length
    ? `\n\n### Policy violations\n` +
      evaluation.violations.map((v) => `- **${v.ruleType}** — ${v.message}`).join("\n")
    : "";

  const policyLine = evaluation.policyName
    ? `\n\nPolicy applied: **${evaluation.policyName}**`
    : "";

  const topFive = findings
    .filter((f) => f.status === "OPEN")
    .sort(sortBySeverity)
    .slice(0, 5);

  const findingList = topFive.length
    ? `\n\n### Top findings\n` +
      topFive.map((f) =>
        `- [${f.severity}] ${f.title}` +
        (f.filePath ? ` — \`${f.filePath}${f.lineStart ? ":" + f.lineStart : ""}\`` : "")
      ).join("\n")
    : "";

  return {
    title:   evaluation.verdict === "failure"
      ? "Security policy failed"
      : evaluation.verdict === "success"
      ? "Security scan passed"
      : "Security scan complete",
    summary: `${sevLine}${policyLine}${violationsBlock}${findingList}`,
  };
}

function buildCommentBody(f: Finding): string {
  const emoji =
    f.severity === "CRITICAL" ? "🔴" :
    f.severity === "HIGH"     ? "🟠" :
    f.severity === "MEDIUM"   ? "🟡" : "🟢";
  const cve = f.cveId ? ` (${f.cveId})` : "";
  // The HTML-comment marker is parsed by prCommandService to link a command
  // reply back to its finding. DO NOT remove — users cannot see it in the UI.
  const marker  = `<!-- devsecops:finding=${f.id} -->`;
  const cmdHelp = `\n\n<sub>Reply with \`/ignore\`, \`/accept-risk <reason>\`, \`/snooze 7d\`, or \`/rescan\` — \`/help\` for all commands.</sub>`;
  return `${marker}\n${emoji} **${f.severity} — ${f.title}**${cve}\n\n${f.description}` +
    (f.remediation ? `\n\n**Remediation:** ${f.remediation}` : "") +
    cmdHelp;
}

/**
 * Build an inline comment augmented with a ```suggestion block whenever the
 * cached AI fix is a clean single-hunk replacement covering the finding's line
 * range. GitHub will render a "Commit suggestion" button that pushes the diff
 * straight onto the PR branch — one-click remediation for the developer.
 */
async function buildCommentBodyWithFix(f: Finding): Promise<string> {
  const base = buildCommentBody(f);
  if (!f.filePath || !f.lineStart) return base;

  let diff = f.aiFixSuggestion;
  if (!diff) {
    try {
      diff = await generateFixSuggestion(f.id);
    } catch (err) {
      logger.debug("prCheck: AI fix generation failed", { findingId: f.id, err: (err as Error).message });
      return base;
    }
  }
  const replacement = extractSuggestionForLines(diff ?? "", f.filePath, f.lineStart, f.lineEnd ?? f.lineStart);
  if (!replacement) return base;

  return base + `\n\n\`\`\`suggestion\n${replacement}\n\`\`\``;
}

/**
 * Parse a unified diff and extract the replacement text for the hunk whose
 * old-range covers [startLine, endLine]. Returns null if the diff's layout
 * doesn't map cleanly onto those lines (multi-file, multi-hunk spanning, etc.)
 * so we never post a broken suggestion.
 */
function extractSuggestionForLines(
  diff: string,
  filePath: string,
  startLine: number,
  endLine:   number
): string | null {
  if (!diff) return null;
  const lines = diff.split("\n");
  // Find the "+++ b/<path>" header for our file, tolerating a/b and leading ./
  const wantPath = filePath.replace(/^\.\//, "");
  let i = 0;
  let inOurFile = false;
  while (i < lines.length) {
    const ln = lines[i] ?? "";
    if (ln.startsWith("+++ ")) {
      inOurFile = ln.includes(wantPath);
    } else if (inOurFile && ln.startsWith("@@")) {
      // Parse "@@ -oldStart,oldLen +newStart,newLen @@"
      const m = /@@ -(\d+)(?:,(\d+))? \+(\d+)(?:,(\d+))? @@/.exec(ln);
      if (!m) { i += 1; continue; }
      const oldStart = parseInt(m[1] ?? "0", 10);
      const oldLen   = parseInt(m[2] ?? "1", 10);
      const hunkEnd  = oldStart + oldLen - 1;
      // Only accept hunks whose old-range fully contains the finding's range
      if (oldStart <= startLine && hunkEnd >= endLine) {
        const out: string[] = [];
        i += 1;
        while (i < lines.length && !lines[i]!.startsWith("@@") && !lines[i]!.startsWith("diff ") && !lines[i]!.startsWith("--- ")) {
          const hl = lines[i] ?? "";
          if (hl.startsWith("+") && !hl.startsWith("+++"))      out.push(hl.slice(1));
          else if (hl.startsWith(" "))                           out.push(hl.slice(1));
          else if (hl.startsWith("-") && !hl.startsWith("---")) { /* drop */ }
          i += 1;
        }
        const text = out.join("\n").replace(/\n+$/, "");
        return text.length > 0 ? text : null;
      }
    }
    i += 1;
  }
  return null;
}

/**
 * Re-evaluate the scan's policy against the current (possibly-updated)
 * finding set and patch the existing Check Run. Called after a slash-command
 * mutates a finding (ignore / accept-risk / snooze) so the PR gate reflects
 * the new state without needing a re-scan.
 */
export async function refreshCheckRun(scanJobId: string): Promise<void> {
  const row = await prisma.prCheckRun.findUnique({
    where: { scanJobId },
    include: { repository: true, scanJob: true },
  });
  if (!row || !row.repository.githubAppInstallationId) return;
  const client = await installationClient(row.repository.githubAppInstallationId);
  if (!client) return;
  const [owner, repo] = row.repository.fullName.split("/");

  const targetFilter = { repositoryId: row.repository.id };
  const windowStart  = row.scanJob.startedAt ?? row.scanJob.createdAt;
  const findings = await prisma.finding.findMany({
    where: { ...targetFilter, orgId: row.repository.orgId, lastSeen: { gte: windowStart } },
  });

  const policy = await resolvePolicy(row.repository.orgId, row.repository.id, row.repository.policyId);
  const evaluation = evaluatePolicy(policy, findings, {
    scanTypesRun: row.scanJob.scanTypes,
    baseCommitDate: row.createdAt,
  });
  const conclusion =
    evaluation.verdict === "success" ? "success" :
    evaluation.verdict === "failure" ? "failure" : "neutral";

  try {
    await client.patch(`/repos/${owner}/${repo}/check-runs/${row.checkRunId}`, {
      status: "completed",
      conclusion,
      completed_at: new Date().toISOString(),
      output: buildCheckOutput(findings, evaluation),
    });
    await prisma.prCheckRun.update({
      where: { scanJobId },
      data:  { status: "completed", conclusion },
    });
    logger.info("prCheckService: refreshed check run", { scanJobId, conclusion });
  } catch (err) {
    logger.error("prCheckService.refresh failed", { scanJobId, err: (err as Error).message });
  }
}

const SEV_RANK: Record<string, number> = { CRITICAL: 4, HIGH: 3, MEDIUM: 2, LOW: 1, INFO: 0 };
function sortBySeverity(a: Finding, b: Finding) {
  return (SEV_RANK[b.severity] ?? 0) - (SEV_RANK[a.severity] ?? 0);
}
