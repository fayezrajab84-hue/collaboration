/**
 * prCommandService — parses and dispatches slash commands from PR comments.
 *
 * Supported commands:
 *   /ignore                     SECURITY+   — mark finding FALSE_POSITIVE
 *   /accept-risk <reason>       SECURITY+   — create suppression
 *   /snooze <Nd|Nh>             DEVELOPER+  — hide finding until deadline
 *   /severity <LEVEL>           SECURITY+   — override severity
 *   /rescan                     DEVELOPER+  — trigger new incremental scan
 *   /help                       any         — post command help
 *
 * Finding context is recovered from the parent review-comment body via the
 * HTML marker  `<!-- devsecops:finding=ID -->`  that prCheckService injects.
 * Commands that need a finding (ignore/accept-risk/snooze/severity) are only
 * valid when replied as a review-comment thread on the bot's original inline
 * comment. `/rescan` and `/help` work anywhere on the PR.
 */
import prisma from "../db.js";
import { logger } from "../logger.js";
import { installationClient, listPullRequestFiles } from "../github/app.js";
import { triggerScan } from "./scanService.js";
import * as suppressions from "./suppressionService.js";
import { refreshCheckRun } from "./prCheckService.js";
import { ROLE_RANK, type Role } from "./rbac.js";
import type { Severity } from "@devsecops/types";

export interface CommandContext {
  installationId: number;
  owner:          string;
  repo:           string;           // repo name only
  repositoryId:   string;           // Repository.id (internal)
  orgId:          string;
  prNumber:       number;
  commentId:      number;           // the comment that issued the command
  commentAuthor:  string;           // GitHub username
  commentBody:    string;
  // Only set for review-comment replies — body of the bot comment being replied to
  parentBody?:    string | null;
  isReviewComment: boolean;         // true = pull_request_review_comment, false = issue_comment
}

type CommandName = "ignore" | "accept-risk" | "snooze" | "severity" | "rescan" | "help";

const MIN_ROLE: Record<CommandName, Role> = {
  "ignore":      "SECURITY",
  "accept-risk": "SECURITY",
  "severity":    "SECURITY",
  "snooze":      "DEVELOPER",
  "rescan":      "DEVELOPER",
  "help":        "VIEWER",
};

const HELP_TEXT =
  "**DevSecOps PR commands**\n\n" +
  "| Command | Role | Description |\n" +
  "|---|---|---|\n" +
  "| `/ignore` | SECURITY+ | Mark this finding as a false positive |\n" +
  "| `/accept-risk <reason>` | SECURITY+ | Suppress this finding across scans (requires reason) |\n" +
  "| `/snooze <Nd\\|Nh>` | DEV+ | Hide finding until deadline (e.g. `/snooze 7d`) |\n" +
  "| `/severity <LEVEL>` | SECURITY+ | Override severity (CRITICAL/HIGH/MEDIUM/LOW/INFO) |\n" +
  "| `/rescan` | DEV+ | Re-run scans for this PR |\n" +
  "| `/help` | any | Show this message |\n\n" +
  "Reply to the bot's inline comment to target a specific finding.";

// ────────────────────────────────────────────────────────────────────────────
// Parsing
// ────────────────────────────────────────────────────────────────────────────

interface ParsedCommand {
  name: CommandName;
  args: string;
}

export function parseCommand(body: string): ParsedCommand | null {
  if (!body) return null;
  // Take first non-empty line that starts with `/`
  for (const raw of body.split(/\r?\n/)) {
    const line = raw.trim();
    if (!line.startsWith("/")) continue;
    const match = line.match(/^\/([a-z-]+)(?:\s+(.*))?$/i);
    if (!match) return null;
    const name = match[1]!.toLowerCase() as CommandName;
    if (!(name in MIN_ROLE)) return null;
    return { name, args: (match[2] ?? "").trim() };
  }
  return null;
}

export function extractFindingId(body: string | null | undefined): string | null {
  if (!body) return null;
  const m = body.match(/<!--\s*devsecops:finding=([a-z0-9-]+)\s*-->/i);
  return m ? m[1]! : null;
}

function parseDuration(s: string): Date | null {
  const m = s.match(/^(\d+)\s*([dhw])$/i);
  if (!m) return null;
  const n = parseInt(m[1]!, 10);
  const unit = m[2]!.toLowerCase();
  const ms =
    unit === "d" ? n * 86_400_000 :
    unit === "h" ? n *  3_600_000 :
    unit === "w" ? n * 7 * 86_400_000 : 0;
  if (ms <= 0) return null;
  return new Date(Date.now() + ms);
}

// ────────────────────────────────────────────────────────────────────────────
// GitHub helpers (reactions / replies)
// ────────────────────────────────────────────────────────────────────────────

async function react(
  ctx: CommandContext,
  content: "+1" | "-1" | "rocket" | "eyes" | "confused"
): Promise<void> {
  const client = await installationClient(ctx.installationId);
  if (!client) return;
  const url = ctx.isReviewComment
    ? `/repos/${ctx.owner}/${ctx.repo}/pulls/comments/${ctx.commentId}/reactions`
    : `/repos/${ctx.owner}/${ctx.repo}/issues/comments/${ctx.commentId}/reactions`;
  try {
    await client.post(url, { content });
  } catch (err) {
    logger.warn("prCommandService: react failed", { err: (err as Error).message });
  }
}

async function reply(ctx: CommandContext, body: string): Promise<void> {
  const client = await installationClient(ctx.installationId);
  if (!client) return;
  try {
    // Always post back as an issue-comment reply on the PR conversation — simple
    // and works for both issue_comment and review_comment origins.
    await client.post(
      `/repos/${ctx.owner}/${ctx.repo}/issues/${ctx.prNumber}/comments`,
      { body }
    );
  } catch (err) {
    logger.warn("prCommandService: reply failed", { err: (err as Error).message });
  }
}

// ────────────────────────────────────────────────────────────────────────────
// Permission resolution
// ────────────────────────────────────────────────────────────────────────────

async function resolveCommenterRole(
  orgId: string,
  githubUsername: string
): Promise<Role | null> {
  const user = await prisma.user.findFirst({
    where: { username: githubUsername },
    select: { id: true },
  });
  if (!user) return null;
  const member = await prisma.organizationMember.findFirst({
    where: { userId: user.id, orgId },
    select: { role: true },
  });
  return (member?.role as Role | undefined) ?? null;
}

function roleAllows(role: Role | null, min: Role): boolean {
  if (!role) return false;
  return (ROLE_RANK[role] ?? 0) >= ROLE_RANK[min];
}

// ────────────────────────────────────────────────────────────────────────────
// Command handlers
// ────────────────────────────────────────────────────────────────────────────

async function mostRecentScanJobForPr(ctx: CommandContext) {
  return prisma.scanJob.findFirst({
    where: {
      orgId:        ctx.orgId,
      repositoryId: ctx.repositoryId,
      prNumber:     ctx.prNumber,
    },
    orderBy: { createdAt: "desc" },
  });
}

async function handleIgnore(ctx: CommandContext, findingId: string): Promise<string> {
  await prisma.finding.updateMany({
    where: { id: findingId, orgId: ctx.orgId },
    data:  { status: "FALSE_POSITIVE", resolvedAt: new Date() },
  });
  const job = await mostRecentScanJobForPr(ctx);
  if (job) await refreshCheckRun(job.id).catch(() => undefined);
  return `Marked finding as **FALSE_POSITIVE** (requested by @${ctx.commentAuthor}).`;
}

async function handleAcceptRisk(
  ctx: CommandContext, findingId: string, reason: string
): Promise<string> {
  if (reason.length < 3) {
    return "`/accept-risk` requires a reason (min 3 chars).";
  }
  const finding = await prisma.finding.findFirst({
    where: { id: findingId, orgId: ctx.orgId },
    select: { fingerprint: true },
  });
  if (!finding) return "Finding not found.";

  // Resolve the platform user id for audit attribution
  const user = await prisma.user.findFirst({
    where: { username: ctx.commentAuthor },
    select: { id: true },
  });
  if (!user) return "Platform user record missing — cannot create suppression.";

  await suppressions.create({
    orgId:        ctx.orgId,
    fingerprint:  finding.fingerprint,
    reason,
    approvedById: user.id,
  });
  const job = await mostRecentScanJobForPr(ctx);
  if (job) await refreshCheckRun(job.id).catch(() => undefined);
  return `Risk accepted — suppression created (reason: _${reason}_).`;
}

async function handleSnooze(
  ctx: CommandContext, findingId: string, args: string
): Promise<string> {
  const deadline = parseDuration(args);
  if (!deadline) return "Usage: `/snooze <Nd|Nh|Nw>` e.g. `/snooze 7d`.";
  await prisma.finding.updateMany({
    where: { id: findingId, orgId: ctx.orgId },
    data:  { snoozedUntil: deadline },
  });
  const job = await mostRecentScanJobForPr(ctx);
  if (job) await refreshCheckRun(job.id).catch(() => undefined);
  return `Snoozed until **${deadline.toISOString().slice(0, 16)}Z**.`;
}

async function handleSeverity(
  ctx: CommandContext, findingId: string, args: string
): Promise<string> {
  const level = args.toUpperCase() as Severity;
  const valid: Severity[] = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"];
  if (!valid.includes(level)) {
    return "Usage: `/severity <CRITICAL|HIGH|MEDIUM|LOW|INFO>`.";
  }
  await prisma.finding.updateMany({
    where: { id: findingId, orgId: ctx.orgId },
    data:  { severity: level },
  });
  const job = await mostRecentScanJobForPr(ctx);
  if (job) await refreshCheckRun(job.id).catch(() => undefined);
  return `Severity overridden to **${level}**.`;
}

async function handleRescan(ctx: CommandContext): Promise<string> {
  const repo = await prisma.repository.findUnique({
    where: { id: ctx.repositoryId },
    select: {
      id: true, orgId: true, url: true, defaultBranch: true,
      githubAppInstallationId: true, fullName: true,
    },
  });
  if (!repo) return "Repository record missing.";

  // Resolve current PR head for accurate incremental scan
  let headSha: string | undefined;
  let baseSha: string | undefined;
  let headBranch: string | undefined;
  let changedFiles: string[] = [];

  const client = await installationClient(ctx.installationId);
  if (client) {
    try {
      const pr = await client.get(`/repos/${ctx.owner}/${ctx.repo}/pulls/${ctx.prNumber}`);
      headSha    = pr.data?.head?.sha;
      baseSha    = pr.data?.base?.sha;
      headBranch = pr.data?.head?.ref;
    } catch { /* best-effort */ }
    try {
      changedFiles = await listPullRequestFiles(ctx.installationId, ctx.owner, ctx.repo, ctx.prNumber);
    } catch { /* best-effort */ }
  }

  await triggerScan({
    orgId:         repo.orgId,
    targetType:    "REPOSITORY",
    targetId:      repo.id,
    scanTypes:     ["SAST", "SCA", "SECRET", "IAC"],
    repoUrl:       repo.url,
    branch:        headBranch ?? repo.defaultBranch,
    triggerType:   "PULL_REQUEST",
    commitSha:     headSha,
    baseCommitSha: baseSha,
    prNumber:      ctx.prNumber,
    changedFiles,
  });
  return `Re-scan queued for PR #${ctx.prNumber} (${changedFiles.length} changed files).`;
}

// ────────────────────────────────────────────────────────────────────────────
// Entry point
// ────────────────────────────────────────────────────────────────────────────

/**
 * Top-level dispatcher. Called by the webhook router for issue_comment and
 * pull_request_review_comment events. Returns quickly — all GitHub-bound work
 * (reactions, replies) is fire-and-forget.
 */
export async function handleCommentEvent(ctx: CommandContext): Promise<void> {
  const cmd = parseCommand(ctx.commentBody);
  if (!cmd) return; // not a command — ignore silently

  // Ignore commands from the bot itself (usernames ending in [bot])
  if (/\[bot\]$/.test(ctx.commentAuthor)) return;

  await react(ctx, "eyes");

  // Permission check
  const role = await resolveCommenterRole(ctx.orgId, ctx.commentAuthor);
  if (!roleAllows(role, MIN_ROLE[cmd.name])) {
    await react(ctx, "-1");
    const msg = role
      ? `@${ctx.commentAuthor} your role **${role}** cannot run \`/${cmd.name}\` (requires **${MIN_ROLE[cmd.name]}+**).`
      : `@${ctx.commentAuthor} please log into the DevSecOps platform and link your GitHub account first.`;
    await reply(ctx, msg);
    return;
  }

  // /help and /rescan don't need a finding
  if (cmd.name === "help") {
    await reply(ctx, HELP_TEXT);
    await react(ctx, "+1");
    return;
  }
  if (cmd.name === "rescan") {
    try {
      const msg = await handleRescan(ctx);
      await reply(ctx, msg);
      await react(ctx, "rocket");
    } catch (err) {
      logger.error("prCommandService.rescan failed", { err: (err as Error).message });
      await react(ctx, "-1");
      await reply(ctx, `Rescan failed: ${(err as Error).message}`);
    }
    return;
  }

  // Finding-scoped commands need the marker from the parent bot comment
  const findingId = extractFindingId(ctx.parentBody);
  if (!findingId) {
    await react(ctx, "confused");
    await reply(ctx,
      `\`/${cmd.name}\` must be used as a **reply to the bot's inline review comment**. ` +
      `Use \`/help\` for more info.`);
    return;
  }

  // Confirm finding belongs to this org
  const finding = await prisma.finding.findFirst({
    where: { id: findingId, orgId: ctx.orgId },
    select: { id: true },
  });
  if (!finding) {
    await react(ctx, "-1");
    await reply(ctx, `Finding \`${findingId}\` not found in this organization.`);
    return;
  }

  try {
    let msg: string;
    switch (cmd.name) {
      case "ignore":      msg = await handleIgnore(ctx, findingId); break;
      case "accept-risk": msg = await handleAcceptRisk(ctx, findingId, cmd.args); break;
      case "snooze":      msg = await handleSnooze(ctx, findingId, cmd.args); break;
      case "severity":    msg = await handleSeverity(ctx, findingId, cmd.args); break;
      default:            return;
    }
    await reply(ctx, msg);
    await react(ctx, "+1");
    logger.info("prCommandService: command handled", {
      cmd: cmd.name, findingId, author: ctx.commentAuthor, pr: ctx.prNumber,
    });
  } catch (err) {
    logger.error("prCommandService: handler failed", {
      cmd: cmd.name, err: (err as Error).message,
    });
    await react(ctx, "-1");
    await reply(ctx, `\`/${cmd.name}\` failed: ${(err as Error).message}`);
  }
}
