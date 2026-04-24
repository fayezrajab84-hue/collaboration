import { Router } from "express";
import { createHmac, timingSafeEqual } from "crypto";
import prisma from "../../db.js";
import { decrypt } from "../../services/encryptionService.js";
import { triggerScan } from "../../services/scanService.js";
import { logger } from "../../logger.js";
import { config } from "../../config.js";
import { listPullRequestFiles, installationClient } from "../../github/app.js";
import { handleCommentEvent, type CommandContext } from "../../services/prCommandService.js";

const router = Router();

// Raw body needed for HMAC verification
router.use("/github", (req, _res, next) => {
  let body = "";
  req.setEncoding("utf8");
  req.on("data", (chunk) => { body += chunk; });
  req.on("end", () => {
    (req as unknown as { rawBody: string }).rawBody = body;
    try {
      req.body = JSON.parse(body);
    } catch {
      req.body = {};
    }
    next();
  });
});

/**
 * Verify HMAC against either the per-repo PAT-webhook secret or the
 * GitHub App's global webhook secret — whichever matches wins.
 */
function verifySignature(
  rawBody:  string,
  signature: string | undefined,
  candidateSecrets: string[]
): boolean {
  if (!signature) return false;
  const sigBuf = Buffer.from(signature);
  for (const secret of candidateSecrets) {
    if (!secret) continue;
    const expected = `sha256=${createHmac("sha256", secret).update(rawBody).digest("hex")}`;
    const expBuf = Buffer.from(expected);
    if (sigBuf.length === expBuf.length && timingSafeEqual(sigBuf, expBuf)) {
      return true;
    }
  }
  return false;
}

router.post("/github", async (req, res) => {
  const event     = req.headers["x-github-event"] as string;
  const signature = req.headers["x-hub-signature-256"] as string | undefined;
  const rawBody   = (req as unknown as { rawBody: string }).rawBody;

  // ── Installation lifecycle — GitHub App install / uninstall ────────────
  if (event === "installation" || event === "installation_repositories") {
    // App-signed events: verify against the global App webhook secret
    if (!verifySignature(rawBody, signature, [config.GITHUB_APP_WEBHOOK_SECRET ?? ""])) {
      logger.warn("GitHub App webhook signature invalid", { event });
      res.status(401).json({ error: "Invalid signature" });
      return;
    }

    const action         = req.body?.action as string;
    const installationId = req.body?.installation?.id as number | undefined;
    const repositories   = (req.body?.repositories ?? req.body?.repositories_added ?? []) as Array<{
      id: number;
      full_name: string;
    }>;

    if (installationId && repositories.length > 0) {
      if (action === "created" || action === "added") {
        // Associate installation ID with any matching Repository rows
        const githubIds = repositories.map((r) => r.id);
        const updated = await prisma.repository.updateMany({
          where: { githubId: { in: githubIds } },
          data:  { githubAppInstallationId: installationId },
        });
        logger.info("GitHub App installed/added", {
          installationId, action, repoCount: repositories.length, matched: updated.count,
        });
      } else if (action === "deleted" || action === "removed") {
        const githubIds = repositories.map((r) => r.id);
        await prisma.repository.updateMany({
          where: { githubId: { in: githubIds } },
          data:  { githubAppInstallationId: null },
        });
        logger.info("GitHub App removed", { installationId, action, repoCount: githubIds.length });
      }
    }
    res.status(200).json({ ok: true });
    return;
  }

  // ── Repository-level events (push / pull_request) ──────────────────────
  const repoId: number | undefined = req.body?.repository?.id;
  if (!repoId) { res.status(200).json({ ok: true }); return; }

  const repo = await prisma.repository.findUnique({
    where: { githubId: repoId },
    select: {
      id: true, orgId: true, defaultBranch: true, webhookSecret: true, url: true,
      fullName: true, githubAppInstallationId: true,
    },
  });

  if (!repo) { res.status(200).json({ ok: true }); return; }

  // Allow either the per-repo PAT webhook secret OR the App's global secret
  const candidates: string[] = [];
  if (repo.webhookSecret) {
    try { candidates.push(decrypt(repo.webhookSecret)); } catch { /* bad cipher — skip */ }
  }
  if (config.GITHUB_APP_WEBHOOK_SECRET) candidates.push(config.GITHUB_APP_WEBHOOK_SECRET);

  if (candidates.length > 0 && !verifySignature(rawBody, signature, candidates)) {
    logger.warn("GitHub webhook signature mismatch", { repoId });
    res.status(401).json({ error: "Invalid signature" });
    return;
  }

  // ── Push → full scan on default branch (existing behaviour) ─────────────
  if (event === "push") {
    const ref: string = req.body?.ref ?? "";
    const branch = ref.replace("refs/heads/", "");
    const commitSha: string | undefined = req.body?.after;
    const baseSha:   string | undefined = req.body?.before;

    if (branch === repo.defaultBranch || branch === "main" || branch === "master") {
      try {
        await triggerScan({
          orgId: repo.orgId,
          targetType: "REPOSITORY",
          targetId: repo.id,
          scanTypes: ["SAST", "SCA", "SECRET", "IAC"],
          repoUrl: repo.url,
          branch,
          triggerType: "PUSH",
          commitSha,
          baseCommitSha: baseSha,
        });
        logger.info("Webhook triggered push scan", { repoId: repo.id, branch, commitSha });
      } catch (err) {
        logger.error("Failed to trigger webhook scan", { error: (err as Error).message });
      }
    }
  }

  // ── Pull request → incremental scan restricted to changed files ────────
  if (event === "pull_request") {
    const action: string = req.body?.action ?? "";
    // Only scan on open / reopened / synchronize (new commits) — ignore close/label/etc.
    if (["opened", "reopened", "synchronize"].includes(action)) {
      const prNumber:   number = req.body?.number ?? req.body?.pull_request?.number;
      const headSha:    string | undefined = req.body?.pull_request?.head?.sha;
      const baseSha:    string | undefined = req.body?.pull_request?.base?.sha;
      const headBranch: string | undefined = req.body?.pull_request?.head?.ref;
      const [owner, name] = repo.fullName.split("/");

      // Resolve changed file list via App (if installed) — else rely on scanner-side fallback
      let changedFiles: string[] = [];
      if (repo.githubAppInstallationId && owner && name && prNumber) {
        try {
          changedFiles = await listPullRequestFiles(
            repo.githubAppInstallationId, owner, name, prNumber
          );
        } catch (err) {
          logger.warn("Failed to list PR files", { prNumber, error: (err as Error).message });
        }
      }

      try {
        await triggerScan({
          orgId: repo.orgId,
          targetType: "REPOSITORY",
          targetId: repo.id,
          scanTypes: ["SAST", "SCA", "SECRET", "IAC"],
          repoUrl: repo.url,
          branch: headBranch ?? repo.defaultBranch,
          triggerType: "PULL_REQUEST",
          commitSha: headSha,
          baseCommitSha: baseSha,
          prNumber,
          changedFiles,
        });
        logger.info("Webhook triggered PR scan", {
          repoId: repo.id, prNumber, headSha, changedFileCount: changedFiles.length,
        });
      } catch (err) {
        logger.error("Failed to trigger PR scan", { error: (err as Error).message });
      }
    }
  }

  // ── Comment events → slash-command dispatcher ─────────────────────────
  if (event === "issue_comment" || event === "pull_request_review_comment") {
    const action: string = req.body?.action ?? "";
    if (action !== "created") { res.status(200).json({ ok: true }); return; }

    const isReviewComment = event === "pull_request_review_comment";
    const commentBody: string = isReviewComment
      ? (req.body?.comment?.body ?? "")
      : (req.body?.comment?.body ?? "");
    const commentAuthor: string =
      req.body?.comment?.user?.login ??
      req.body?.sender?.login ?? "";
    const commentId: number = req.body?.comment?.id;

    // issue_comment only applies when the issue is actually a PR
    const prNumber: number | undefined = isReviewComment
      ? req.body?.pull_request?.number
      : (req.body?.issue?.pull_request ? req.body?.issue?.number : undefined);

    if (!prNumber || !commentBody.trim().startsWith("/")) {
      // Not a PR, or not a slash command — ignore
      res.status(200).json({ ok: true });
      return;
    }

    const installationId = repo.githubAppInstallationId
      ?? req.body?.installation?.id;
    if (!installationId) {
      logger.warn("Comment event received but no App installation id", { repoId: repo.id });
      res.status(200).json({ ok: true });
      return;
    }

    const [owner, name] = repo.fullName.split("/");
    if (!owner || !name) { res.status(200).json({ ok: true }); return; }

    // For review-comment replies, fetch the parent bot comment so we can
    // recover the finding id from its HTML marker.
    let parentBody: string | null = null;
    if (isReviewComment) {
      const inReplyTo: number | undefined = req.body?.comment?.in_reply_to_id;
      if (inReplyTo) {
        try {
          const client = await installationClient(installationId);
          if (client) {
            const r = await client.get(
              `/repos/${owner}/${name}/pulls/comments/${inReplyTo}`
            );
            parentBody = r.data?.body ?? null;
          }
        } catch (err) {
          logger.warn("Failed to fetch parent review comment", { err: (err as Error).message });
        }
      }
    }

    const ctx: CommandContext = {
      installationId,
      owner,
      repo:            name,
      repositoryId:    repo.id,
      orgId:           repo.orgId,
      prNumber,
      commentId,
      commentAuthor,
      commentBody,
      parentBody,
      isReviewComment,
    };

    // Fire-and-forget so webhook returns promptly
    handleCommentEvent(ctx).catch((err) =>
      logger.error("handleCommentEvent failed", { err: (err as Error).message })
    );
  }

  res.status(200).json({ ok: true });
});

export default router;
