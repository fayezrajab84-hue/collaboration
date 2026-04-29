/**
 * repoAutoDiscoveryService — Phase A7 CI-from-GitHub-context.
 *
 * Auto-creates a Repository row when a CI workflow triggers a scan
 * with just the GitHub context (no repo-id input). Mirrors the
 * canonical "Add Repository" flow in routes/repos/router.ts but
 * skips the webhook registration step — CI is the trigger; we
 * don't also need GitHub push webhooks firing.
 *
 * Concurrency safety:
 *   The findOrCreate is racey if two CI runs trigger nearly
 *   simultaneously on a fresh repo. We rely on the Postgres UNIQUE
 *   constraint on Repository.githubId — the second insert fails with
 *   a P2002, we catch it, and refetch the now-existing row. Result
 *   is the same as if the first request had won, just with a wasted
 *   GitHub API call.
 *
 * Auth model:
 *   The user whose API token authenticated the request supplies the
 *   GitHub OAuth access token (their stored `accessToken` from the
 *   original passport-github login). For private-repo auto-discovery
 *   to succeed, that user must have access to the repo.
 */
import prisma from "../db.js";
import * as gh from "../github/client.js";
import { randomBytes } from "node:crypto";
import { encrypt } from "./encryptionService.js";
import { logger } from "../logger.js";

export interface AutoDiscoveryResult {
  repository: {
    id:            string;
    fullName:      string;
    defaultBranch: string;
    isPrivate:     boolean;
  };
  /** True when the row was created by this call (vs. already existed). */
  newlyCreated: boolean;
}

export async function findOrCreateRepository(opts: {
  orgId:           string;
  userId:          string;
  githubFullName:  string;       // "owner/name" — preferred lookup key
}): Promise<AutoDiscoveryResult> {
  const { orgId, userId, githubFullName } = opts;
  const [owner, name] = githubFullName.split("/");
  if (!owner || !name) {
    throw new Error(`Invalid GitHub full name: ${githubFullName}`);
  }

  // Fast path — already onboarded under this org.
  const existing = await prisma.repository.findFirst({
    where: { orgId, fullName: githubFullName },
  });
  if (existing) {
    return {
      repository: {
        id:            existing.id,
        fullName:      existing.fullName,
        defaultBranch: existing.defaultBranch,
        isPrivate:     existing.isPrivate,
      },
      newlyCreated: false,
    };
  }

  // Fetch from GitHub — verifies access AND gives us the numeric
  // githubId we use as the unique cross-org key.
  const dbUser = await prisma.user.findUnique({
    where:  { id: userId },
    select: { accessToken: true },
  });
  if (!dbUser?.accessToken) {
    throw new Error(
      `User ${userId} has no stored GitHub OAuth token; cannot auto-discover ` +
      `${githubFullName}. Operator must log into BreachLens via GitHub OAuth ` +
      `at least once before minting an API token for CI.`,
    );
  }

  const ghRepo = await gh.getRepo(dbUser.accessToken, owner, name);

  // Webhook secret minted even though we don't register a webhook —
  // future Phase A8 GitHub App can pick up the same secret if/when the
  // App is installed. Cheap, no harm in pre-generating.
  const webhookSecret = randomBytes(32).toString("hex");
  const encryptedWebhookSecret = encrypt(webhookSecret);

  try {
    const repo = await prisma.repository.create({
      data: {
        orgId,
        githubId:      ghRepo.id,
        fullName:      ghRepo.full_name,
        url:           ghRepo.html_url,
        defaultBranch: ghRepo.default_branch,
        isPrivate:     ghRepo.private,
        language:      ghRepo.language,
        webhookSecret: encryptedWebhookSecret,
      },
    });

    logger.info(
      `[auto-discover] Created Repository ${repo.id} (${repo.fullName}) for org ${orgId}`,
    );

    return {
      repository: {
        id:            repo.id,
        fullName:      repo.fullName,
        defaultBranch: repo.defaultBranch,
        isPrivate:     repo.isPrivate,
      },
      newlyCreated: true,
    };
  } catch (err) {
    // P2002 = unique constraint violation. Race with another CI run
    // for the same repo — refetch and return the winning row.
    if ((err as { code?: string }).code === "P2002") {
      const racedRow = await prisma.repository.findUnique({
        where: { githubId: ghRepo.id },
      });
      if (racedRow) {
        return {
          repository: {
            id:            racedRow.id,
            fullName:      racedRow.fullName,
            defaultBranch: racedRow.defaultBranch,
            isPrivate:     racedRow.isPrivate,
          },
          newlyCreated: false,
        };
      }
    }
    throw err;
  }
}
