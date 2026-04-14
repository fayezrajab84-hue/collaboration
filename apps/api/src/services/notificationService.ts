import prisma from "../db.js";
import { logger } from "../logger.js";
import { decrypt } from "./encryptionService.js";
import { sendFindingAlert as sendSlackAlert } from "./slackService.js";
import { sendFindingAlert as sendTeamsAlert } from "./teamsService.js";
import type { Finding } from "@prisma/client";

const ALERT_SEVERITIES = new Set(["CRITICAL", "HIGH"]);

/**
 * Send Slack and Teams alerts for new CRITICAL/HIGH findings after a scan completes.
 * Called by scanWorker when completedScans === totalScans.
 */
export async function notifyNewFindings(
  orgId: string,
  newFindings: Finding[]
): Promise<void> {
  const alertable = newFindings.filter((f) => ALERT_SEVERITIES.has(f.severity));
  if (alertable.length === 0) return;

  // Load active integrations for the org in parallel
  const [slackIntegration, teamsIntegration] = await Promise.all([
    prisma.integration.findUnique({
      where: { orgId_type: { orgId, type: "SLACK" } },
    }),
    prisma.integration.findUnique({
      where: { orgId_type: { orgId, type: "MICROSOFT_TEAMS" } },
    }),
  ]);

  const slackUrl = slackIntegration?.isActive
    ? tryDecrypt((slackIntegration.encryptedData as Record<string, string>)["webhookUrl"])
    : null;

  const teamsUrl = teamsIntegration?.isActive
    ? tryDecrypt((teamsIntegration.encryptedData as Record<string, string>)["webhookUrl"])
    : null;

  if (!slackUrl && !teamsUrl) return;

  logger.info("Sending finding notifications", {
    orgId,
    count: alertable.length,
    slack: !!slackUrl,
    teams: !!teamsUrl,
  });

  // Send alerts concurrently; individual failures are swallowed inside each service
  const tasks: Promise<void>[] = [];
  for (const finding of alertable) {
    if (slackUrl) tasks.push(sendSlackAlert(slackUrl, finding));
    if (teamsUrl) tasks.push(sendTeamsAlert(teamsUrl, finding));
  }

  await Promise.allSettled(tasks);
}

function tryDecrypt(value: string | undefined): string | null {
  if (!value) return null;
  try {
    return decrypt(value);
  } catch {
    logger.error("Failed to decrypt webhook URL for notification");
    return null;
  }
}
