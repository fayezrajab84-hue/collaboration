import axios from "axios";
import { logger } from "../logger.js";
import { config } from "../config.js";
import type { Finding } from "@prisma/client";

const SEVERITY_COLORS: Record<string, string> = {
  CRITICAL: "#7B0000",
  HIGH: "#D94F00",
  MEDIUM: "#E6820E",
  LOW: "#2E8B57",
  INFO: "#808080",
};

export async function sendFindingAlert(webhookUrl: string, finding: Finding): Promise<void> {
  try {
    const color = SEVERITY_COLORS[finding.severity] ?? "#808080";
    const viewUrl = `${config.FRONTEND_URL}/findings?id=${finding.id}`;

    await axios.post(
      webhookUrl,
      {
        text: `🔐 *${finding.severity} Security Finding*`,
        attachments: [
          {
            color,
            blocks: [
              {
                type: "section",
                text: {
                  type: "mrkdwn",
                  text: `*${finding.title}*\n${finding.description.substring(0, 300)}`,
                },
              },
              {
                type: "section",
                fields: [
                  { type: "mrkdwn", text: `*Severity:* ${finding.severity}` },
                  { type: "mrkdwn", text: `*Type:* ${finding.scanType}` },
                  { type: "mrkdwn", text: `*Scanner:* ${finding.scanner}` },
                  ...(finding.filePath
                    ? [{ type: "mrkdwn", text: `*Location:* \`${finding.filePath}:${finding.lineStart ?? ""}\`` }]
                    : []),
                  ...(finding.cveId
                    ? [{ type: "mrkdwn", text: `*CVE:* ${finding.cveId}` }]
                    : []),
                ],
              },
              {
                type: "actions",
                elements: [
                  {
                    type: "button",
                    text: { type: "plain_text", text: "View Finding" },
                    url: viewUrl,
                    style: "danger",
                  },
                ],
              },
            ],
          },
        ],
      },
      { timeout: 10_000 }
    );
  } catch (err) {
    logger.error("Failed to send Slack alert", { error: (err as Error).message });
  }
}
