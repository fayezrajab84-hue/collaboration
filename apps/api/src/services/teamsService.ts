import axios from "axios";
import { logger } from "../logger.js";
import { config } from "../config.js";
import type { Finding } from "@prisma/client";

const SEVERITY_COLORS: Record<string, string> = {
  CRITICAL: "FF0000",
  HIGH: "FF6600",
  MEDIUM: "FFA500",
  LOW: "008000",
  INFO: "808080",
};

export async function sendFindingAlert(webhookUrl: string, finding: Finding): Promise<void> {
  try {
    const color = SEVERITY_COLORS[finding.severity] ?? "808080";
    const viewUrl = `${config.FRONTEND_URL}/findings?id=${finding.id}`;

    const payload = {
      "@type": "MessageCard",
      "@context": "https://schema.org/extensions",
      summary: `${finding.severity} Security Finding: ${finding.title}`,
      themeColor: color,
      sections: [
        {
          activityTitle: `🔐 ${finding.severity} — ${finding.title}`,
          activitySubtitle: `Scanner: ${finding.scanner} | Type: ${finding.scanType}`,
          text: finding.description.substring(0, 500),
          facts: [
            { name: "Severity", value: finding.severity },
            { name: "Scan Type", value: finding.scanType },
            { name: "Scanner", value: finding.scanner },
            ...(finding.cveId ? [{ name: "CVE", value: finding.cveId }] : []),
            ...(finding.filePath
              ? [{ name: "Location", value: `${finding.filePath}:${finding.lineStart ?? ""}` }]
              : []),
          ],
        },
      ],
      potentialAction: [
        {
          "@type": "OpenUri",
          name: "View Finding",
          targets: [{ os: "default", uri: viewUrl }],
        },
      ],
    };

    await axios.post(webhookUrl, payload, {
      headers: { "Content-Type": "application/json" },
      timeout: 10_000,
    });
  } catch (err) {
    logger.error("Failed to send Teams alert", { error: (err as Error).message });
  }
}
