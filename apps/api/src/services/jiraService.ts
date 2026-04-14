import axios from "axios";
import { logger } from "../logger.js";
import type { Finding } from "@prisma/client";

interface JiraConfig {
  host: string;
  email: string;
  apiToken: string;
  projectKey: string;
  issueType: string;
}

const SEVERITY_TO_PRIORITY: Record<string, string> = {
  CRITICAL: "Highest",
  HIGH: "High",
  MEDIUM: "Medium",
  LOW: "Low",
  INFO: "Low",
};

export async function createJiraIssue(
  cfg: JiraConfig,
  finding: Finding
): Promise<{ key: string; url: string } | null> {
  try {
    const auth = Buffer.from(`${cfg.email}:${cfg.apiToken}`).toString("base64");
    const baseUrl = cfg.host.replace(/\/$/, "");

    const payload = {
      fields: {
        project: { key: cfg.projectKey },
        summary: `[${finding.scanType}] ${finding.title}`,
        description: {
          type: "doc",
          version: 1,
          content: [
            {
              type: "paragraph",
              content: [{ type: "text", text: finding.description }],
            },
            ...(finding.filePath
              ? [
                  {
                    type: "paragraph",
                    content: [
                      { type: "text", text: `Location: ${finding.filePath}:${finding.lineStart ?? ""}` },
                    ],
                  },
                ]
              : []),
            ...(finding.cveId
              ? [
                  {
                    type: "paragraph",
                    content: [{ type: "text", text: `CVE: ${finding.cveId}` }],
                  },
                ]
              : []),
          ],
        },
        issuetype: { name: cfg.issueType },
        priority: { name: SEVERITY_TO_PRIORITY[finding.severity] ?? "Medium" },
        labels: ["devsecops", `severity-${finding.severity.toLowerCase()}`, finding.scanType.toLowerCase()],
      },
    };

    const res = await axios.post(`${baseUrl}/rest/api/3/issue`, payload, {
      headers: {
        Authorization: `Basic ${auth}`,
        "Content-Type": "application/json",
      },
      timeout: 15_000,
    });

    const key: string = res.data.key;
    return { key, url: `${baseUrl}/browse/${key}` };
  } catch (err) {
    logger.error("Failed to create Jira issue", { error: (err as Error).message });
    return null;
  }
}
