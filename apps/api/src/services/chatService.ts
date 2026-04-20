/**
 * BreachLens AI Chat Service
 *
 * Builds a security context from the org's findings and streams
 * responses from Ollama token-by-token via a callback.
 */

import axios from "axios";
import prisma from "../db.js";
import { config } from "../config.js";
import { logger } from "../logger.js";

// ── Types ─────────────────────────────────────────────────────────────────────

export interface ChatMessage {
  role: "user" | "assistant";
  content: string;
}

export interface OrgStats {
  totalOpen: number;
  critical: number;
  high: number;
  medium: number;
  low: number;
}

// ── System prompt ─────────────────────────────────────────────────────────────

const SYSTEM_PROMPT = `You are BreachLens AI, a cybersecurity analyst in the BreachLens DevSecOps platform. Help teams understand and fix vulnerabilities from SAST, SCA, secrets, IaC, container, DAST, and pentest scans.
Rules: be concise and actionable, use markdown (bullets, **bold** for severity, \`code\` for commands), reference findings by severity and scan type. Only answer security-related questions.`;

// ── Context builder ───────────────────────────────────────────────────────────

export async function buildOrgStats(orgId: string): Promise<OrgStats> {
  const counts = await prisma.finding.groupBy({
    by: ["severity"],
    where: { orgId, status: { notIn: ["FALSE_POSITIVE", "FIXED"] } },
    _count: true,
  });

  const map: Record<string, number> = {};
  let total = 0;
  for (const c of counts) {
    map[c.severity] = c._count;
    total += c._count;
  }

  return {
    totalOpen: total,
    critical: map["CRITICAL"] ?? 0,
    high: map["HIGH"] ?? 0,
    medium: map["MEDIUM"] ?? 0,
    low: map["LOW"] ?? 0,
  };
}

async function buildContext(orgId: string, userMessage: string): Promise<string> {
  const [severityCounts, statusCounts, scanTypeCounts, totalOpen, topFindings] =
    await Promise.all([
      prisma.finding.groupBy({
        by: ["severity"],
        where: { orgId, status: { notIn: ["FALSE_POSITIVE"] } },
        _count: true,
      }),
      prisma.finding.groupBy({
        by: ["status"],
        where: { orgId },
        _count: true,
      }),
      prisma.finding.groupBy({
        by: ["scanType"],
        where: { orgId, status: "OPEN" },
        _count: true,
      }),
      prisma.finding.count({ where: { orgId, status: "OPEN" } }),
      // Always include top critical/high open findings
      prisma.finding.findMany({
        where: { orgId, status: "OPEN", severity: { in: ["CRITICAL", "HIGH"] } },
        orderBy: [{ severity: "asc" }, { firstSeen: "desc" }],
        take: 8,
        include: {
          repository: { select: { fullName: true } },
          container:  { select: { imageRef: true } },
          domain:     { select: { domain: true } },
        },
      }),
    ]);

  // Keyword search for findings relevant to the user's question
  const keywords = userMessage
    .toLowerCase()
    .replace(/[^a-z0-9\s]/g, " ")
    .split(/\s+/)
    .filter((w) => w.length > 3)
    .slice(0, 6);

  let searchFindings: typeof topFindings = [];
  if (keywords.length > 0) {
    searchFindings = await prisma.finding.findMany({
      where: {
        orgId,
        OR: keywords.flatMap((kw) => [
          { title:       { contains: kw, mode: "insensitive" as const } },
          { description: { contains: kw, mode: "insensitive" as const } },
          { cveId:       { contains: kw, mode: "insensitive" as const } },
          { packageName: { contains: kw, mode: "insensitive" as const } },
          { ruleId:      { contains: kw, mode: "insensitive" as const } },
        ]),
      },
      take: 5,
      orderBy: [{ severity: "asc" }, { lastSeen: "desc" }],
      include: {
        repository: { select: { fullName: true } },
        container:  { select: { imageRef: true } },
        domain:     { select: { domain: true } },
      },
    });
  }

  const formatFinding = (f: typeof topFindings[0]) => {
    const target =
      f.repository?.fullName ?? f.container?.imageRef ?? f.domain?.domain ?? "unknown";
    const cve    = f.cveId ? ` [${f.cveId}]` : "";
    return `  - [${f.severity}] ${f.title}${cve} | ${f.scanType} | ${target} | ${f.status}`;
  };

  const sev   = severityCounts.map((s) => `${s.severity}: ${s._count}`).join(", ");
  const stat  = statusCounts.map((s) => `${s.status}: ${s._count}`).join(", ");
  const types = scanTypeCounts.map((s) => `${s.scanType}: ${s._count}`).join(", ");

  let ctx = `=== BREACHLENS SECURITY CONTEXT ===

OPEN FINDINGS: ${totalOpen} total
By severity  : ${sev || "none"}
By status    : ${stat || "none"}
By scan type : ${types || "none"}

TOP CRITICAL/HIGH OPEN FINDINGS:
${topFindings.length > 0 ? topFindings.map(formatFinding).join("\n") : "  None"}`;

  const extra = searchFindings.filter((sf) => !topFindings.some((tf) => tf.id === sf.id));
  if (extra.length > 0) {
    ctx += `\n\nFINDINGS RELEVANT TO YOUR QUESTION:\n${extra.map(formatFinding).join("\n")}`;
  }

  return ctx;
}

// ── Streaming chat ─────────────────────────────────────────────────────────────

export async function streamChat(
  orgId: string,
  messages: ChatMessage[],
  onToken: (token: string) => void,
  onDone:  () => void,
  onError: (err: Error) => void,
): Promise<void> {
  const userMessage = [...messages].reverse().find((m) => m.role === "user")?.content ?? "";

  let context: string;
  try {
    context = await buildContext(orgId, userMessage);
  } catch (err) {
    logger.error(`[chat] context build failed: ${err}`);
    context = "(Could not load finding context — DB may be unavailable)";
  }

  const ollamaMessages = [
    { role: "system", content: `${SYSTEM_PROMPT}\n\n${context}` },
    ...messages,
  ];

  logger.info(`[chat] streaming response for org ${orgId} (${messages.length} messages)`);

  try {
    const resp = await axios.post(
      `${config.OLLAMA_URL}/api/chat`,
      {
        model:    config.OLLAMA_MODEL,
        messages: ollamaMessages,
        stream:   true,
        options: {
          temperature: 0.3,
          num_predict: 400,
          num_ctx:     2048,
        },
      },
      { responseType: "stream", timeout: 600_000 },
    );

    const stream = resp.data as NodeJS.ReadableStream;
    let finished = false;

    stream.on("data", (chunk: Buffer) => {
      for (const line of chunk.toString().split("\n")) {
        const trimmed = line.trim();
        if (!trimmed) continue;
        try {
          const parsed = JSON.parse(trimmed) as {
            message?: { content?: string };
            done?: boolean;
          };
          const token = parsed.message?.content ?? "";
          if (token) onToken(token);
          if (parsed.done && !finished) {
            finished = true;
            onDone();
          }
        } catch {
          // partial JSON chunk — safe to ignore
        }
      }
    });

    stream.on("end", () => {
      if (!finished) { finished = true; onDone(); }
    });

    stream.on("error", (err: Error) => {
      if (!finished) { finished = true; onError(err); }
    });
  } catch (err: unknown) {
    const msg = err instanceof Error ? err.message : String(err);
    logger.error(`[chat] ollama request failed: ${msg}`);
    onError(new Error(`AI service unavailable: ${msg}`));
  }
}
