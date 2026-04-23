/**
 * BreachLens AI Chat Service
 *
 * Builds a security context from the org's findings and streams
 * responses from Ollama token-by-token via a callback.
 */

import { AIServiceName } from "@prisma/client";
import prisma from "../db.js";
import { logger } from "../logger.js";
import { invokeAI, AIError } from "./aiClient.js";

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

  logger.info(`[chat] response for org ${orgId} (${messages.length} messages) via aiClient`);

  // The aiClient abstraction is non-streaming; the SSE route still expects to
  // emit tokens, so we buffer the full response and deliver it as a single
  // chunk. Streaming support can be added later by extending invokeAI.
  try {
    const result = await invokeAI({
      service:         AIServiceName.CHAT,
      orgId,
      system:          `${SYSTEM_PROMPT}\n\n${context}`,
      messages:        messages.map((m) => ({ role: m.role, content: m.content })),
      maxOutputTokens: 400,
      temperature:     0.3,
      timeoutMs:       600_000,
    });
    if (result.data) onToken(result.data);
    onDone();
  } catch (err: unknown) {
    if (err instanceof AIError) {
      logger.error(`[chat] invokeAI failed: ${err.kind} — ${err.message}`);
      const friendly =
        err.kind === "INVALID_OUTPUT"
          ? "AI returned an unreadable response — please try again."
          : `AI service is unavailable (${err.kind}). Check that the configured provider is reachable.`;
      onError(new Error(friendly));
      return;
    }
    const msg = err instanceof Error ? err.message : String(err);
    logger.error(`[chat] AI request failed: ${msg}`);
    onError(new Error(`AI service unavailable: ${msg}`));
  }
}
