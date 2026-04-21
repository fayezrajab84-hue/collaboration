/**
 * Audit service — records mutation events for the UI and compliance.
 *
 * Never throws — audit failures must not break user actions. Errors are logged
 * and swallowed.
 */
import prisma from "../db.js";
import { logger } from "../logger.js";

export interface AuditLogInput {
  orgId:        string;
  userId:       string;
  action:       string;                       // "suppression.create", "finding.status_change", ...
  resourceType: string;                       // "Finding" | "Repository" | "Suppression" | ...
  resourceId?:  string | null;
  metadata?:    Record<string, unknown>;
}

export async function log(input: AuditLogInput): Promise<void> {
  try {
    await prisma.auditEvent.create({
      data: {
        orgId:        input.orgId,
        userId:       input.userId,
        action:       input.action,
        resourceType: input.resourceType,
        resourceId:   input.resourceId ?? null,
        metadata:     (input.metadata ?? {}) as object,
      },
    });
  } catch (err) {
    logger.error("[audit] failed to record event", {
      action: input.action,
      error: (err as Error).message,
    });
  }
}

export async function listEvents(orgId: string, opts: { limit?: number } = {}) {
  const limit = Math.min(opts.limit ?? 100, 500);
  return prisma.auditEvent.findMany({
    where:   { orgId },
    orderBy: { createdAt: "desc" },
    take:    limit,
  });
}
