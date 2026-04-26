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

export interface ListEventsFilters {
  /** Match action by case-sensitive prefix (e.g. "finding." matches all finding actions). */
  actionPrefix?: string;
  /** Filter to specific resource type (e.g. "Finding"). */
  resourceType?: string;
  /** Filter to specific actor. */
  userId?: string;
  /** ISO timestamp lower bound (inclusive). */
  fromDate?: Date;
  /** ISO timestamp upper bound (inclusive). */
  toDate?: Date;
  /** Page size. Hard cap 500. */
  limit?: number;
  /** Offset into the result set. */
  offset?: number;
}

/**
 * List audit events for an org with optional filters.
 *
 * Returns rows + total count so the UI can paginate without a second
 * round-trip. The total counts ALL matching rows, not just the page.
 */
export async function listEvents(orgId: string, filters: ListEventsFilters = {}) {
  const limit  = Math.min(filters.limit ?? 100, 500);
  const offset = Math.max(filters.offset ?? 0, 0);

  const where: Record<string, unknown> = { orgId };
  if (filters.actionPrefix) where["action"]       = { startsWith: filters.actionPrefix };
  if (filters.resourceType) where["resourceType"] = filters.resourceType;
  if (filters.userId)       where["userId"]       = filters.userId;
  if (filters.fromDate || filters.toDate) {
    where["createdAt"] = {
      ...(filters.fromDate && { gte: filters.fromDate }),
      ...(filters.toDate   && { lte: filters.toDate   }),
    };
  }

  const [rawRows, total] = await Promise.all([
    prisma.auditEvent.findMany({
      where,
      orderBy: { createdAt: "desc" },
      take:    limit,
      skip:    offset,
    }),
    prisma.auditEvent.count({ where }),
  ]);

  // Enrich with actor info for the UI. No Prisma relation is defined on
  // AuditEvent yet (would require a migration), so we look up users
  // separately. Cheap because results are paginated.
  const userIds = Array.from(new Set(rawRows.map((r) => r.userId)));
  const users = userIds.length === 0
    ? []
    : await prisma.user.findMany({
        where:  { id: { in: userIds } },
        select: { id: true, username: true, avatarUrl: true },
      });
  const userById = new Map(users.map((u) => [u.id, u]));

  const rows = rawRows.map((r) => ({
    ...r,
    user: userById.get(r.userId) ?? null,
  }));

  return { rows, total };
}
