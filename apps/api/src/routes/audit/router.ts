/**
 * Audit log read API.
 *
 * Surface the AuditEvent table to org admins for review and SOC 2
 * evidence export. Writes happen via auditService.log() from individual
 * mutation handlers; this router is read-only.
 *
 * Both endpoints require ADMIN+ — audit log content (actor, action,
 * timestamp, IP-via-metadata) is sensitive recon material that lower
 * roles should not enumerate.
 */
import { Router } from "express";
import { z } from "zod";
import { requireRole } from "../../middleware/requireRole.js";
import * as audit from "../../services/auditService.js";

const router = Router();

const filtersSchema = z.object({
  actionPrefix: z.string().min(1).max(100).optional(),
  resourceType: z.string().min(1).max(100).optional(),
  userId:       z.string().min(1).max(100).optional(),
  fromDate:     z.string().datetime().optional(),
  toDate:       z.string().datetime().optional(),
  limit:        z.coerce.number().int().min(1).max(500).optional(),
  offset:       z.coerce.number().int().min(0).optional(),
});

function parseFilters(query: Record<string, unknown>) {
  const parsed = filtersSchema.parse(query);
  return {
    ...(parsed.actionPrefix && { actionPrefix: parsed.actionPrefix }),
    ...(parsed.resourceType && { resourceType: parsed.resourceType }),
    ...(parsed.userId       && { userId:       parsed.userId       }),
    ...(parsed.fromDate     && { fromDate:     new Date(parsed.fromDate) }),
    ...(parsed.toDate       && { toDate:       new Date(parsed.toDate)   }),
    ...(parsed.limit  != null && { limit:  parsed.limit  }),
    ...(parsed.offset != null && { offset: parsed.offset }),
  };
}

// ── GET /api/audit ───────────────────────────────────────────────────────────
// JSON list with filters + pagination. Returns { rows, total, limit, offset }
// so the UI can render "Showing 1–100 of 4321" without a second roundtrip.
router.get("/", requireRole("ADMIN"), async (req, res, next) => {
  try {
    const filters = parseFilters(req.query as Record<string, unknown>);
    const result  = await audit.listEvents(req.orgId!, filters);
    res.json({
      rows:   result.rows,
      total:  result.total,
      limit:  filters.limit  ?? 100,
      offset: filters.offset ?? 0,
    });
  } catch (err) { next(err); }
});

// ── GET /api/audit/export.csv ────────────────────────────────────────────────
// CSV export for compliance evidence. Same filters as the JSON endpoint, but
// the limit cap is raised to 50_000 so a typical year of activity exports in
// one shot. Streams a single response — no chunked download.
router.get("/export.csv", requireRole("ADMIN"), async (req, res, next) => {
  try {
    const filters = parseFilters(req.query as Record<string, unknown>);
    // Override limit cap for export — 50k rows fit comfortably in memory and
    // cover typical org activity over months.
    const result = await audit.listEvents(req.orgId!, { ...filters, limit: 50_000 });

    const filename = `audit-log-${new Date().toISOString().slice(0, 10)}.csv`;
    res.setHeader("Content-Type",        "text/csv; charset=utf-8");
    res.setHeader("Content-Disposition", `attachment; filename="${filename}"`);

    res.write("timestamp,user,action,resourceType,resourceId,metadata\n");
    for (const row of result.rows) {
      const r = row as { createdAt: Date; user: { username?: string } | null; userId: string; action: string; resourceType: string; resourceId: string | null; metadata: unknown };
      res.write([
        r.createdAt.toISOString(),
        csvEscape(r.user?.username ?? r.userId),
        csvEscape(r.action),
        csvEscape(r.resourceType),
        csvEscape(r.resourceId ?? ""),
        csvEscape(JSON.stringify(r.metadata ?? {})),
      ].join(",") + "\n");
    }
    res.end();
  } catch (err) { next(err); }
});

/** RFC 4180-style escape: wrap in double quotes, escape internal quotes. */
function csvEscape(value: string): string {
  if (value === "") return "";
  if (/[",\n\r]/.test(value)) {
    return `"${value.replace(/"/g, '""')}"`;
  }
  return value;
}

export default router;
