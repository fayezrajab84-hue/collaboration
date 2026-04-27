/**
 * Backfill compliance mappings for existing findings (Phase 16 Slice B).
 *
 * Run after:
 *   - Initial Phase 16 deployment (maps the historical finding backlog)
 *   - Editing seedComplianceControls.ts (re-runs the mapper against the
 *     new control definitions; adds new links, removes obsolete ones)
 *
 * Idempotent — safe to run repeatedly. Adds + removes only the deltas
 * via complianceMappingService.backfillMappings.
 *
 * Usage:
 *   docker compose exec -T -w //app/apps/api api node --import tsx \
 *     src/migrations/backfillComplianceMappings.ts
 *
 *   # Scope to one org:
 *   docker compose exec -T -w //app/apps/api api node --import tsx \
 *     src/migrations/backfillComplianceMappings.ts <orgId>
 */

import { backfillMappings } from "../services/complianceMappingService.js";
import { logger } from "../logger.js";

async function main() {
  const orgId = process.argv[2];
  const result = await backfillMappings({ orgId });

  // eslint-disable-next-line no-console
  console.log(JSON.stringify({
    scope:           orgId ? `org:${orgId}` : "all-orgs",
    findingsScanned: result.findings,
    mappingsCreated: result.mappingsCreated,
    mappingsRemoved: result.mappingsRemoved,
  }, null, 2));
}

main()
  .then(() => process.exit(0))
  .catch((err) => {
    logger.error("[backfill-compliance] failed", { error: (err as Error).message });
    process.exit(1);
  });
