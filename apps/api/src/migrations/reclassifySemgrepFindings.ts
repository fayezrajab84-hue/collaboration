/**
 * One-time migration: reclassify Semgrep findings that were stored as SAST
 * but whose rule IDs indicate they are IAC (terraform.*, cloudformation.*,
 * kubernetes.*, dockerfile.*) or SECRET (generic.secrets.*, secrets.*).
 *
 * Semgrep with --config auto runs rules for SAST, IaC, and secrets in a
 * single pass. Before this fix, all results were stored under scanType=SAST.
 *
 * Only scanType is updated here. Fingerprints are left as-is because they
 * were computed by the SAST merge logic (sast-rule:…) and changing them would
 * create duplicates on the next scan. On the next full re-scan, findingService
 * will create correctly-fingerprinted IAC/SECRET entries; the old stale ones
 * will be resolved by the FIXED-sweep worker.
 *
 * Safe to re-run — idempotent.
 *
 * Run:
 *   docker exec admiring-hertz-api-1 sh -c \
 *     "node --import tsx/esm /app/apps/api/src/migrations/reclassifySemgrepFindings.ts"
 */

import prisma from "../db.js";
import { logger } from "../logger.js";

const IAC_PREFIXES = [
  "terraform.",
  "cloudformation.",
  "kubernetes.",
  "dockerfile.",
  "docker.",
  "helm.",
  "ansible.",
  "arm.",
  "bicep.",
  "github-actions.",
];

const SECRET_PREFIXES = [
  "generic.secrets.",
  "secrets.",
  "trufflehog.",
  "tokens.",
  "credentials.",
];

function classifyScanType(checkId: string): "IAC" | "SECRET" | null {
  const cid = checkId.toLowerCase();
  if (IAC_PREFIXES.some(p => cid.startsWith(p))) return "IAC";
  if (SECRET_PREFIXES.some(p => cid.startsWith(p))) return "SECRET";
  return null; // correctly classified as SAST — no change needed
}

async function run() {
  logger.info("[reclassify-semgrep] starting scan type reclassification");

  // All semgrep SAST findings — check each rule ID
  const findings = await prisma.finding.findMany({
    where: { scanType: "SAST", scanner: "semgrep" },
    select: { id: true, rawOutput: true, ruleId: true },
  });

  logger.info(`[reclassify-semgrep] examining ${findings.length} semgrep SAST findings`);

  let iac     = 0;
  let secret  = 0;
  let skipped = 0;

  for (const f of findings) {
    // ruleId is stored directly on the finding; fall back to rawOutput check_id
    const checkId =
      f.ruleId
      ?? ((f.rawOutput as Record<string, unknown>)["check_id"] as string | undefined)
      ?? ((f.rawOutput as Record<string, unknown>)["primary"] as Record<string, unknown> | undefined)?.["check_id"] as string | undefined
      ?? "";

    const newType = classifyScanType(checkId);
    if (!newType) { skipped++; continue; }

    await prisma.finding.update({
      where: { id: f.id },
      data:  { scanType: newType },
    });

    if (newType === "IAC") iac++;
    else secret++;
  }

  logger.info(
    `[reclassify-semgrep] done — ${iac} → IAC, ${secret} → SECRET, ${skipped} already SAST`,
  );
}

run()
  .then(() => process.exit(0))
  .catch((err) => { console.error(err); process.exit(1); });
