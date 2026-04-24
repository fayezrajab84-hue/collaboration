/**
 * Policy engine — evaluates a Policy (set of PolicyRules) against a ScanJob's
 * findings and returns a pass/fail verdict used by the PR check run publisher.
 *
 * Rule types (stored as `PolicyRuleType` enum + JSON `config`):
 *
 *   SEVERITY_THRESHOLD   { severity: "CRITICAL"|"HIGH"|"MEDIUM"|"LOW"; maxCount: number }
 *     Fails when findings of `severity` (or higher) exceed `maxCount`.
 *
 *   BLOCK_ON_NEW_ONLY    { severity: "CRITICAL"|"HIGH"; maxCount: number }
 *     Like SEVERITY_THRESHOLD but only counts findings whose `firstSeen` is
 *     after the scanJob's base-commit timestamp (i.e. introduced by the PR).
 *     Pre-existing debt does not block the PR.
 *
 *   SLA_DAYS             { severity: "CRITICAL"|"HIGH"; maxDays: number }
 *     Fails when any OPEN finding of this severity was first seen more than
 *     `maxDays` ago — enforces remediation SLAs.
 *
 *   IGNORE_DEV_DEPS      { enabled: true }
 *     Drops SCA findings whose package path is under a dev-only manifest
 *     (devDependencies in package.json, tests/ requirements, etc.) before any
 *     other rule runs.
 *
 *   SCAN_TYPE_REQUIRED   { scanTypes: ScanType[] }
 *     Fails the run when the ScanJob didn't execute the listed scan types
 *     (e.g. require SAST + SCA on every PR).
 *
 * Resolution precedence (caller-supplied):
 *   1. repository.policyId
 *   2. any Policy where isActive && repoIds contains repoId
 *   3. any Policy where isActive && isDefault
 *   4. null — no policy → always pass
 */
import prisma from "../db.js";
import { logger } from "../logger.js";
import type { Finding, Policy, PolicyRule } from "@prisma/client";

export type Verdict = "success" | "failure" | "neutral";

export interface PolicyViolation {
  ruleType:    string;
  message:     string;
  findingIds:  string[];
}

export interface PolicyEvaluation {
  verdict:     Verdict;
  policyId:    string | null;
  policyName:  string | null;
  violations:  PolicyViolation[];
  passed:      boolean;
}

const SEVERITY_ORDER = { CRITICAL: 4, HIGH: 3, MEDIUM: 2, LOW: 1, INFO: 0 } as const;
type SeverityKey = keyof typeof SEVERITY_ORDER;

function sevAtLeast(a: string, min: string): boolean {
  return (SEVERITY_ORDER[a as SeverityKey] ?? 0) >= (SEVERITY_ORDER[min as SeverityKey] ?? 0);
}

/** Resolve the effective policy for a repository. Returns null if none. */
export async function resolvePolicy(
  orgId: string,
  repoId: string,
  explicitPolicyId: string | null
): Promise<(Policy & { rules: PolicyRule[] }) | null> {
  // 1. Explicit per-repo assignment
  if (explicitPolicyId) {
    const p = await prisma.policy.findUnique({
      where: { id: explicitPolicyId },
      include: { rules: true },
    });
    if (p && p.isActive) return p;
  }

  // 2. Any policy whose repoIds contains this repoId
  const assigned = await prisma.policy.findFirst({
    where: { orgId, isActive: true, repoIds: { has: repoId } },
    include: { rules: true },
  });
  if (assigned) return assigned;

  // 3. The org-wide default
  const def = await prisma.policy.findFirst({
    where: { orgId, isActive: true, isDefault: true },
    include: { rules: true },
  });
  return def;
}

/**
 * Evaluate a policy against a scan's findings.
 * Only OPEN findings count — ACKNOWLEDGED / FALSE_POSITIVE / FIXED are
 * considered resolved for policy purposes.
 */
export function evaluatePolicy(
  policy:   (Policy & { rules: PolicyRule[] }) | null,
  findings: Finding[],
  ctx: {
    scanTypesRun: string[];
    baseCommitDate?: Date | null;
  }
): PolicyEvaluation {
  if (!policy) {
    return { verdict: "neutral", policyId: null, policyName: null, violations: [], passed: true };
  }

  const violations: PolicyViolation[] = [];

  // ── Pre-filter: IGNORE_DEV_DEPS strips SCA findings under dev manifests ──
  const ignoreDevDeps = policy.rules.some(
    (r) => r.type === "IGNORE_DEV_DEPS" && (r.config as { enabled?: boolean })?.enabled !== false
  );
  const DEV_PATH_HINTS = ["devDependencies", "test/", "tests/", "__tests__/", "/dev-", "-dev."];

  let filtered = findings.filter((f) => f.status === "OPEN");
  if (ignoreDevDeps) {
    filtered = filtered.filter((f) => {
      if (f.scanType !== "SCA") return true;
      const hay = `${f.filePath ?? ""} ${f.packageName ?? ""}`.toLowerCase();
      return !DEV_PATH_HINTS.some((h) => hay.includes(h.toLowerCase()));
    });
  }

  // ── Iterate enforcement rules ────────────────────────────────────────────
  for (const rule of policy.rules) {
    const cfg = (rule.config ?? {}) as Record<string, unknown>;

    switch (rule.type) {
      case "IGNORE_DEV_DEPS":
        break; // already applied above

      case "SEVERITY_THRESHOLD": {
        const minSev   = (cfg.severity as string) ?? "CRITICAL";
        const maxCount = Number(cfg.maxCount ?? 0);
        const matched  = filtered.filter((f) => sevAtLeast(f.severity, minSev));
        if (matched.length > maxCount) {
          violations.push({
            ruleType: rule.type,
            message: `${matched.length} ${minSev}+ finding(s) exceed the maximum of ${maxCount}`,
            findingIds: matched.map((f) => f.id),
          });
        }
        break;
      }

      case "BLOCK_ON_NEW_ONLY": {
        const minSev   = (cfg.severity as string) ?? "HIGH";
        const maxCount = Number(cfg.maxCount ?? 0);
        const cutoff   = ctx.baseCommitDate?.getTime() ?? Date.now();
        const matched  = filtered.filter(
          (f) => sevAtLeast(f.severity, minSev) && f.firstSeen.getTime() >= cutoff - 60_000
        );
        if (matched.length > maxCount) {
          violations.push({
            ruleType: rule.type,
            message: `${matched.length} new ${minSev}+ finding(s) introduced by this PR exceed ${maxCount}`,
            findingIds: matched.map((f) => f.id),
          });
        }
        break;
      }

      case "SLA_DAYS": {
        const minSev  = (cfg.severity as string) ?? "HIGH";
        const maxDays = Number(cfg.maxDays ?? 30);
        const cutoff  = Date.now() - maxDays * 24 * 60 * 60 * 1000;
        const matched = filtered.filter(
          (f) => sevAtLeast(f.severity, minSev) && f.firstSeen.getTime() < cutoff
        );
        if (matched.length > 0) {
          violations.push({
            ruleType: rule.type,
            message: `${matched.length} ${minSev}+ finding(s) older than ${maxDays} days — SLA breach`,
            findingIds: matched.map((f) => f.id),
          });
        }
        break;
      }

      case "SCAN_TYPE_REQUIRED": {
        const required = (cfg.scanTypes as string[]) ?? [];
        const missing  = required.filter((t) => !ctx.scanTypesRun.includes(t));
        if (missing.length > 0) {
          violations.push({
            ruleType: rule.type,
            message: `Required scan types not run: ${missing.join(", ")}`,
            findingIds: [],
          });
        }
        break;
      }

      default:
        logger.warn("policyService: unknown rule type", { type: rule.type });
    }
  }

  const passed  = violations.length === 0;
  return {
    verdict:    passed ? "success" : "failure",
    policyId:   policy.id,
    policyName: policy.name,
    violations,
    passed,
  };
}
