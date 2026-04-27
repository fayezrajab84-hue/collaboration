/**
 * applicationService — Phase 27.5 Application boundary CRUD + component
 * assignment + slug derivation.
 *
 * Why a dedicated service: the route handler stays thin while the business
 * rules (slug uniqueness per org, cross-org rejection on bulk component
 * assignment, automatic re-correlation when membership changes) live in
 * one place that can be unit-tested in isolation.
 */
import prisma from "../db.js";
import type {
  ApplicationEnv,
  Criticality,
} from "@devsecops/types";

// ── Slug helpers ──────────────────────────────────────────────────────

/**
 * Derive a url-safe slug from a name. Lowercased, alphanumerics + dashes,
 * collapsed-runs, trimmed-edges. Falls back to "app" if name has no
 * representable characters.
 */
export function deriveSlug(name: string): string {
  const cleaned = name
    .toLowerCase()
    .replace(/[^a-z0-9]+/g, "-")
    .replace(/-+/g, "-")
    .replace(/^-|-$/g, "");
  return cleaned.length > 0 ? cleaned : "app";
}

/**
 * Pick a slug that's unique within the org. If the operator passed one,
 * we trust it (and let Prisma's unique constraint reject duplicates).
 * Otherwise we derive from name and append a numeric suffix on conflict.
 */
export async function pickSlug(orgId: string, name: string, requested?: string): Promise<string> {
  const base = requested ? deriveSlug(requested) : deriveSlug(name);
  let candidate = base;
  let suffix = 2;
  // Bound the loop — if the operator has 100+ apps with the same name,
  // we surface the original conflict via DB error rather than spinning forever.
  for (let i = 0; i < 100; i++) {
    const existing = await prisma.application.findFirst({
      where: { orgId, slug: candidate },
      select: { id: true },
    });
    if (!existing) return candidate;
    candidate = `${base}-${suffix}`;
    suffix += 1;
  }
  return candidate; // fall through; DB will reject if still conflicting
}

// ── Component assignment ──────────────────────────────────────────────

export class ApplicationComponentValidationError extends Error {
  details: Record<string, unknown>;
  constructor(message: string, details: Record<string, unknown> = {}) {
    super(message);
    this.name = "ApplicationComponentValidationError";
    this.details = details;
  }
}

export function isApplicationComponentValidationError(
  e: unknown,
): e is ApplicationComponentValidationError {
  return e instanceof ApplicationComponentValidationError;
}

/**
 * Replace the application's component membership atomically. Each input
 * array is the FULL desired set for its kind; assets not listed get
 * un-assigned (their `applicationId` set to null), assets newly listed get
 * assigned. Cross-org references rejected hard.
 *
 * Returns the resulting component summary for the API response.
 */
export async function assignComponents(
  applicationId: string,
  orgId: string,
  input: { repositoryIds?: string[]; containerIds?: string[]; domainIds?: string[] },
): Promise<{
  repositories: Array<{ id: string; fullName: string }>;
  containers:   Array<{ id: string; imageRef: string }>;
  domains:      Array<{ id: string; domain:  string }>;
}> {
  // Validate every requested ID exists and belongs to the same org.
  if (input.repositoryIds) {
    const found = await prisma.repository.findMany({
      where: { id: { in: input.repositoryIds }, orgId },
      select: { id: true },
    });
    const foundIds = new Set(found.map((r) => r.id));
    const missing  = input.repositoryIds.filter((id) => !foundIds.has(id));
    if (missing.length > 0) {
      throw new ApplicationComponentValidationError(
        "Some repository IDs do not exist in this organization",
        { missing, kind: "repository" },
      );
    }
  }
  if (input.containerIds) {
    const found = await prisma.container.findMany({
      where: { id: { in: input.containerIds }, orgId },
      select: { id: true },
    });
    const foundIds = new Set(found.map((c) => c.id));
    const missing  = input.containerIds.filter((id) => !foundIds.has(id));
    if (missing.length > 0) {
      throw new ApplicationComponentValidationError(
        "Some container IDs do not exist in this organization",
        { missing, kind: "container" },
      );
    }
  }
  if (input.domainIds) {
    const found = await prisma.domain.findMany({
      where: { id: { in: input.domainIds }, orgId },
      select: { id: true },
    });
    const foundIds = new Set(found.map((d) => d.id));
    const missing  = input.domainIds.filter((id) => !foundIds.has(id));
    if (missing.length > 0) {
      throw new ApplicationComponentValidationError(
        "Some domain IDs do not exist in this organization",
        { missing, kind: "domain" },
      );
    }
  }

  // Apply the new membership atomically. updateMany over the org's existing
  // members + the requested set covers both directions (assign + un-assign).
  await prisma.$transaction(async (tx) => {
    if (input.repositoryIds) {
      // un-assign: anything currently in this app but not in the new list
      await tx.repository.updateMany({
        where: { orgId, applicationId, NOT: { id: { in: input.repositoryIds } } },
        data:  { applicationId: null },
      });
      // assign: everything in the new list (also clears any previous app)
      await tx.repository.updateMany({
        where: { id: { in: input.repositoryIds }, orgId },
        data:  { applicationId },
      });
    }
    if (input.containerIds) {
      await tx.container.updateMany({
        where: { orgId, applicationId, NOT: { id: { in: input.containerIds } } },
        data:  { applicationId: null },
      });
      await tx.container.updateMany({
        where: { id: { in: input.containerIds }, orgId },
        data:  { applicationId },
      });
    }
    if (input.domainIds) {
      await tx.domain.updateMany({
        where: { orgId, applicationId, NOT: { id: { in: input.domainIds } } },
        data:  { applicationId: null },
      });
      await tx.domain.updateMany({
        where: { id: { in: input.domainIds }, orgId },
        data:  { applicationId },
      });
    }
  });

  return loadComponents(applicationId, orgId);
}

export async function loadComponents(applicationId: string, orgId: string) {
  const [repositories, containers, domains] = await Promise.all([
    prisma.repository.findMany({
      where: { applicationId, orgId },
      select: { id: true, fullName: true },
      orderBy: { addedAt: "asc" },
    }),
    prisma.container.findMany({
      where: { applicationId, orgId },
      select: { id: true, imageRef: true },
      orderBy: { addedAt: "asc" },
    }),
    prisma.domain.findMany({
      where: { applicationId, orgId },
      select: { id: true, domain: true },
      orderBy: { addedAt: "asc" },
    }),
  ]);
  return { repositories, containers, domains };
}

// ── Counts for list view ──────────────────────────────────────────────

export async function loadComponentCounts(applicationId: string, orgId: string) {
  const [repositories, containers, domains] = await Promise.all([
    prisma.repository.count({ where: { applicationId, orgId } }),
    prisma.container.count({ where: { applicationId, orgId } }),
    prisma.domain.count({ where: { applicationId, orgId } }),
  ]);
  return { repositories, containers, domains };
}

/**
 * Aggregate severity counts across an application's components. Powers
 * the per-app risk roll-up on the Applications list page.
 */
export async function loadFindingCounts(applicationId: string, orgId: string) {
  const componentIds = await prisma.$transaction(async (tx) => {
    const [repos, containers, domains] = await Promise.all([
      tx.repository.findMany({ where: { applicationId, orgId }, select: { id: true } }),
      tx.container.findMany({  where: { applicationId, orgId }, select: { id: true } }),
      tx.domain.findMany({     where: { applicationId, orgId }, select: { id: true } }),
    ]);
    return {
      repos:      repos.map((r) => r.id),
      containers: containers.map((c) => c.id),
      domains:    domains.map((d) => d.id),
    };
  });

  if (
    componentIds.repos.length === 0 &&
    componentIds.containers.length === 0 &&
    componentIds.domains.length === 0
  ) {
    return { CRITICAL: 0, HIGH: 0, MEDIUM: 0, LOW: 0 };
  }

  const rows = await prisma.finding.groupBy({
    by: ["severity"],
    where: {
      orgId,
      status: { not: "FALSE_POSITIVE" },
      OR: [
        { repositoryId: { in: componentIds.repos } },
        { containerId:  { in: componentIds.containers } },
        { domainId:     { in: componentIds.domains } },
      ],
    },
    _count: { id: true },
  });

  const out = { CRITICAL: 0, HIGH: 0, MEDIUM: 0, LOW: 0 };
  for (const r of rows) {
    if (r.severity in out) (out as Record<string, number>)[r.severity] = r._count.id;
  }
  return out;
}

// ── Type-safe wrappers for the validators ─────────────────────────────

export const ALL_APPLICATION_ENVS: ApplicationEnv[] = ["DEVELOPMENT", "STAGING", "PRODUCTION"];
export const ALL_CRITICALITIES:    Criticality[]    = ["CRITICAL", "HIGH", "MEDIUM", "LOW"];
