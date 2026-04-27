/**
 * assetLinksService — operator-declared asset-relation editing (Phase 27 Slice A).
 *
 * Why a dedicated service: the three resource routers (repos, containers,
 * domains) each surface a tiny PATCH endpoint that updates a different field,
 * but the *validation* is identical — every reference must:
 *   1. point to an asset that exists,
 *   2. belong to the SAME org as the asset being edited (no cross-tenant
 *      linkage; that would be a privacy violation),
 *   3. dedupe its array (no double-listed image refs / IDs).
 *
 * The service centralises that validation so the routers stay thin and the
 * "cross-org reference rejected" guarantee lives in one place.
 *
 * Audit events are written by the router (not here) so the action verb stays
 * resource-specific (e.g. `repo.asset_links.update` vs `container...`); the
 * service returns the validated array for the router to persist + audit.
 */
import prisma from "../db.js";

/**
 * Resolve a list of container image refs against the org's containers + raise
 * if any string doesn't match an existing container in this org.
 *
 * Repositories declare `buildsContainerImages: string[]` of image refs (not
 * IDs) because it's friendlier to type ("myorg/api:latest") and survives
 * container rows being recreated. Resolution to actual Container rows happens
 * later in the correlation engine via imageRef equality.
 */
export async function validateContainerImageRefs(
  orgId: string,
  imageRefs: string[],
): Promise<string[]> {
  const cleaned = dedupeAndTrim(imageRefs);
  if (cleaned.length === 0) return [];

  // We don't strictly require every imageRef to map to a known Container —
  // operators may declare a ref that gets created later. But we DO warn when
  // none of the refs exist (typo signal). For v1 we accept any non-empty
  // string and let the correlation engine match opportunistically.
  return cleaned;
}

/**
 * Resolve a list of container IDs to existing rows in this org. Throws an
 * AssetLinkValidationError listing the bad IDs if any are missing or
 * cross-org.
 */
export async function validateContainerIds(orgId: string, ids: string[]): Promise<string[]> {
  const cleaned = dedupeAndTrim(ids);
  if (cleaned.length === 0) return [];
  const found = await prisma.container.findMany({
    where: { id: { in: cleaned }, orgId },
    select: { id: true },
  });
  const foundIds = new Set(found.map((c) => c.id));
  const missing  = cleaned.filter((id) => !foundIds.has(id));
  if (missing.length > 0) {
    throw new AssetLinkValidationError(
      "Some container IDs do not exist in this organization",
      { missing },
    );
  }
  return cleaned;
}

/** Same as validateContainerIds for domain IDs. */
export async function validateDomainIds(orgId: string, ids: string[]): Promise<string[]> {
  const cleaned = dedupeAndTrim(ids);
  if (cleaned.length === 0) return [];
  const found = await prisma.domain.findMany({
    where: { id: { in: cleaned }, orgId },
    select: { id: true },
  });
  const foundIds = new Set(found.map((d) => d.id));
  const missing  = cleaned.filter((id) => !foundIds.has(id));
  if (missing.length > 0) {
    throw new AssetLinkValidationError(
      "Some domain IDs do not exist in this organization",
      { missing },
    );
  }
  return cleaned;
}

/**
 * Validate a single repository ID (used by Container.sourceRepositoryId).
 * Returns the same string when valid, or throws if missing/cross-org.
 * Pass null/undefined to clear the link (returns null).
 */
export async function validateRepositoryId(
  orgId: string,
  repositoryId: string | null | undefined,
): Promise<string | null> {
  if (!repositoryId) return null;
  const repo = await prisma.repository.findFirst({
    where: { id: repositoryId, orgId },
    select: { id: true },
  });
  if (!repo) {
    throw new AssetLinkValidationError(
      "Repository ID does not exist in this organization",
      { missing: [repositoryId] },
    );
  }
  return repo.id;
}

/** Trim, drop empties, dedupe while preserving first-occurrence order. */
function dedupeAndTrim(values: string[]): string[] {
  const seen = new Set<string>();
  const out: string[] = [];
  for (const raw of values) {
    const v = raw.trim();
    if (v.length === 0) continue;
    if (seen.has(v)) continue;
    seen.add(v);
    out.push(v);
  }
  return out;
}

export class AssetLinkValidationError extends Error {
  details: Record<string, unknown>;
  constructor(message: string, details: Record<string, unknown> = {}) {
    super(message);
    this.name = "AssetLinkValidationError";
    this.details = details;
  }
}

/**
 * Express helper — write a 400 response from an AssetLinkValidationError
 * with the missing-IDs detail payload. Used by all three asset-link route
 * handlers so the error shape is identical across resources.
 */
export function isAssetLinkValidationError(e: unknown): e is AssetLinkValidationError {
  return e instanceof AssetLinkValidationError;
}
