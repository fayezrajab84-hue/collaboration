/**
 * SBOM service — proxies CycloneDX or SPDX SBOM generation to the scanner.
 *
 * Repo:      clones and runs `trivy fs --format <fmt>`.
 * Container: runs `trivy image --format <fmt> <imageRef>`.
 *
 * Returns the parsed JSON object. The Express route sets the right
 * filename/content-type headers based on the format.
 */
import axios from "axios";
import { createHash } from "node:crypto";
import { SbomFormat as PrismaSbomFormat } from "@prisma/client";
import prisma from "../db.js";
import { config } from "../config.js";
import { logger } from "../logger.js";
import { decrypt } from "./encryptionService.js";
import { signBuffer } from "./sbomSigningService.js";

export type SbomFormat = "cyclonedx" | "spdx";

/** Content-Type + filename suffix per format. Used by the route to set headers. */
export const SBOM_FORMAT_META: Record<SbomFormat, { contentType: string; suffix: string }> = {
  cyclonedx: { contentType: "application/vnd.cyclonedx+json", suffix: "cdx.json"  },
  spdx:      { contentType: "application/spdx+json",          suffix: "spdx.json" },
};

export async function generateRepoSbom(input: {
  repoUrl:           string;
  branch:            string;
  encryptedGitToken: string | null;
  format?:           SbomFormat;
}): Promise<unknown> {
  const gitToken = input.encryptedGitToken ? decrypt(input.encryptedGitToken) : undefined;
  const resp = await axios.post(
    `${config.SCANNER_URL}/sbom`,
    {
      target_type: "REPOSITORY",
      format:      input.format ?? "cyclonedx",
      repo_url:    input.repoUrl,
      branch:      input.branch,
      git_token:   gitToken,
    },
    { timeout: 660_000 }, // 11 min — trivy+clone can take a while
  );
  return resp.data;
}

export async function generateContainerSbom(input: {
  imageRef: string;
  format?:  SbomFormat;
}): Promise<unknown> {
  const resp = await axios.post(
    `${config.SCANNER_URL}/sbom`,
    {
      target_type: "CONTAINER",
      format:      input.format ?? "cyclonedx",
      image_ref:   input.imageRef,
    },
    { timeout: 660_000 },
  );
  return resp.data;
}

// ── Persistence (Phase 15 Slice B) ───────────────────────────────────────────
// Called fire-and-forget by the scan worker after each successful SCA scan.
// Generates the CycloneDX SBOM and stores it as a `Sbom` row indexed by
// (repositoryId, format, generatedAt DESC). The download endpoint queries
// this cache first; only falls back to on-demand generation when no row
// exists (e.g. repos scanned before this slice landed, or SPDX requests
// since we only persist CycloneDX automatically).
//
// Dedup: if the new SBOM is byte-identical to the latest stored one for
// this (repo, format), we skip the insert and just bump generatedAt on the
// existing row. Avoids unbounded JSONB growth for repos with stable deps.
//
// Format note: only CycloneDX is auto-persisted on each scan. SPDX would
// double the per-scan Trivy cost; rare enough that on-demand generation
// from the download endpoint is acceptable.

const PERSISTED_FORMATS: SbomFormat[] = ["cyclonedx"];

const FORMAT_TO_PRISMA: Record<SbomFormat, PrismaSbomFormat> = {
  cyclonedx: PrismaSbomFormat.CYCLONEDX,
  spdx:      PrismaSbomFormat.SPDX,
};

/** Read the component count from a parsed CycloneDX or SPDX document. */
function countComponents(doc: unknown, format: SbomFormat): number {
  const obj = doc as Record<string, unknown>;
  if (format === "cyclonedx") {
    const comps = obj["components"];
    return Array.isArray(comps) ? comps.length : 0;
  }
  // SPDX
  const pkgs = obj["packages"];
  return Array.isArray(pkgs) ? pkgs.length : 0;
}

export async function persistRepoSbom(input: {
  orgId:             string;
  repositoryId:      string;
  scanJobId:         string;
  repoUrl:           string;
  branch:            string;
  encryptedGitToken: string | null;
}): Promise<void> {
  for (const format of PERSISTED_FORMATS) {
    try {
      const doc = await generateRepoSbom({
        repoUrl:           input.repoUrl,
        branch:            input.branch,
        encryptedGitToken: input.encryptedGitToken,
        format,
      });

      // Canonical-ish hash: stringify with sorted keys so trivial reordering
      // doesn't churn the cache. Strip Trivy's serialNumber + generated-at
      // fields before hashing — they change on every run regardless of repo
      // content (would break the dedup we want).
      const stripped = stripVolatileFields(doc, format);
      const contentHash = createHash("sha256")
        .update(JSON.stringify(stripped))
        .digest("hex");

      // Look up the latest row for this (repo, format) to dedupe.
      const latest = await prisma.sbom.findFirst({
        where:   { repositoryId: input.repositoryId, format: FORMAT_TO_PRISMA[format] },
        orderBy: { generatedAt: "desc" },
        select:  { id: true, contentHash: true },
      });

      if (latest && latest.contentHash === contentHash) {
        await prisma.sbom.update({
          where: { id: latest.id },
          data:  { generatedAt: new Date(), scanJobId: input.scanJobId },
        });
        logger.info("[sbom] dedup hit — bumped generatedAt", {
          repositoryId: input.repositoryId, format, sbomId: latest.id,
        });
        // If the existing row has no signature (created pre-Slice C, or sign
        // failed last time), backfill it now. The dedup path is the cheapest
        // place to do this — we already know the document hasn't changed.
        await maybeBackfillSignature(latest.id);
        continue;
      }

      const componentCount = countComponents(doc, format);
      const created = await prisma.sbom.create({
        data: {
          orgId:          input.orgId,
          repositoryId:   input.repositoryId,
          scanJobId:      input.scanJobId,
          format:         FORMAT_TO_PRISMA[format],
          document:       doc as object,
          componentCount,
          contentHash,
        },
        select: { id: true },
      });
      logger.info("[sbom] persisted", {
        repositoryId: input.repositoryId, format, components: componentCount, sbomId: created.id,
      });

      // ── Sign (Phase 15 Slice C) ──────────────────────────────────────────
      // Critical detail: Postgres JSONB normalises documents — strips
      // whitespace, may reorder object keys. So `JSON.stringify(doc)` does
      // NOT match `JSON.stringify(<retrieved JSONB>)` byte-for-byte. The
      // download endpoint serves the post-JSONB form. To make the signature
      // verify against what the endpoint serves, we must sign the
      // post-JSONB bytes — fetch the row back, stringify, then sign.
      try {
        const persisted = await prisma.sbom.findUniqueOrThrow({
          where:  { id: created.id },
          select: { document: true },
        });
        const documentBytes  = Buffer.from(JSON.stringify(persisted.document, null, 2), "utf8");
        const { signature, keyId } = await signBuffer(documentBytes);
        await prisma.sbom.update({
          where: { id: created.id },
          data:  { signature, signatureKeyId: keyId, signedAt: new Date() },
        });
        logger.info("[sbom] signed", { sbomId: created.id, keyId });
      } catch (signErr) {
        // Signing failure leaves the row unsigned — download endpoint just
        // omits the X-Sbom-Signature header. Loud-but-harmless degradation.
        logger.warn("[sbom] sign failed", {
          sbomId: created.id, error: (signErr as Error).message,
        });
      }
    } catch (err) {
      logger.warn("[sbom] persist failed", {
        repositoryId: input.repositoryId, format, error: (err as Error).message,
      });
    }
  }
}

/**
 * Sign an existing Sbom row if it isn't signed yet. Used by the dedup path
 * to backfill signatures for rows created before Slice C landed (they have
 * the document but no signature/keyId).
 */
async function maybeBackfillSignature(sbomId: string): Promise<void> {
  try {
    const row = await prisma.sbom.findUnique({
      where:  { id: sbomId },
      select: { signature: true, document: true },
    });
    if (!row || row.signature) return;
    const documentBytes = Buffer.from(JSON.stringify(row.document, null, 2), "utf8");
    const { signature, keyId } = await signBuffer(documentBytes);
    await prisma.sbom.update({
      where: { id: sbomId },
      data:  { signature, signatureKeyId: keyId, signedAt: new Date() },
    });
    logger.info("[sbom] signature backfilled", { sbomId, keyId });
  } catch (err) {
    logger.warn("[sbom] signature backfill failed", { sbomId, error: (err as Error).message });
  }
}

/** Get the latest persisted SBOM for a repo + format, or null.
 *
 * Returns the signature + keyId when present so the download endpoint can
 * emit `X-Sbom-Signature` headers. Both null when the row was created
 * before signing landed or signing failed.
 */
export async function getLatestRepoSbom(input: {
  repositoryId: string;
  format:       SbomFormat;
}): Promise<{
  document:       unknown;
  generatedAt:    Date;
  componentCount: number;
  signature:      string | null;
  signatureKeyId: string | null;
} | null> {
  const row = await prisma.sbom.findFirst({
    where:   { repositoryId: input.repositoryId, format: FORMAT_TO_PRISMA[input.format] },
    orderBy: { generatedAt: "desc" },
    select:  {
      document: true, generatedAt: true, componentCount: true,
      signature: true, signatureKeyId: true,
    },
  });
  if (!row) return null;
  return {
    document:       row.document,
    generatedAt:    row.generatedAt,
    componentCount: row.componentCount,
    signature:      row.signature,
    signatureKeyId: row.signatureKeyId,
  };
}

/**
 * CycloneDX puts a unique `serialNumber` + a fresh `metadata.timestamp` on
 * every run; SPDX has `documentNamespace` (random URL fragment) + `creationInfo
 * .created`. Strip them so dedup fires when the actual component list is
 * unchanged scan-over-scan.
 */
function stripVolatileFields(doc: unknown, format: SbomFormat): unknown {
  const obj = JSON.parse(JSON.stringify(doc)) as Record<string, unknown>;
  if (format === "cyclonedx") {
    delete obj["serialNumber"];
    const meta = obj["metadata"] as Record<string, unknown> | undefined;
    if (meta) delete meta["timestamp"];
  } else {
    delete obj["documentNamespace"];
    const ci = obj["creationInfo"] as Record<string, unknown> | undefined;
    if (ci) delete ci["created"];
  }
  return obj;
}
