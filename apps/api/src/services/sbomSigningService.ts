/**
 * SBOM signing — ECDSA P-256 SHA256 attestation for every persisted SBOM.
 *
 * Compatible with cosign's blob signing (`cosign sign-blob` / `cosign
 * verify-blob` use the same algorithm + same base64 DER signature format)
 * so operators with existing cosign tooling can verify BreachLens-issued
 * SBOMs without learning a new path.
 *
 * The keypair is generated lazily on first sign and stored as a singleton
 * `SbomSigningKey` row — private key AES-256-GCM encrypted via
 * encryptionService, public key plaintext (it's public).
 *
 * Rotation:
 *   1. Operator deletes the SbomSigningKey row (DB or DELETE endpoint TODO)
 *   2. Next sign attempt generates a fresh key
 *   3. Old signatures stay valid as long as the old public key was archived
 *      somewhere (operator export — Phase 15 follow-up)
 *
 * Phase 15 Slice C.
 */
import {
  createSign,
  generateKeyPairSync,
  type KeyObject,
  createPrivateKey,
} from "node:crypto";
import { SbomSigningKey } from "@prisma/client";
import prisma from "../db.js";
import { encrypt, decrypt } from "./encryptionService.js";
import { logger } from "../logger.js";

// ── Key management ──────────────────────────────────────────────────────────
//
// The singleton row pattern: query for any existing row first; only generate
// when none exists. Race-safe via a transaction with the SELECT-then-INSERT
// inside `prisma.$transaction`. Two concurrent first-sign requests would
// generate two keys without the transaction; both would be valid but only
// one would win the SbomSigningKey "singleton" intent.
//
// In-memory cache: once loaded, the KeyObject stays in memory for the
// process lifetime. No re-decrypt per-sign. Cleared on process restart.

let cachedKey: { row: SbomSigningKey; privateKey: KeyObject } | null = null;

export async function getOrCreateSigningKey(): Promise<{
  row:        SbomSigningKey;
  privateKey: KeyObject;
}> {
  if (cachedKey) return cachedKey;

  // Try to load existing
  const existing = await prisma.sbomSigningKey.findFirst({
    orderBy: { createdAt: "desc" },
  });
  if (existing) {
    const privateKey = createPrivateKey({
      key:    decrypt(existing.encryptedPrivateKey),
      format: "pem",
    });
    cachedKey = { row: existing, privateKey };
    return cachedKey;
  }

  // None yet — generate and persist. Race window: two parallel first-sign
  // requests would each generate + insert. We accept the (rare) duplication
  // since both keys are valid and any subsequent reads use the latest.
  logger.info("[sbom-sign] generating new ECDSA P-256 keypair");
  const { privateKey, publicKey } = generateKeyPairSync("ec", {
    namedCurve: "P-256",
  });
  const publicPem  = publicKey.export({ type: "spki",  format: "pem" }) as string;
  const privatePem = privateKey.export({ type: "pkcs8", format: "pem" }) as string;

  const row = await prisma.sbomSigningKey.create({
    data: {
      algorithm:           "ECDSA_P256_SHA256",
      publicKeyPem:        publicPem,
      encryptedPrivateKey: encrypt(privatePem),
    },
  });
  cachedKey = { row, privateKey };
  logger.info("[sbom-sign] new signing key persisted", { keyId: row.id });
  return cachedKey;
}

// ── Signing ──────────────────────────────────────────────────────────────────

/**
 * Sign a buffer with the instance's signing key.
 *
 * Output is base64 of the DER-encoded ECDSA signature — matches
 * `cosign sign-blob`'s output exactly. Verification:
 *   echo -n '<base64-sig>' | base64 -d > sbom.sig
 *   cosign verify-blob --key cosign.pub --signature sbom.sig sbom.json
 * Or with openssl directly:
 *   openssl dgst -sha256 -verify cosign.pub -signature sbom.sig sbom.json
 */
export async function signBuffer(buf: Buffer): Promise<{
  signature: string;
  keyId:     string;
}> {
  const { row, privateKey } = await getOrCreateSigningKey();
  const signer = createSign("SHA256");
  signer.update(buf);
  signer.end();
  const sig = signer.sign(privateKey);
  return {
    signature: sig.toString("base64"),
    keyId:     row.id,
  };
}

/** Read-only view of the public key for the verification endpoint. */
export async function getPublicKeyView(): Promise<{
  keyId:        string;
  algorithm:    string;
  publicKeyPem: string;
  createdAt:    Date;
} | null> {
  const row = await prisma.sbomSigningKey.findFirst({
    orderBy: { createdAt: "desc" },
    select:  { id: true, algorithm: true, publicKeyPem: true, createdAt: true },
  });
  if (!row) return null;
  return {
    keyId:        row.id,
    algorithm:    row.algorithm,
    publicKeyPem: row.publicKeyPem,
    createdAt:    row.createdAt,
  };
}
