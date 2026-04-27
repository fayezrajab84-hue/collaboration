/**
 * secretBridge — Phase 27 Slice B.
 *
 * Links a SECRET finding (TruffleHog hit on a hardcoded credential in a repo)
 * to a CONTAINER finding that mentions the same secret value. The classic
 * chain: developer commits an API key to a repo → docker build bakes the
 * file into the image → key gets surfaced in container scans + maybe also in
 * runtime via Wazuh. All three findings collapse into one chain.
 *
 * Implementation note: we never store the secret value in plaintext — the
 * SHA-256 hash from `evidence.secret_hash` is what matches across stages.
 * Scanners are responsible for hashing before persisting; this bridge just
 * compares hashes.
 */
import type { Finding } from "@prisma/client";
import type { Bridge, BridgeMatch } from "./bridgeInterface.js";

export const secretBridge: Bridge = {
  id: "secret",
  match(a: Finding, b: Finding): BridgeMatch | null {
    if (a.orgId !== b.orgId) return null;

    // Pull a comparable hash from each finding. Bridge is symmetric — if the
    // hash matches, both sides describe the same leaked credential.
    const aHash = extractSecretHash(a);
    const bHash = extractSecretHash(b);
    if (!aHash || !bHash) return null;
    if (aHash !== bHash) return null;

    // Same finding (already deduped by fingerprint) — skip.
    if (a.id === b.id) return null;

    // Highest confidence — secret hashes are essentially unique IDs. If
    // they match, the underlying secret is the same and the chain is real.
    return {
      bridgeType: "secret",
      confidence: "CONFIRMED",
      reason: `Same secret value (sha256 ${aHash.slice(0, 8)}…) found across multiple stages`,
    };
  },
};

const HASH_KEYS = ["secret_hash", "secretHash", "value_hash", "valueHash"];

function extractSecretHash(f: Finding): string | null {
  // We require at least one finding side to be a SECRET-class scanner result;
  // the other side might be a CONTAINER finding that also surfaces a hashed
  // secret in its evidence.
  if (f.scanType !== "SECRET" && f.scanType !== "CONTAINER") return null;

  const ev  = (f.evidence  ?? {}) as Record<string, unknown>;
  const raw = (f.rawOutput ?? {}) as Record<string, unknown>;
  for (const k of HASH_KEYS) {
    const v = ev[k] ?? raw[k];
    if (typeof v === "string" && /^[a-f0-9]{64}$/i.test(v)) return v.toLowerCase();
  }
  return null;
}
