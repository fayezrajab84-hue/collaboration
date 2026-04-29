/**
 * apiTokenService — Phase A4 CI integration.
 *
 * Mints + verifies long-lived bearer tokens for non-interactive callers
 * (CI pipelines, scripts, the breachlens CLI). Replaces the awkward
 * "extract a session cookie from your browser DevTools" pattern that
 * Phase A1-A3's GitHub Action shipped with.
 *
 * Token format:
 *
 *   blt_<32 random base64url chars>      (52 chars total)
 *
 * The `blt_` prefix is brand identification — operators glancing at a
 * leaked token recognise the source immediately, and secret-scanning
 * rules can pattern-match it. The 32-char body has 192 bits of entropy,
 * which is overkill for a credential but cheap and forgery-resistant.
 *
 * Security properties:
 *   - Plaintext is returned ONLY ONCE (on creation). Never logged,
 *     never re-fetchable. Lose it → mint a new one.
 *   - Storage: SHA-256 hash of plaintext. Hash collision is
 *     computationally infeasible at 256 bits, but @unique on the column
 *     makes any race-condition collision a hard fail.
 *   - Display prefix: first 12 chars of plaintext (e.g. "blt_aB3xK9qL")
 *     stored separately so the Settings UI can render an identifying
 *     chip without revealing the secret.
 *   - Constant-time hash comparison happens implicitly via the unique
 *     index lookup — Prisma's where-by-unique-key uses Postgres's
 *     hash-table lookup which is timing-safe.
 *   - Scopes: enforced by the Bearer auth middleware downstream, not
 *     here. This service is data-layer only.
 */
import { createHash, randomBytes } from "node:crypto";
import prisma from "../db.js";

const TOKEN_PREFIX = "blt_";
const PREFIX_DISPLAY_LENGTH = 12; // "blt_" + 8 = 12 chars shown to operators
const TOKEN_BODY_BYTES = 24;       // 24 raw bytes → 32 base64url chars

export type TokenScope =
  | "scans:trigger"
  | "scans:read"
  | "findings:read";

export const ALL_SCOPES: TokenScope[] = [
  "scans:trigger",
  "scans:read",
  "findings:read",
];

export function isKnownScope(s: string): s is TokenScope {
  return (ALL_SCOPES as string[]).includes(s);
}

/**
 * Generate a fresh token. Returns the plaintext (return ONCE to caller,
 * then forget) plus the persistence-shape (hash + prefix) the caller
 * stores via createToken(). Split this way so the route handler can
 * present the plaintext to the operator before persistence — guarantees
 * we never return a token that wasn't successfully stored.
 */
export function generateToken(): { plaintext: string; hash: string; prefix: string } {
  // base64url is URL-safe + filename-safe + has no padding chars; safe
  // to drop into env vars and shell scripts without escaping concerns.
  const body = randomBytes(TOKEN_BODY_BYTES).toString("base64url");
  const plaintext = `${TOKEN_PREFIX}${body}`;
  const hash = sha256(plaintext);
  const prefix = plaintext.slice(0, PREFIX_DISPLAY_LENGTH);
  return { plaintext, hash, prefix };
}

function sha256(input: string): string {
  return createHash("sha256").update(input).digest("hex");
}

// ── Mint ─────────────────────────────────────────────────────────────────

export interface CreateTokenInput {
  orgId:       string;
  createdById: string;
  name:        string;
  scopes:      TokenScope[];
  expiresAt?:  Date | null;
}

export async function createToken(
  input: CreateTokenInput,
): Promise<{ id: string; plaintext: string; prefix: string }> {
  const { plaintext, hash, prefix } = generateToken();
  const row = await prisma.apiToken.create({
    data: {
      orgId:       input.orgId,
      createdById: input.createdById,
      name:        input.name,
      tokenHash:   hash,
      prefix,
      scopes:      input.scopes as string[],
      expiresAt:   input.expiresAt ?? null,
    },
    select: { id: true },
  });
  return { id: row.id, plaintext, prefix };
}

// ── Verify (called by Bearer auth middleware) ───────────────────────────

export interface VerifiedToken {
  id:          string;
  orgId:       string;
  createdById: string;
  scopes:      TokenScope[];
  prefix:      string;
}

/**
 * Verify a plaintext token. Returns the token row + owner if valid,
 * null otherwise. "Valid" = exists in DB AND not revoked AND not
 * expired. Updates lastUsedAt as a side effect (fire-and-forget so the
 * auth path stays fast — a few ms slower per request would compound
 * across the high-volume GET /findings).
 */
export async function verifyToken(plaintext: string): Promise<VerifiedToken | null> {
  if (!plaintext.startsWith(TOKEN_PREFIX)) return null;
  const hash = sha256(plaintext);

  const row = await prisma.apiToken.findUnique({
    where: { tokenHash: hash },
    select: {
      id: true, orgId: true, createdById: true, scopes: true, prefix: true,
      revokedAt: true, expiresAt: true,
    },
  });
  if (!row)             return null;
  if (row.revokedAt)    return null;
  if (row.expiresAt && row.expiresAt < new Date()) return null;

  // Fire-and-forget lastUsedAt update — must not block auth. Errors
  // are swallowed silently because a missed timestamp update is far
  // less bad than failing an authenticated request.
  prisma.apiToken
    .update({ where: { id: row.id }, data: { lastUsedAt: new Date() } })
    .catch(() => {});

  return {
    id:          row.id,
    orgId:       row.orgId,
    createdById: row.createdById,
    // The DB stores scopes as String[] (Postgres text[]); cast back to
    // the typed alias. Filter unknown-scope strings defensively in case
    // a future scope string ends up in DB without a code update.
    scopes:      (row.scopes as string[]).filter(isKnownScope),
    prefix:      row.prefix,
  };
}

// ── List + revoke ────────────────────────────────────────────────────────

export interface TokenSummary {
  id:         string;
  name:       string;
  prefix:     string;
  scopes:     TokenScope[];
  createdAt:  Date;
  lastUsedAt: Date | null;
  expiresAt:  Date | null;
  revokedAt:  Date | null;
  createdBy:  { id: string; username: string };
}

export async function listTokens(orgId: string): Promise<TokenSummary[]> {
  const rows = await prisma.apiToken.findMany({
    where:   { orgId },
    orderBy: { createdAt: "desc" },
    include: { createdBy: { select: { id: true, username: true } } },
  });
  return rows.map((r) => ({
    id:         r.id,
    name:       r.name,
    prefix:     r.prefix,
    scopes:     (r.scopes as string[]).filter(isKnownScope),
    createdAt:  r.createdAt,
    lastUsedAt: r.lastUsedAt,
    expiresAt:  r.expiresAt,
    revokedAt:  r.revokedAt,
    createdBy:  r.createdBy,
  }));
}

/**
 * Revoke a token. Soft-delete by default — preserves the audit trail
 * (operators may want to know "this token was used 47 times before we
 * revoked it on $date"). Hard delete is a separate code path used only
 * when the operator explicitly chooses "delete forever".
 */
export async function revokeToken(orgId: string, tokenId: string): Promise<boolean> {
  const result = await prisma.apiToken.updateMany({
    where: { id: tokenId, orgId, revokedAt: null },
    data:  { revokedAt: new Date() },
  });
  return result.count > 0;
}

export async function deleteToken(orgId: string, tokenId: string): Promise<boolean> {
  const result = await prisma.apiToken.deleteMany({
    where: { id: tokenId, orgId },
  });
  return result.count > 0;
}
