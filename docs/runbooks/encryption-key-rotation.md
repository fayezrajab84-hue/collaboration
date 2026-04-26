# `ENCRYPTION_KEY` rotation runbook

> Operator runbook for rotating the AES-256-GCM master key that
> protects every secret stored in BreachLens's database.

## What this key protects

`ENCRYPTION_KEY` is a 32-byte key (64 hex characters) that the API
uses with AES-256-GCM (12-byte IV, 16-byte auth tag, base64-packed)
to encrypt every secret BreachLens persists. See
[`apps/api/src/services/encryptionService.ts`](../../apps/api/src/services/encryptionService.ts).

| Model | Field | Contents |
|---|---|---|
| `User` | `accessToken` | GitHub OAuth user access token (used to clone private repos) |
| `AIProvider` | `encryptedConfig` | `{ apiKey: <base64> }` for Anthropic / OpenAI / Gemini providers |
| `DomainAuthConfig` | `encryptedCreds` | FORM / HEADER / COOKIE / OAUTH2 credentials for authenticated DAST scans |
| `Integration` | `encryptedData` | Jira host + email + apiToken; Slack / Teams webhook URLs |
| `Repository` | `webhookSecret` | GitHub webhook signing secret |

If `ENCRYPTION_KEY` is lost, every value above becomes
**unrecoverable** — there is no key escrow. If the key is leaked,
every value above must be **assumed compromised** until rotated and
the upstream credentials revoked at the source (GitHub PAT
revocation, AI provider key rotation, Jira API token regen, webhook
URL re-issuance).

## When to rotate

- **Suspected compromise** — key file leaked, machine seized, ex-employee
  with operator access, repository accidentally pushed with the env
  variable set.
- **Routine hygiene** — annually, or quarterly for high-sensitivity
  deployments.
- **SOC 2 / ISO 27001 evidence** — auditors want a documented rotation
  cadence and proof of last rotation date.
- **Compliance event** — scope expansion (new org, regulated data
  class) often requires a key rotation as evidence of fresh control.

## Two rotation strategies

### Strategy A — Hard cutover *(recommended for current single-instance scale)*

1. Stop API + workers (small downtime, typically 1–5 minutes)
2. Re-encrypt every persisted secret with the new key
3. Update `ENCRYPTION_KEY` env var
4. Restart

Simple, atomic, no edge cases. Use this if you can tolerate a
maintenance window. **Default choice today.**

### Strategy B — Dual-key transition *(for zero-downtime production)*

1. Add a second env var `ENCRYPTION_KEY_PREVIOUS`
2. Modify `decrypt()` to try the new key first, fall back to the old
3. Deploy this dual-decrypt build
4. Run a background re-encryption job that walks each table and
   rewrites every row with the new key
5. Once the job completes, remove the dual-decrypt code path and
   `ENCRYPTION_KEY_PREVIOUS`

Required when you can't take downtime — but it requires a code
change to `encryptionService.ts` and is harder to reason about.
Defer until the platform reaches multi-instance scale (Phase 25).

---

## Strategy A — Step-by-step

### 1. Generate the new key

```bash
openssl rand -hex 32
```

Save the output somewhere secure (1Password, Vault, sealed-secret).
**Do not paste into chat or commit.**

### 2. Pre-flight check — count what will be re-encrypted

```bash
docker compose exec -T postgres psql -U devsecops -d devsecops -c \
  "SELECT
     (SELECT COUNT(*) FROM \"User\" WHERE \"accessToken\" IS NOT NULL)        AS users,
     (SELECT COUNT(*) FROM \"AIProvider\")                                     AS ai_providers,
     (SELECT COUNT(*) FROM \"DomainAuthConfig\")                               AS domain_auth_configs,
     (SELECT COUNT(*) FROM \"Integration\")                                    AS integrations,
     (SELECT COUNT(*) FROM \"Repository\" WHERE \"webhookSecret\" IS NOT NULL) AS webhooks;"
```

Note the totals. The post-rotation verification step will compare
against these.

### 3. Take a Postgres backup *(non-negotiable)*

```bash
docker compose exec -T postgres pg_dump -U devsecops -d devsecops \
  > "backup-pre-rotation-$(date +%Y%m%d-%H%M%S).sql"
```

If the re-encryption migration fails partway through, this is your
safety net. Do not skip.

### 4. Stop the API + workers

The scanner can keep running — it doesn't decrypt these fields.

```bash
docker compose stop api
```

`migrate` and `crawler` are unaffected. `web` (Vite dev server) can
stay up; it will show 502s during the cutover, that's expected.

### 5. Run the re-encryption migration

A migration script needs to be added under
`apps/api/src/migrations/rotateEncryptionKey.ts` that:

- Reads `ENCRYPTION_KEY_OLD` and `ENCRYPTION_KEY_NEW` from env
- Constructs two `encryptionService` instances (one per key)
- For each affected table:
  1. SELECT all rows
  2. Decrypt with OLD key
  3. Encrypt with NEW key
  4. UPDATE the row with the new ciphertext
- Wraps the whole thing in a single transaction so it's all-or-nothing

Until that script exists, follow the **manual path** in §6.

Run via:

```bash
ENCRYPTION_KEY_OLD="<old key>" ENCRYPTION_KEY_NEW="<new key>" \
  docker compose exec -T -w //app/apps/api api node --import tsx \
  src/migrations/rotateEncryptionKey.ts
```

Expected output: row counts per table matching the pre-flight numbers.

### 6. Manual path *(if the migration script does not yet exist)*

For each table listed in §1:

1. SELECT the encrypted column with the row id
2. Decrypt each value with the old key (offline, in a one-shot
   container with `ENCRYPTION_KEY` set to the old value)
3. Re-encrypt each value with the new key (a separate one-shot)
4. UPDATE the row with the new ciphertext

This is tedious and error-prone. **Build the script in step 5 before
your first real rotation.** Tracked as a Phase 13 follow-up.

### 7. Swap the env var

Update `.env`:

```diff
-ENCRYPTION_KEY=<old key>
+ENCRYPTION_KEY=<new key>
```

For production deploys using a secrets manager (Doppler, Vault,
Kubernetes Secret), update there.

### 8. Restart the API

```bash
docker compose start api
```

Watch the logs:

```bash
docker compose logs -f --tail 50 api
```

The first GitHub OAuth call, AI service call, or DAST authenticated
scan will exercise decryption. Errors of the form
`Unsupported state or unable to authenticate data` mean a row was
not re-encrypted — restore from the §3 backup and investigate.

### 9. Verify

Sample one row from each affected table and confirm decryption
works end-to-end:

- **User token**: trigger `GET /api/repos` (loads list using stored token)
- **AIProvider**: trigger `POST /api/findings/<id>/analyse` (uses encrypted apiKey)
- **DomainAuthConfig**: trigger an authenticated DAST scan (uses encrypted creds at scanner-side via `obtain_session()`)
- **Integration**: trigger a test notification (`POST /api/integrations/<type>/test` if endpoint exists, otherwise re-save the integration to round-trip the encryption)
- **Repository.webhookSecret**: send a test webhook from GitHub (or simulate via curl with the secret) and confirm 200

### 10. Securely retire the old key

- Remove from any operator notebooks, password managers, sealed-secrets
- Mark as REVOKED in the audit log entry recorded in §12
- Wipe from any local shell history: `history -c && history -w`

### 11. Re-issue any upstream credentials that were ever leaked

Rotation re-encrypts the *storage*. If the suspicion is that the
*plaintext credentials themselves* leaked alongside the key, the
upstream credentials must also be rotated:

| Stored secret | Where to rotate it upstream |
|---|---|
| `User.accessToken` (GitHub OAuth) | Have the user re-auth via OAuth — old token will be invalidated by GitHub on next user-initiated revoke, OR force via `POST /auth/logout` for all sessions |
| `AIProvider` API keys | Anthropic / OpenAI / Gemini consoles — issue a new key, update `AIProvider`, revoke the old |
| `DomainAuthConfig` creds | The customer's domain admin must rotate the password / token / cookie / OAuth client secret |
| `Integration` Jira API token | Atlassian profile → API tokens → revoke + re-issue |
| `Integration` Slack/Teams webhook URLs | Re-create the incoming webhook in Slack / Teams admin |
| `Repository.webhookSecret` | Regenerate the GitHub repo webhook secret + update via `PATCH /repos/.../hooks` |

### 12. Record the rotation

Add a row to your operator log (or, when it lands, the audit log
table from Phase 22) with:

- ISO 8601 timestamp
- Operator name
- Reason (routine / suspected compromise / scope change / SOC 2 evidence)
- Old key fingerprint (first 8 hex chars only — do not log the whole key)
- New key fingerprint
- Number of rows re-encrypted per table (from §5 output)

---

## Rollback plan

If decryption fails after rotation and the cause isn't clear within
~10 minutes:

```bash
docker compose stop api
psql -U devsecops -d devsecops < backup-pre-rotation-<timestamp>.sql
# Restore the OLD ENCRYPTION_KEY in .env
docker compose start api
```

Then investigate offline against a copy of the new-key database.

---

## Common failure modes

| Symptom | Likely cause | Fix |
|---|---|---|
| `Unsupported state or unable to authenticate data` on every decrypt | Wrong `ENCRYPTION_KEY` or migration didn't run | Restore backup, verify env var, re-run migration |
| `Unsupported state…` on *some* decrypts | Partial re-encryption (transaction not used) | Restore backup, ensure migration wraps in `prisma.$transaction` |
| AI provider 401s after rotation | Either re-encryption didn't reach `AIProvider`, or upstream key was *also* rotated and now the stored value is a stale plaintext re-encrypted | Re-test by re-creating the provider via UI to round-trip encryption |
| GitHub clone failures | User access tokens expired during the maintenance window (separate issue) | Have user re-auth via OAuth |

---

## Appendix — encryption format

`encryptionService.ts` produces a single base64-encoded payload:

```
[ iv (12 bytes) | auth tag (16 bytes) | ciphertext (variable) ]
```

`decrypt()` reverses this by slicing the buffer. The `KEY` is loaded
from `config.ENCRYPTION_KEY` once at process start and held in memory
for the lifetime of the process — there is no per-request key
re-derivation, no salt, no PBKDF2/Argon2. The ENCRYPTION_KEY itself
*is* the AES key.

This means a process restart is sufficient to pick up a new key —
no cache invalidation, no warm-up, no in-flight decrypt jobs to
drain. Step 8 of the rotation works because of this.
