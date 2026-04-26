---
description: Sync the prisma schema into the running api container (docker-cp + prisma db push + generate + restart). Use after a postgres recreate drops `db push`-only tables, or after editing schema.prisma.
argument-hint: "(no arguments)"
allowed-tools: Bash
---

# Prisma db push (in-container dance)

The `api` container bind-mounts `apps/api/src` but **NOT**
`apps/api/prisma/`, so a host-side edit to `schema.prisma` doesn't
reach the running container. The `migrate` service only runs
migration files — anything pushed via `prisma db push` (no migration
file) lives only in the running database and disappears the next time
the postgres container gets recreated.

Symptom that calls for this command: `/auth/sso/initiate` (or any
other route) starts returning 500 because *"The table public.<X> does
not exist in the current database"*.

---

## Steps

Run from the repo root.

1. **Copy the prisma directory into the api container** (no bind
   mount, so this has to happen explicitly):

   ```bash
   docker compose cp apps/api/prisma api:/app/apps/api/
   ```

2. **Push the schema to postgres.** `--skip-generate` separates the
   slow client-regeneration step; `--accept-data-loss` lets it drop
   columns that no longer exist in `schema.prisma` (dev-only — never
   run this in prod):

   ```bash
   docker compose exec -T -w //app/apps/api api npx prisma db push \
     --skip-generate --accept-data-loss
   ```

3. **Regenerate the Prisma client** so `import { …Type } from
   "@prisma/client"` resolves to the new shape:

   ```bash
   docker compose exec -T -w //app/apps/api api npx prisma generate
   ```

4. **Restart the api** so `tsx watch` picks up the regenerated client
   (HMR doesn't reload `node_modules/`):

   ```bash
   docker compose restart api
   ```

5. **Wait for healthy + verify** the table is present:

   ```bash
   until curl -sf http://localhost:3000/health >/dev/null 2>&1; do sleep 1; done
   echo "API READY"
   docker compose exec -T postgres psql -U devsecops -d devsecops -c "\dt" | \
     grep -E "SsoConfig|Sbom|Invitation"   # adjust grep to the table you expected
   ```

If the grep returns nothing, the push silently failed — check the api
container logs (`docker compose logs api --tail 50`) for Prisma errors.
