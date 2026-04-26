---
description: Bring up the BreachLens dev stack (postgres, redis, api, scanner, web, dvwa) and wait until services are healthy. Pass "pentest" to also start scanner-pentest, "ai" to start ollama, "full" for both, "down" to tear everything down.
argument-hint: "[ pentest | ai | full | down ]  (default: base stack)"
allowed-tools: Bash
---

# Dev start

Brings up the BreachLens stack with the right Docker Compose profiles
and waits for the services that the API depends on (`postgres`, `redis`)
to actually report healthy — so you don't hit the API right after `up`
and get a 500 because Prisma can't connect yet.

`docker compose up` returns the moment the containers are *created*, not
when they're *ready*. The healthcheck poll closes that gap.

## Profile cheatsheet

| Arg | Profiles enabled | What you get |
|---|---|---|
| *(empty)* | default | postgres, redis, migrate, api, web, scanner, dvwa, dvwa-db |
| `pentest` | + `pentest` | adds `scanner-pentest` (sqlmap, xsstrike, dalfox, nikto) |
| `ai` | + `ai` | adds `ollama` (local inference for AI triage) |
| `full` | + `pentest` + `ai` | everything |
| `down` | — | `docker compose down` for all profiles |

## Steps

```bash
ARG="$ARGUMENTS"

if [ "$ARG" = "down" ]; then
  echo "=== Stopping all profiles ==="
  docker compose --profile pentest --profile ai --profile test down
  exit 0
fi

PROFILES=""
case "$ARG" in
  ""|"base")   PROFILES="" ;;
  "pentest")   PROFILES="--profile pentest" ;;
  "ai")        PROFILES="--profile ai" ;;
  "full")      PROFILES="--profile pentest --profile ai" ;;
  *)
    echo "Unknown arg: $ARG" >&2
    echo "Usage: /dev-start [ pentest | ai | full | down ]" >&2
    exit 1
    ;;
esac

echo "=== Bringing up stack (profiles: ${PROFILES:-default}) ==="
docker compose $PROFILES up -d

echo
echo "=== Waiting for postgres + redis healthchecks ==="
# Poll until both are healthy or 60s elapses. Postgres needs the longest:
# `pg_isready` typically passes in 5-15s, longer on a cold start.
deadline=$((SECONDS + 60))
while [ $SECONDS -lt $deadline ]; do
  pg_status=$(docker inspect --format '{{.State.Health.Status}}' admiring-hertz-postgres-1 2>/dev/null || echo "missing")
  rd_status=$(docker inspect --format '{{.State.Health.Status}}' admiring-hertz-redis-1 2>/dev/null || echo "missing")
  if [ "$pg_status" = "healthy" ] && [ "$rd_status" = "healthy" ]; then
    echo "postgres: $pg_status   redis: $rd_status"
    break
  fi
  echo "postgres: $pg_status   redis: $rd_status   (waiting…)"
  sleep 3
done

if [ "$pg_status" != "healthy" ] || [ "$rd_status" != "healthy" ]; then
  echo
  echo "=== TIMEOUT — postgres or redis did not become healthy in 60s ===" >&2
  echo "Check logs:" >&2
  echo "  docker compose logs --tail 50 postgres" >&2
  echo "  docker compose logs --tail 50 redis" >&2
  exit 1
fi

echo
echo "=== Service status ==="
docker compose $PROFILES ps

echo
echo "=== URLs ==="
echo "  Web (nginx prod build) : http://localhost          (docker web)"
echo "  Web (Vite dev server)  : http://localhost:5173     (preview_start, hot-reload)"
echo "  API                    : http://localhost:3000"
echo "  DVWA test target       : http://localhost:4280     (admin / password)"

if [ -n "$PROFILES" ]; then
  echo
  echo "=== Active extra profiles ==="
  echo "  $PROFILES"
fi
```

## Notes

- **Web at port 80 vs 5173:** the docker `web` service serves the
  production nginx build with no hot reload. For UI development use
  `preview_start` to run Vite at `localhost:5173` against the same `api`
  backend — both work side-by-side.
- **The `version: "3.9"` warning in compose output is benign.** The
  field has been obsolete since Compose v2 but the file still has it.
- **`down` stops *all* profiles**, not just the active ones — Compose
  treats profile-gated services as defined-but-not-selected unless you
  pass the same profile flags. The command flips on every profile
  during teardown so you don't end up with orphan containers.
- **Container name prefix `admiring-hertz-`** comes from the worktree
  directory name. If you've renamed the worktree, update the
  `docker inspect` lines above accordingly (or grep for the prefix once
  with `docker ps --format '{{.Names}}'`).
