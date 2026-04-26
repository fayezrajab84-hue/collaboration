---
description: Rebuild the scanner + scanner-pentest images and force-recreate the running pentest container so source edits take effect.
argument-hint: "(no arguments)"
allowed-tools: Bash
---

# Scanner rebuild

The scanner stack uses two layered images (`devsecops-scanner` →
`devsecops-scanner-pentest`) and **neither has a source bind mount in
dev**. Edits to `apps/scanner/**/*.py` only reach a running container
after both rebuilds *and* a `--force-recreate` of the pentest container.

Skipping the recreate step is the single most common reason "my fix
didn't work" — the new image gets built but the live container keeps
running the previous image. Always do both.

---

## Steps

Run from the repo root.

1. **Rebuild base scanner image** (must come first; the pentest image
   uses it as its `FROM` base):

   ```bash
   docker compose build scanner
   ```

2. **Rebuild scanner-pentest** (depends on base from step 1):

   ```bash
   docker compose --profile pentest build scanner-pentest
   ```

3. **Force-recreate the running pentest container** so it actually
   binds to the new image:

   ```bash
   docker compose --profile pentest up -d --force-recreate scanner-pentest
   ```

4. **Verify** the live container's image ID matches the freshly built
   one — if these don't match, recreate didn't take:

   ```bash
   docker inspect --format '{{.Image}}' admiring-hertz-scanner-pentest-1
   docker images --no-trunc --quiet devsecops-scanner-pentest:latest
   ```

5. **Confirm the source edit is in the container** by greping the
   baked file for a string from your change. Adjust the path/pattern
   to match what you edited:

   ```bash
   docker compose --profile pentest exec -T scanner-pentest \
     grep -n "no payload .90% efficiency" /app/scanners/pentest_full/exploit.py || \
     echo "EDIT NOT IN CONTAINER — recreate did not take"
   ```

If step 5 prints "EDIT NOT IN CONTAINER", repeat step 3 — usually a
volume from a stale compose state. As a nuclear option,
`docker compose --profile pentest down scanner-pentest` followed by
step 3 always works.
