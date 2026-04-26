---
description: Pretty-print the evidence + raw_output JSON for a finding so you can verify the Proof-of-Exploit badge will render.
argument-hint: "<findingId>  (e.g. cmo... — get from /scan-status)"
allowed-tools: Bash
---

# Finding evidence

Dumps the two JSONB columns that drive the **Proof of Exploit** badge:

- `evidence` — the curated, UI-facing object (`url`, `param`, `attack`,
  `curl_command`, etc.). The badge requires non-null `url` AND non-null
  `attack`.
- `rawOutput` — the unmodified scanner output that produced the finding.
  Useful when `evidence` is missing fields and you need to see what the
  parser was working from.

Treat `$ARGUMENTS` as the finding ID. Refuse on empty input.

---

## Steps

```bash
FINDING_ID="$ARGUMENTS"

if [ -z "$FINDING_ID" ]; then
  echo "Usage: /finding-evidence <findingId>" >&2
  exit 1
fi

echo "=== Finding header ==="
docker compose exec -T postgres psql -U devsecops -d devsecops -c \
  "SELECT id, severity, confidence, scanner, title, status, \
          \"createdAt\", \"scanJobId\" \
   FROM \"Finding\" WHERE id='$FINDING_ID';"

echo
echo "=== evidence (UI-facing) ==="
docker compose exec -T postgres psql -U devsecops -d devsecops -c \
  "SELECT jsonb_pretty(evidence) FROM \"Finding\" WHERE id='$FINDING_ID';"

echo
echo "=== Proof-of-Exploit badge eligibility ==="
docker compose exec -T postgres psql -U devsecops -d devsecops -c \
  "SELECT \
     confidence='CONFIRMED'      AS confirmed, \
     evidence ? 'url'            AS has_url, \
     evidence ? 'attack'         AS has_attack, \
     evidence ? 'curl_command'   AS has_curl, \
     (confidence='CONFIRMED' \
      AND evidence ? 'url' \
      AND evidence ? 'attack')   AS badge_renders \
   FROM \"Finding\" WHERE id='$FINDING_ID';"

echo
echo "=== rawOutput (truncated to 4000 chars) ==="
docker compose exec -T postgres psql -U devsecops -d devsecops -c \
  "SELECT left(jsonb_pretty(\"rawOutput\"), 4000) FROM \"Finding\" WHERE id='$FINDING_ID';"
```

**Interpreting the output:**

- `badge_renders=t` → the UI will show the **Proof of Exploit** badge.
- `badge_renders=f` with `confirmed=t` → finding is high-confidence but
  missing one of the required evidence keys. Most common: scanner found
  the vuln but the parser didn't extract a reproducer URL. Check the
  parser for that scanner in `apps/scanner/scanners/pentest_full/exploit.py`.
- `confirmed=f` → scanner only got `LIKELY` / `POSSIBLE`. Either the
  payload didn't trigger the vulnerability (true low-confidence) or the
  detection logic is too conservative.

If `rawOutput` is empty `{}`, the parser dropped everything — common
xsstrike failure mode. Compare against a fresh manual run:

```bash
docker run --rm --network admiring-hertz_internal --entrypoint xsstrike \
  devsecops-scanner-pentest:latest -u 'http://dvwa/vulnerabilities/xss_r/?name=test' --skip
```
