---
description: Show the DB row, finding counts grouped by severity/scanner, and recent scanner-pentest log lines for a given scanJobId.
argument-hint: "<scanJobId>  (e.g. cmoelx3lw0001deu32pjd207y)"
allowed-tools: Bash
---

# Scan status

Pulls a one-screen summary for a `ScanJob`:

1. The job row (status, scan types, timing, error)
2. Findings grouped by `severity × confidence × scanner`
3. The last 80 lines of `scanner-pentest` logs that mention this job ID

Treat `$ARGUMENTS` as the scan job ID. If it's empty, refuse and tell
the user to pass the ID — there's no safe default.

---

## Steps

```bash
JOB_ID="$ARGUMENTS"

if [ -z "$JOB_ID" ]; then
  echo "Usage: /scan-status <scanJobId>" >&2
  exit 1
fi

echo "=== ScanJob row ==="
docker compose exec -T postgres psql -U devsecops -d devsecops -c \
  "SELECT id, status, \"scanTypes\", \"createdAt\", \"startedAt\", \"completedAt\", error \
   FROM \"ScanJob\" WHERE id='$JOB_ID';"

echo
echo "=== Findings (severity x confidence x scanner) ==="
docker compose exec -T postgres psql -U devsecops -d devsecops -c \
  "SELECT severity, confidence, scanner, COUNT(*) \
   FROM \"Finding\" WHERE \"scanJobId\"='$JOB_ID' \
   GROUP BY severity, confidence, scanner \
   ORDER BY severity, confidence;"

echo
echo "=== Findings with proof-of-exploit evidence (CONFIRMED + curl_command) ==="
docker compose exec -T postgres psql -U devsecops -d devsecops -c \
  "SELECT id, severity, confidence, scanner, title \
   FROM \"Finding\" \
   WHERE \"scanJobId\"='$JOB_ID' \
     AND confidence='CONFIRMED' \
     AND evidence ? 'curl_command' \
   LIMIT 20;"

echo
echo "=== scanner-pentest log tail (filtered to this job) ==="
docker compose --profile pentest logs --tail 2000 scanner-pentest 2>/dev/null \
  | grep -F "$JOB_ID" \
  | tail -80
```

**Reading the output:**

- `status=FAILED` with non-null `error` → look at the log tail for the
  Python traceback. Phase 4 failures usually surface as a
  `[exploit][<tool>]` prefixed line.
- `confidence=CONFIRMED` count of 0 across xsstrike + dalfox is the
  Phase-4 "no proof of exploit" failure mode — most often caused by
  unparameterised URLs or stale session cookies. Check
  `[exploit] refreshed session cookie` is present in the log tail.
- `[+] Payload:` candidates with `[!] Efficiency: < 90` means xsstrike
  ran but didn't find anything high-confidence; this is a *true negative*,
  not a parser bug.

If the log tail is empty, the job ID may be wrong, or logs may have
rolled over. `docker compose --profile pentest logs --since 2h` widens
the window.
