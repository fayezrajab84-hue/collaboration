# Scanner QA Harness

Smoke + contract tests for every scanner in `apps/scanner/scanners/`. Designed to run in seconds against tiny fixture artifacts so it can sit on the critical path of every PR.

## What's tested

### `test_contracts.py` — instant, no scanning
- Every `ScanType` enum value is wired to a scanner class
- Every scanner inherits `BaseScanner` (so it has `clone_repo`, `compute_fingerprint`, etc.)
- Every scanner implements `scan(self, request, workspace)`
- `NormalizedFinding` still has all fields the API's `findingService` depends on

### `test_smoke.py` — ~30s total
- **SAST / SCA / SECRET / IAC**: clone the local fixture repo (`fixtures/vulnerable_repo/`), run scan, assert findings count + per-finding contract
- **CONTAINER**: scan `alpine:3.10` (~5 MB), assert ≥1 CVE
- **Fingerprint stability**: rescan the same fixture, assert identical fingerprint set (the dedup contract the API relies on)

### Opt-in (gated by env var)
- **DAST**: requires `QA_DAST_TARGET=<reachable-host>` (e.g. `dvwa` inside docker network). Marked `@pytest.mark.slow_network`.
- **PENTEST / PENTEST_FULL**: skipped by default — they take 20+ minutes. Future work: add a pruned template set for ~2 min run.

## How to run

```bash
# All fast tests (contracts + smoke):
docker exec admiring-hertz-scanner-1 pytest /app/apps/scanner/qa/

# Just contracts (instant — good for pre-commit):
docker exec admiring-hertz-scanner-1 pytest /app/apps/scanner/qa/test_contracts.py

# Skip network-dependent tests entirely:
docker exec -e QA_SKIP_NETWORK=1 admiring-hertz-scanner-1 pytest /app/apps/scanner/qa/

# Include DAST against the running DVWA stack:
docker exec -e QA_DAST_TARGET=dvwa admiring-hertz-scanner-1 pytest -m slow_network /app/apps/scanner/qa/
```

## Adding a new scanner

When you add a new scanner:

1. Add it to `SCANNER_MAP` in `apps/scanner/main.py` — `test_contracts` will fail otherwise.
2. Make it inherit `BaseScanner`.
3. Add a fixture artifact in `fixtures/vulnerable_repo/` that triggers it, OR a separate fixture file.
4. Add an entry to `EXPECTED_MIN_FINDINGS` in `test_smoke.py`.
5. Run the suite — green on the first try means your scanner has the same contract every other scanner has.

## Why the fixtures look like that

The fixture repo (`fixtures/vulnerable_repo/`) intentionally contains:

- **`app.py`** — Python with `eval()`, `subprocess shell=True`, SQL string formatting + a hardcoded fake AWS key. Triggers SAST and SECRET scanners with one file.
- **`main.tf`** — Terraform with a public S3 bucket + wide-open security group. Triggers IAC.
- **`package.json`** — pinned to `lodash@4.17.4`, `minimist@1.2.0`, `axios@0.18.0`. Triggers SCA.

Do NOT update these to fix the vulnerabilities — they are the test signal. If you need to add a new vulnerable pattern for a new rule, append; don't replace.

## Why fixtures, not WebGoat / DVWA-style apps

WebGoat is huge (1+ GB clone) and changes upstream. DVWA needs a running container. Both are unfit for "should run in CI in <60 s". The hand-built fixtures are deterministic, version-pinned, and fit in a single commit — so when a test breaks you know it's the scanner, not the fixture drifting.
