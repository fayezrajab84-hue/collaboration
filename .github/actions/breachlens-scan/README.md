# BreachLens Scan — GitHub Action

[![Marketplace](https://img.shields.io/badge/Marketplace-BreachLens%20Scan-blue?logo=github)](https://github.com/marketplace/actions/breachlens-scan)
[![License](https://img.shields.io/badge/License-MIT-blue.svg)](./LICENSE)

Trigger a [BreachLens](https://github.com/fayezrajab84-hue/collaboration) security scan from your CI pipeline, gate the build on findings severity, and surface results in the GitHub Security tab via SARIF upload.

BreachLens correlates SAST + SCA + Secrets + IaC + Container + DAST + Pentest + Runtime findings into one chain — this Action lets your CI pull that view down to the PR diff.

---

## Choose your integration pattern

BreachLens scans **server-side** — the GitHub runner just tells your BreachLens deployment to start a scan; your code is cloned + analysed on your BreachLens server, not on the runner. That gives you two valid workflow shapes:

| Pattern | When to use | Example |
|---|---|---|
| **A. Composite action** | Multiple consumer teams, Marketplace listing, branded one-line `uses:` | `uses: fayezrajab84-hue/...@v1` |
| **B. Bash-only workflow** | Your own team's repos, fewer moving parts, immune to action-parser quirks | inline `curl` calls — see below |
| **C. GitHub App** *(planned, Phase A8)* | Zero-config — install App once at org level, every repo auto-scans on push/PR | (none yet) |

**Pattern B is recommended for repos under your direct control** — it's ~30 lines of bash with no external action download. You can always switch to Pattern A later for external customers.

Both patterns hit the same `/api/scans/from-github` endpoint, get the same SARIF, fail the same severity gates. The choice is purely about packaging.

---

## Pattern A — Composite action (current default)

One-line `uses:`. Drop into any repo, set two secrets, push.

```yaml
name: Security scan

on:
  pull_request:
    branches: [main]
  push:
    branches: [main]

permissions:
  security-events: write     # for SARIF upload to Code Scanning
  contents: read

jobs:
  breachlens-scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - uses: fayezrajab84-hue/collaboration/.github/actions/breachlens-scan@v1
        with:
          api-url:       ${{ vars.BREACHLENS_API_URL }}
          api-token:     ${{ secrets.BREACHLENS_API_TOKEN }}
          severity-gate: HIGH    # fail build if HIGH+ findings
          # No repo-id needed! Phase A7 auto-discovers the repo from
          # ${{ github.repository }} and onboards it on first run.
```

That's the entire workflow — drop it in any GitHub repo, set two secrets, push. **No "Add Repository" step in BreachLens UI required**: the first time the Action fires, BreachLens auto-onboards the repo using the API token owner's GitHub OAuth credentials.

That single step:

1. POSTs `/api/scans/from-github` to your BreachLens deployment
2. Polls until the scan completes (45-min default timeout)
3. Downloads SARIF 2.1.0 results
4. Renders a step summary table (Critical / High / Medium counts)
5. Fails the build if findings at the gated severity exist
6. Uploads SARIF to GitHub Code Scanning so findings appear in the **Security tab** + on **PR diffs**

---

## Pattern B — Bash-only workflow (recommended for repos you control)

Same end-to-end flow, no external action dependency. **GitHub doesn't download anything from the BreachLens repo** — the workflow is fully self-contained:

```yaml
name: Security scan
on:
  pull_request:
    branches: [main]
  push:
    branches: [main]
  workflow_dispatch:

permissions:
  security-events: write   # SARIF upload to Code Scanning
  contents: read

jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
      - name: Trigger BreachLens scan + wait + apply gate
        env:
          API_URL:       ${{ vars.BREACHLENS_API_URL }}
          API_TOKEN:     ${{ secrets.BREACHLENS_API_TOKEN }}
          SEVERITY_GATE: HIGH
        run: |
          set -euo pipefail
          PR=$(jq -r '.pull_request.number // empty' "$GITHUB_EVENT_PATH" 2>/dev/null || echo "")

          # 1. Trigger scan via auto-discovery — no repo-id needed
          BODY=$(jq -nc \
            --arg full   "$GITHUB_REPOSITORY" \
            --arg sha    "$GITHUB_SHA" \
            --arg branch "${GITHUB_HEAD_REF:-$GITHUB_REF_NAME}" \
            --arg pr     "$PR" \
            '{githubFullName:$full, commitSha:$sha, branch:$branch}
             + (if $pr != "" then {prNumber:($pr|tonumber)} else {} end)')
          SCAN_ID=$(curl -fsS -X POST "$API_URL/api/scans/from-github" \
            -H "Authorization: Bearer $API_TOKEN" \
            -H "Content-Type: application/json" \
            -d "$BODY" | jq -r '.scanJobId')
          echo "Triggered scan: $SCAN_ID"

          # 2. Poll for completion (~5–15 min)
          STATUS=PENDING
          DEADLINE=$(( $(date +%s) + 45*60 ))
          while [[ "$STATUS" != "COMPLETED" && "$STATUS" != "FAILED" ]]; do
            (( $(date +%s) > DEADLINE )) && { echo "::error::scan timeout"; exit 1; }
            sleep 15
            STATUS=$(curl -fsS "$API_URL/api/scans/$SCAN_ID" \
              -H "Authorization: Bearer $API_TOKEN" | jq -r '.status')
            echo "[poll] $STATUS"
          done
          [[ "$STATUS" == "FAILED" ]] && { echo "::error::scan FAILED"; exit 1; }

          # 3. Fetch SARIF
          curl -fsS "$API_URL/api/scans/$SCAN_ID/export.sarif" \
            -H "Authorization: Bearer $API_TOKEN" -o breachlens.sarif

          # 4. Severity counts + gate
          C=$(jq '[.runs[].results[] | select(.properties.severity=="CRITICAL")] | length' breachlens.sarif)
          H=$(jq '[.runs[].results[] | select(.properties.severity=="HIGH")] | length' breachlens.sarif)
          M=$(jq '[.runs[].results[] | select(.properties.severity=="MEDIUM")] | length' breachlens.sarif)
          {
            echo "## BreachLens scan results"
            echo "| Severity | Count |"
            echo "|---|---|"
            echo "| 🔴 Critical | $C |"
            echo "| 🟠 High     | $H |"
            echo "| 🟡 Medium   | $M |"
          } >> "$GITHUB_STEP_SUMMARY"

          case "$SEVERITY_GATE" in
            CRITICAL) (( C > 0 ))             && { echo "::error::$C critical"; exit 1; } ;;
            HIGH)     (( C + H > 0 ))         && { echo "::error::$((C+H)) HIGH+"; exit 1; } ;;
            MEDIUM)   (( C + H + M > 0 ))     && { echo "::error::$((C+H+M)) MED+"; exit 1; } ;;
          esac

      - name: Upload SARIF to GitHub Code Scanning
        if: always() && hashFiles('breachlens.sarif') != ''
        uses: github/codeql-action/upload-sarif@v3
        with:
          sarif_file: breachlens.sarif
          category:   breachlens
```

That's the entire workflow. ~70 lines of bash + one trusted upstream action (`github/codeql-action/upload-sarif@v3` from GitHub itself) for the Security-tab integration.

**Trade-offs vs Pattern A:**

|   | Pattern A (composite) | Pattern B (bash) |
|---|---|---|
| Lines of YAML in consumer repo | ~10 | ~70 |
| External action download per run | yes | no |
| Pinning + version updates | one-line `@v1` bump | edit each consumer repo's bash |
| Marketplace branding | yes | no |
| Action-parser quirks (the `${{ github.* }}` parser issue) | risk | none |
| Centralised bug fixes propagate to all consumers | yes | no |

**Use Pattern A when:** you want to ship to teams who shouldn't have to maintain bash. Pin `@v1`; one bump updates every consumer.

**Use Pattern B when:** the repos consuming this are under your direct control. Fewer moving parts, no parser fragility, and you can debug the entire flow inline. **For a self-hosted BreachLens deployment scanning your own org's repos, this is the cleaner pattern.**

---

## Setup — two minutes

### 1. Mint an API token

BreachLens → **Settings** → **API Tokens** → **Generate token**.

Choose:
- **Name** — e.g. "GitHub Actions for myrepo" (helps you identify the token later)
- **Scopes** — for a full CI workflow, check all three:
  - `scans:trigger` — POST scan triggers
  - `scans:read` — read scan status + SARIF export
  - `findings:read` — read findings + summary stats
- **Expiry** — `90 days` is a sensible default; rotate before expiry

The plaintext token is shown **once**. Copy it immediately.

### 2. Add to GitHub Secrets

In your repo's **Settings** → **Secrets and variables** → **Actions**:

| Type | Name | Value |
|---|---|---|
| Repository secret | `BREACHLENS_API_TOKEN` | `blt_…` (paste the plaintext) |
| Repository variable | `BREACHLENS_API_URL` | `https://your-breachlens.example.com` |

### 3. Drop the workflow in

Copy the [Quickstart](#quickstart) workflow into `.github/workflows/security.yml`, push. The next push or PR auto-runs the scan — BreachLens onboards the repo on first call.

---

## Inputs

| Input | Required | Default | Description |
|---|---|---|---|
| `api-url` | ✅ | — | BreachLens deployment URL, e.g. `https://breachlens.example.com` |
| `api-token` | ✅ * | — | BreachLens API token (`blt_…`). Mint via Settings → API Tokens |
| `repo-id` | ⚪ ** | — | BreachLens Repository ID to scan |
| `container-id` | ⚪ ** | — | BreachLens Container ID to scan |
| `domain-id` | ⚪ ** | — | BreachLens Domain ID to scan |
| `scan-types` | — | varies | Comma-separated scan types. Defaults vary by target type |
| `severity-gate` | — | `none` | Fail build if findings ≥ this severity exist. One of `CRITICAL`, `HIGH`, `MEDIUM`, `LOW`, `INFO`, `none` |
| `upload-sarif` | — | `true` | Upload SARIF to GitHub Code Scanning |
| `poll-interval-seconds` | — | `15` | How often to poll scan status |
| `timeout-minutes` | — | `45` | Hard timeout (PENTEST_FULL can take 30+ min) |
| `session-cookie` | — | — | **DEPRECATED** — kept for backwards compat. Use `api-token` instead. |

*\* `api-token` or `session-cookie` (deprecated) — exactly one auth method required.*
*\*\* Exactly one target ID required.*

### Default scan types

| Target | Default `scan-types` |
|---|---|
| Repository | `SAST,SCA,SECRET,IAC,CONTAINER` |
| Container | `CONTAINER` |
| Domain | `DAST` (use `PENTEST_FULL` for the deeper sweep — 30+ min) |

---

## Outputs

| Output | Description |
|---|---|
| `scan-id` | The BreachLens scan job ID |
| `status` | Final scan status (`COMPLETED` or `FAILED`) |
| `critical-count` | Number of CRITICAL findings on the scan target |
| `high-count` | Number of HIGH findings |
| `medium-count` | Number of MEDIUM findings |
| `sarif-path` | Local file path of the downloaded SARIF report |

Use them in downstream steps:

```yaml
- uses: fayezrajab84-hue/collaboration/.github/actions/breachlens-scan@v1
  id: scan
  with: {...}

- name: Slack notify if critical
  if: ${{ steps.scan.outputs.critical-count != '0' }}
  run: |
    curl -X POST $SLACK_WEBHOOK -d "{\"text\": \"${{ steps.scan.outputs.critical-count }} critical findings on ${{ github.event.head_commit.url }}\"}"
```

---

## Examples

### Scheduled nightly DAST against a staging domain

```yaml
on:
  schedule:
    - cron: "0 2 * * *"       # 2am UTC daily

jobs:
  nightly-dast:
    runs-on: ubuntu-latest
    permissions: { security-events: write }
    steps:
      - uses: fayezrajab84-hue/collaboration/.github/actions/breachlens-scan@v1
        with:
          api-url:        ${{ vars.BREACHLENS_API_URL }}
          api-token:      ${{ secrets.BREACHLENS_API_TOKEN }}
          domain-id:      cmoh4mqg90001amrdvf6q9r7w
          scan-types:     PENTEST_FULL
          timeout-minutes: 90    # PENTEST_FULL on a real target takes longer
          severity-gate:  CRITICAL
```

### Block PR merges if CRITICAL findings exist, but allow HIGH

```yaml
- uses: fayezrajab84-hue/collaboration/.github/actions/breachlens-scan@v1
  with:
    api-url:        ${{ vars.BREACHLENS_API_URL }}
    api-token:      ${{ secrets.BREACHLENS_API_TOKEN }}
    repo-id:        cmoh50000abc1234
    severity-gate:  CRITICAL    # only Critical fails the build
```

### Container image scan on push to main

```yaml
- uses: fayezrajab84-hue/collaboration/.github/actions/breachlens-scan@v1
  with:
    api-url:        ${{ vars.BREACHLENS_API_URL }}
    api-token:      ${{ secrets.BREACHLENS_API_TOKEN }}
    container-id:   cmohi55oz0002ci7dvxsgdgs8
    scan-types:     CONTAINER
    severity-gate:  HIGH
```

---

## What flows into the GitHub Security tab

When `upload-sarif: true` (default) and your workflow has `security-events: write` permission, the SARIF output uploads to GitHub Code Scanning. Findings appear:

- On the **Security tab** of your repo, ranked by `security-severity` (CVSS-mapped)
- Inline on **PR diffs** when a finding's location matches a changed file
- In the **commit-level Security overview** for code owners

Each finding's properties bag includes the BreachLens-specific axes (`cveId`, `cweId`, `packageName`, `fixVersion`, `cvssScore`, `scanType`, `confidence`) so downstream automation (filters, reports) can key off them.

The `partialFingerprints.breachlensFingerprint` keeps re-uploads stable — when you fix a finding and re-scan, GitHub Code Scanning matches the same fingerprint and marks the alert closed instead of duplicating it.

---

## Troubleshooting

| Symptom | Likely cause |
|---|---|
| `Authentication required` (401) | `api-token` not set or expired. Mint a new token in BreachLens Settings → API Tokens. |
| `Invalid or expired API token` | Token was revoked, or the prefix `blt_` was stripped during copy-paste. Verify the token starts with `blt_` and matches the prefix shown in Settings. |
| `API token missing required scope` (403) | Token doesn't include the scope this Action needs. Mint a new token with `scans:trigger`, `scans:read`, `findings:read`. |
| Scan times out | Bump `timeout-minutes`. PENTEST_FULL on a real target can take 60+ min; defaults are 45min. |
| `Severity gate HIGH: found N findings` (gate failure) | The Action did its job — your code has findings at or above the gated severity. Either fix them, or relax the gate (`severity-gate: CRITICAL` → only critical fails). |
| SARIF upload fails | Your workflow needs `permissions: security-events: write` at the job or workflow level. |

---

## Authentication scopes — what each one unlocks

| Scope | Endpoints | When to grant |
|---|---|---|
| `scans:trigger` | `POST /api/{repos\|containers\|domains}/:id/scan` | Always — required to run scans |
| `scans:read` | `GET /api/scans/:id`, `GET /api/scans/:id/export.sarif` | Always — required to poll status + fetch SARIF |
| `findings:read` | `GET /api/findings`, summary stats | Required if downstream steps query findings beyond the SARIF |

Tokens are **org-scoped** at mint time and cannot escalate to other orgs the user belongs to. The `lastUsedAt` timestamp updates on every authenticated request so operators can see "this token hasn't been used in N days — safe to revoke?"

---

## Security model

- **Tokens are hashed at rest** — only SHA-256(plaintext) is stored
- **Plaintext is shown once** — on creation only; never re-fetchable
- **Scope-gated** — tokens authenticate as the user who minted them and inherit that user's role; scope additionally caps capability
- **Revocable** — soft-revoke preserves audit trail; hard-delete available
- **Optional expiry** — auto-fails auth past `expiresAt` without a sweep job
- **Audit-logged** — every mint / revoke / delete writes an audit row

---

## Self-hosted vs. SaaS

BreachLens is self-hosted only — there's no public SaaS. Run it on your own infrastructure via the docker-compose stack at the [main repo](https://github.com/fayezrajab84-hue/collaboration). The GitHub Action calls *your* deployment's API URL.

For air-gapped deployments where GitHub-hosted runners can't reach your BreachLens API, use [self-hosted runners](https://docs.github.com/en/actions/hosting-your-own-runners/managing-self-hosted-runners/about-self-hosted-runners) inside the same VPC.

---

## Versioning

This Action follows semantic versioning. Pin to a major version for non-breaking auto-updates:

```yaml
uses: fayezrajab84-hue/collaboration/.github/actions/breachlens-scan@v1
```

Or pin to a specific release for fully reproducible CI:

```yaml
uses: fayezrajab84-hue/collaboration/.github/actions/breachlens-scan@v1.0.0
```

---

## License

[MIT](./LICENSE) — see LICENSE file for details.

---

## Reporting issues

Bug reports, feature requests, and pull requests welcome at the [main repo](https://github.com/fayezrajab84-hue/collaboration/issues). When filing a bug, please include the workflow snippet that reproduces it, the BreachLens deployment version, and a redacted excerpt of the failing step's logs.
