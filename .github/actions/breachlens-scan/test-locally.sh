#!/usr/bin/env bash
#
# test-locally.sh — Phase A5 end-to-end test harness for the breachlens-scan Action.
#
# Mimics the Action's composite steps (validate inputs → trigger scan → poll →
# fetch SARIF → apply severity gate) using bash + curl + jq, against your local
# BreachLens deployment. Lets you validate the full CI pipeline BEFORE pushing
# to a real GitHub repo.
#
# What this proves:
#   1. Your API token has the right scopes (scans:trigger, scans:read)
#   2. Your repo/container/domain ID is valid + scannable
#   3. The scan completes within reasonable time
#   4. SARIF export returns valid 2.1.0 JSON
#   5. The severity gate logic fails the build correctly when it should
#
# Usage:
#   export BREACHLENS_API_URL=http://localhost:3000
#   export BREACHLENS_API_TOKEN=blt_...        # mint via Settings → API Tokens
#   export BREACHLENS_REPO_ID=cmoh50000abc1234 # or use --container-id / --domain-id
#   ./test-locally.sh
#
# Or with a severity gate:
#   ./test-locally.sh --severity-gate=HIGH
#
# Requirements: bash 4+, curl, jq.

set -euo pipefail

# ── Defaults ─────────────────────────────────────────────────────────────
API_URL="${BREACHLENS_API_URL:-http://localhost:3000}"
API_TOKEN="${BREACHLENS_API_TOKEN:-}"
REPO_ID="${BREACHLENS_REPO_ID:-}"
CONTAINER_ID="${BREACHLENS_CONTAINER_ID:-}"
DOMAIN_ID="${BREACHLENS_DOMAIN_ID:-}"
SCAN_TYPES=""
SEVERITY_GATE="none"
POLL_INTERVAL=10
TIMEOUT_MIN=45

# ── Parse args ───────────────────────────────────────────────────────────
# Pre-process so both --key=value AND --key value forms work. The README
# examples use --key=value form; the original case-statement only matched
# space-separated form, which made the documented examples error out
# with "Unknown arg".
PARSED_ARGS=()
for raw_arg in "$@"; do
  if [[ "$raw_arg" == --*=* ]]; then
    PARSED_ARGS+=("${raw_arg%%=*}" "${raw_arg#*=}")
  else
    PARSED_ARGS+=("$raw_arg")
  fi
done
set -- "${PARSED_ARGS[@]}"

while [[ $# -gt 0 ]]; do
  case $1 in
    --api-url)       API_URL="$2"; shift 2 ;;
    --api-token)     API_TOKEN="$2"; shift 2 ;;
    --repo-id)       REPO_ID="$2"; shift 2 ;;
    --container-id)  CONTAINER_ID="$2"; shift 2 ;;
    --domain-id)     DOMAIN_ID="$2"; shift 2 ;;
    --scan-types)    SCAN_TYPES="$2"; shift 2 ;;
    --severity-gate) SEVERITY_GATE="$2"; shift 2 ;;
    --poll-interval) POLL_INTERVAL="$2"; shift 2 ;;
    --timeout-min)   TIMEOUT_MIN="$2"; shift 2 ;;
    -h|--help)
      sed -n 's/^# //p' "$0" | head -30
      exit 0
      ;;
    *)
      echo "Unknown arg: $1" >&2
      exit 2
      ;;
  esac
done

# ── Colour helpers ───────────────────────────────────────────────────────
if [[ -t 1 ]]; then
  C_RED=$'\033[31m'; C_GREEN=$'\033[32m'; C_YELLOW=$'\033[33m'
  C_BLUE=$'\033[34m'; C_DIM=$'\033[2m'; C_BOLD=$'\033[1m'; C_RESET=$'\033[0m'
else
  C_RED=""; C_GREEN=""; C_YELLOW=""; C_BLUE=""; C_DIM=""; C_BOLD=""; C_RESET=""
fi

step()    { printf "%s▸%s %s\n" "${C_BLUE}${C_BOLD}" "${C_RESET}" "$1"; }
ok()      { printf "  %s✓%s %s\n" "${C_GREEN}" "${C_RESET}" "$1"; }
warn()    { printf "  %s!%s %s\n" "${C_YELLOW}" "${C_RESET}" "$1"; }
fail()    { printf "  %s✗%s %s\n" "${C_RED}" "${C_RESET}" "$1" >&2; exit 1; }
detail()  { printf "    %s%s%s\n" "${C_DIM}" "$1" "${C_RESET}"; }

# ── Validate inputs ──────────────────────────────────────────────────────
step "Validating inputs"
[[ -z "$API_TOKEN" ]] && fail "BREACHLENS_API_TOKEN not set. Mint via Settings → API Tokens."
[[ "$API_TOKEN" =~ ^blt_ ]] || warn "Token doesn't start with blt_ — verify you copied the full plaintext."

TARGETS_SET=0
[[ -n "$REPO_ID" ]]      && TARGETS_SET=$((TARGETS_SET + 1))
[[ -n "$CONTAINER_ID" ]] && TARGETS_SET=$((TARGETS_SET + 1))
[[ -n "$DOMAIN_ID" ]]    && TARGETS_SET=$((TARGETS_SET + 1))
[[ $TARGETS_SET -eq 0 ]] && fail "Set one of BREACHLENS_REPO_ID / BREACHLENS_CONTAINER_ID / BREACHLENS_DOMAIN_ID."
[[ $TARGETS_SET -gt 1 ]] && fail "Multiple targets set — pick exactly one."

case "$SEVERITY_GATE" in
  CRITICAL|HIGH|MEDIUM|LOW|INFO|none) ;;
  *) fail "Invalid --severity-gate '$SEVERITY_GATE' (use CRITICAL|HIGH|MEDIUM|LOW|INFO|none)" ;;
esac

ok "API URL:       $API_URL"
ok "Token prefix:  ${API_TOKEN:0:12}…"
if [[ -n "$REPO_ID" ]];      then ok "Target:        repo $REPO_ID";
elif [[ -n "$CONTAINER_ID" ]]; then ok "Target:        container $CONTAINER_ID";
else                              ok "Target:        domain $DOMAIN_ID";
fi
ok "Severity gate: $SEVERITY_GATE"

# ── Sanity: token works ──────────────────────────────────────────────────
step "Verifying token (GET /api/auth/tokens)"
HTTP=$(curl -sS -o /tmp/bl-tokens.json -w "%{http_code}" \
  -H "Authorization: Bearer $API_TOKEN" \
  "$API_URL/api/auth/tokens")
if [[ "$HTTP" == "200" ]]; then
  COUNT=$(jq '.tokens | length' /tmp/bl-tokens.json)
  ok "Token valid ($COUNT token(s) visible to this org)"
elif [[ "$HTTP" == "401" ]]; then
  fail "Token rejected — verify it's not revoked + hasn't expired"
else
  fail "Unexpected HTTP $HTTP from /api/auth/tokens"
fi

# ── Trigger scan ─────────────────────────────────────────────────────────
step "Triggering scan"
if [[ -n "$REPO_ID" ]];      then ENDPOINT="$API_URL/api/repos/$REPO_ID/scan";
elif [[ -n "$CONTAINER_ID" ]]; then ENDPOINT="$API_URL/api/containers/$CONTAINER_ID/scan";
else                              ENDPOINT="$API_URL/api/domains/$DOMAIN_ID/scan";
fi

if [[ -n "$SCAN_TYPES" ]]; then
  BODY=$(jq -nc --arg types "$SCAN_TYPES" '{ scanTypes: ($types | split(",")) }')
else
  BODY='{}'
fi

detail "POST $ENDPOINT"
detail "body: $BODY"

RESPONSE=$(curl -fsS -X POST "$ENDPOINT" \
  -H "Authorization: Bearer $API_TOKEN" \
  -H "Content-Type: application/json" \
  -d "$BODY")

SCAN_ID=$(echo "$RESPONSE" | jq -r '.id // .scanJobId // empty')
[[ -z "$SCAN_ID" ]] && fail "Couldn't extract scan ID from response: $RESPONSE"
ok "Scan triggered: $SCAN_ID"

# ── Poll for completion ──────────────────────────────────────────────────
step "Polling for completion (timeout ${TIMEOUT_MIN} min, poll every ${POLL_INTERVAL}s)"
DEADLINE=$(( $(date +%s) + (TIMEOUT_MIN * 60) ))
STATUS=PENDING
while [[ "$STATUS" != "COMPLETED" && "$STATUS" != "FAILED" ]]; do
  if (( $(date +%s) > DEADLINE )); then
    fail "Scan exceeded ${TIMEOUT_MIN}-minute timeout (last status: $STATUS)"
  fi
  sleep "$POLL_INTERVAL"
  STATUS=$(curl -fsS "$API_URL/api/scans/$SCAN_ID" \
    -H "Authorization: Bearer $API_TOKEN" | jq -r '.status // "UNKNOWN"')
  detail "[$(date +%H:%M:%S)] status: $STATUS"
done
[[ "$STATUS" == "FAILED" ]] && fail "Scan reported FAILED"
ok "Scan COMPLETED"

# ── Fetch SARIF ──────────────────────────────────────────────────────────
step "Fetching SARIF"
SARIF_PATH="/tmp/breachlens-${SCAN_ID}.sarif"
HTTP=$(curl -sS -o "$SARIF_PATH" -w "%{http_code}" \
  -H "Authorization: Bearer $API_TOKEN" \
  "$API_URL/api/scans/$SCAN_ID/export.sarif")
[[ "$HTTP" != "200" ]] && fail "SARIF fetch returned HTTP $HTTP"

BYTES=$(wc -c < "$SARIF_PATH")
SCHEMA=$(jq -r '.["$schema"] // empty' "$SARIF_PATH")
VERSION=$(jq -r '.version // empty' "$SARIF_PATH")
RULES=$(jq '[.runs[].tool.driver.rules[]] | length' "$SARIF_PATH")
RESULTS=$(jq '[.runs[].results[]] | length' "$SARIF_PATH")

ok "Wrote $SARIF_PATH ($BYTES bytes)"
ok "Schema: $SCHEMA"
ok "Version: $VERSION"
ok "Rules: $RULES, Results: $RESULTS"

[[ "$VERSION" != "2.1.0" ]] && warn "Expected SARIF 2.1.0, got $VERSION"

# ── Count findings by severity ───────────────────────────────────────────
step "Severity breakdown"
CRITICAL=$(jq '[.runs[].results[] | select(.properties.severity == "CRITICAL")] | length' "$SARIF_PATH")
HIGH=$(jq     '[.runs[].results[] | select(.properties.severity == "HIGH")]     | length' "$SARIF_PATH")
MEDIUM=$(jq   '[.runs[].results[] | select(.properties.severity == "MEDIUM")]   | length' "$SARIF_PATH")
LOW=$(jq      '[.runs[].results[] | select(.properties.severity == "LOW")]      | length' "$SARIF_PATH")
INFO=$(jq     '[.runs[].results[] | select(.properties.severity == "INFO")]     | length' "$SARIF_PATH")

printf "  %s%-12s%s %s%5d%s\n" "${C_RED}"     "Critical:" "${C_RESET}" "${C_RED}"     "$CRITICAL" "${C_RESET}"
printf "  %s%-12s%s %s%5d%s\n" "${C_RED}"     "High:"     "${C_RESET}" "${C_RED}"     "$HIGH"     "${C_RESET}"
printf "  %s%-12s%s %s%5d%s\n" "${C_YELLOW}"  "Medium:"   "${C_RESET}" "${C_YELLOW}"  "$MEDIUM"   "${C_RESET}"
printf "  %s%-12s%s %5d\n"     "${C_BLUE}"    "Low:"      "${C_RESET}"                "$LOW"
printf "  %s%-12s%s %5d\n"     "${C_DIM}"     "Info:"     "${C_RESET}"                "$INFO"

# ── Apply severity gate ──────────────────────────────────────────────────
step "Severity gate ($SEVERITY_GATE)"
GATE_FAIL=0
case "$SEVERITY_GATE" in
  CRITICAL) (( CRITICAL > 0 )) && GATE_FAIL=$CRITICAL ;;
  HIGH)     GATE_FAIL=$((CRITICAL + HIGH)) ;;
  MEDIUM)   GATE_FAIL=$((CRITICAL + HIGH + MEDIUM)) ;;
  LOW)      GATE_FAIL=$((CRITICAL + HIGH + MEDIUM + LOW)) ;;
  INFO)     GATE_FAIL=$((CRITICAL + HIGH + MEDIUM + LOW + INFO)) ;;
  none)     ok "Gate disabled — would not fail build"; GATE_FAIL=0 ;;
esac
if (( GATE_FAIL > 0 )); then
  fail "Gate would fail the build: $GATE_FAIL finding(s) at $SEVERITY_GATE-or-above"
fi

step "End-to-end test ${C_GREEN}${C_BOLD}PASSED${C_RESET}"
detail "scan-id:    $SCAN_ID"
detail "sarif-file: $SARIF_PATH"
detail ""
detail "Next: copy this Action's example-workflow.yml into a real repo and"
detail "      replace the local API URL with your deployment's public URL."
