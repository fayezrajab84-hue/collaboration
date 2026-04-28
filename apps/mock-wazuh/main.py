"""
Mock Wazuh REST API — Phase 28 Slice C (W3) validation.

A tiny FastAPI service that imitates the two Wazuh Manager API endpoints
``wazuhIngestService`` calls:

  - POST /security/user/authenticate  — Basic Auth → returns a fake JWT
  - POST /security/events/_search     — Bearer auth → returns canned alerts

Purpose: validates the wazuhIngestService HTTP code path + runtimeBridge
end-to-end without spinning up the real Wazuh stack (manager + indexer +
dashboard ≈ 3 GB of images). Operators wanting a real EDR deployment
should swap WAZUH_API_URL to point at a real Wazuh manager.

Runs on port 8080. Add as a compose service under ``--profile pentest``
(or always-on; it's <100 MB, no database).
"""
from __future__ import annotations

import logging
import os
from typing import Any

from fastapi import FastAPI, Header, HTTPException, Request

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
log = logging.getLogger("mock-wazuh")

app = FastAPI(title="Mock Wazuh API", version="0.1.0")

# Static credentials — wazuhIngestService passes WAZUH_API_USER + PASSWORD
# via HTTP Basic Auth. Anything will do; document the expected pair.
EXPECTED_USER = os.environ.get("MOCK_WAZUH_USER", "admin")
EXPECTED_PASS = os.environ.get("MOCK_WAZUH_PASSWORD", "admin")
FAKE_JWT      = "mock-wazuh-fake-jwt-not-a-real-token"


# ── Canned alerts ─────────────────────────────────────────────────────────────
#
# Each alert mirrors the Wazuh OpenSearch _source shape that
# wazuhIngestService.normaliseAlert() expects.  Fields used:
#   agent.{id,name}, timestamp, rule.{id,level,description,mitre,groups},
#   location, srcip, full_log
#
# Multiple rule_ids so the hourly-bucket fingerprint doesn't collapse them
# all into one Finding row — gives us 4 distinct RUNTIME findings to chain.

def _alert(
    rule_id: str, level: int, description: str,
    location: str, mitre: list[str], groups: list[str],
    src_ip: str | None = None, agent_id: str = "001", agent_name: str = "dvwa-host",
) -> dict[str, Any]:
    """Build a single Wazuh alert in the OpenSearch _source format."""
    return {
        "agent":     {"id": agent_id, "name": agent_name},
        "timestamp": "2026-04-28T10:30:00.000Z",
        "rule":      {
            "id":          rule_id,
            "level":       level,
            "description": description,
            "mitre":       mitre,
            "groups":      groups,
        },
        "location":  location,
        "srcip":     src_ip,
        "full_log":  description,
    }


# Pre-build the canned alert set. SSH brute-force + privilege escalation +
# file-integrity tampering + outbound C2 — a coherent attack chain a SOC
# would actually triage.
CANNED_ALERTS: list[dict[str, Any]] = [
    _alert("5715", 10, "SSH brute-force attack from 10.0.0.42 (3 failed logins)",
           "/var/log/auth.log", ["T1110.001"], ["authentication_failed", "syslog"],
           src_ip="10.0.0.42"),
    _alert("5503", 12, "Successful sudo to root by 'www-data' — privilege escalation",
           "/var/log/auth.log", ["T1548.003"], ["privilege_escalation", "syslog"]),
    _alert("550",  13, "File integrity violation: /etc/passwd modified outside change window",
           "/etc/passwd", ["T1136.001"], ["syscheck", "file_integrity"]),
    _alert("31100", 9, "Outbound connection to known-malicious IP 198.51.100.13:4444",
           "iptables", ["T1071.001"], ["egress", "command_and_control"],
           src_ip="198.51.100.13"),
]


# ── Wazuh Manager auth endpoint ──────────────────────────────────────────────

@app.post("/security/user/authenticate")
async def authenticate(request: Request) -> dict[str, Any]:
    """
    HTTP Basic Auth → JWT. wazuhIngestService passes WAZUH_API_USER +
    WAZUH_API_PASSWORD as Basic Auth credentials; we accept anything that
    matches our env-configured pair.
    """
    auth_header = request.headers.get("authorization", "")
    if not auth_header.lower().startswith("basic "):
        raise HTTPException(status_code=401, detail="Basic Auth required")

    import base64
    try:
        decoded = base64.b64decode(auth_header.split(" ", 1)[1]).decode("utf-8")
        user, password = decoded.split(":", 1)
    except Exception:
        raise HTTPException(status_code=401, detail="Malformed Basic Auth header")

    if user != EXPECTED_USER or password != EXPECTED_PASS:
        log.warning("auth rejected: user=%r expected=%r", user, EXPECTED_USER)
        raise HTTPException(status_code=401, detail="invalid credentials")

    log.info("auth OK for user=%s — issuing fake JWT", user)
    # Wazuh response shape: {"data": {"token": "<jwt>"}}
    return {"data": {"token": FAKE_JWT}}


# ── Wazuh OpenSearch alerts endpoint ────────────────────────────────────────

@app.post("/security/events/_search")
async def search_events(
    request: Request,
    authorization: str | None = Header(default=None),
) -> dict[str, Any]:
    """
    Returns canned alerts in the OpenSearch ``hits.hits[]._source`` shape
    wazuhIngestService expects. Filters by agent.id when provided in the
    query so the ingestion service correctly sees alerts for the agent
    it asked about.
    """
    if not authorization or not authorization.startswith("Bearer "):
        raise HTTPException(status_code=401, detail="Bearer token required")

    body = await request.json()
    # Pull the requested agent id out of the bool/must/term query — same
    # shape wazuhIngestService.defaultAlertsFetcher constructs.
    requested_agent_id: str | None = None
    try:
        for clause in (body or {}).get("query", {}).get("bool", {}).get("must", []):
            term = clause.get("term", {})
            if "agent.id" in term:
                requested_agent_id = str(term["agent.id"])
                break
    except Exception:
        pass

    matched = [
        a for a in CANNED_ALERTS
        if requested_agent_id is None or a["agent"]["id"] == requested_agent_id
    ]
    log.info(
        "search_events: agent=%s → returning %d alert(s)",
        requested_agent_id, len(matched),
    )

    return {
        "hits": {
            "total": {"value": len(matched), "relation": "eq"},
            "hits":  [{"_source": a} for a in matched],
        },
    }


# ── Health check ─────────────────────────────────────────────────────────────

@app.get("/health")
async def health() -> dict[str, str]:
    return {"status": "ok", "service": "mock-wazuh", "alerts_in_canned_set": str(len(CANNED_ALERTS))}
