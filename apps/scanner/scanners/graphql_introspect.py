"""
GraphQL endpoint detection + introspection.

Modern apps increasingly expose a single ``/graphql`` POST endpoint instead
of many REST routes — which makes the existing URL-based discovery (Katana,
ffuf, sitemap) blind: a crawler sees one URL, but the API surface behind it
is dozens of queries and mutations.

This module:

  1. Probes a small set of conventional GraphQL paths on the target host
     with a minimal introspection request. If any returns a 200 with a
     well-formed response, that's the endpoint.
  2. Runs the full introspection query against the detected endpoint.
  3. Walks the schema to extract every Query and Mutation field.
  4. For each field, builds a concrete POST request payload (URL + JSON body
     with sample variables filled in).

The output is consumed by DAST / pentest as additional targets — Nuclei
templates have GraphQL-specific tags (``graphql``, ``introspection``), and
ZAP can be seeded with the POST URLs to passive-scan responses.

Notes:
  - We deliberately use *named* operations in the request body so logs and
    the underlying server's tracing can attribute each call back to the
    schema field — mirrors how a real GraphQL client behaves.
  - Sample variable values are minimal (``"test"`` / ``1`` / ``true``); the
    goal is to *invoke* the resolver, not to deeply fuzz it. Downstream
    DAST/pentest tools layer payload mutation on top.
  - Introspection often disabled in production by hardening (``apollo-server``
    config, custom middleware). We treat ``errors`` in the introspection
    response or non-2xx status as "endpoint not introspectable" and return
    an empty operation list — but still flag the endpoint so DAST records
    it as a target for blind probing (Nuclei's `graphql-detect` template
    finds these without needing the schema).
"""
from __future__ import annotations

import json
import logging
from dataclasses import dataclass, field
from typing import Optional
from urllib.parse import urljoin, urlparse

import httpx

log = logging.getLogger("scanner.graphql_introspect")


# ── Constants ──────────────────────────────────────────────────────────────

# Conventional paths to probe. Ordered most-likely first so detection short-
# circuits fast on common deployments.
DEFAULT_PROBE_PATHS = (
    "/graphql",
    "/api/graphql",
    "/v1/graphql",
    "/v2/graphql",
    "/query",          # Hasura, some Apollo configs
    "/api",            # rare but seen on Strapi
    "/graphiql",       # the explorer often shares the path
)

# The GraphQL introspection query — standard form from the spec, abbreviated
# slightly to skip directives and deeply-nested type info we don't use here.
# Must be a single line for httpx body posting.
_INTROSPECTION_QUERY = """
query IntrospectionQuery {
  __schema {
    queryType { name }
    mutationType { name }
    types {
      kind
      name
      fields(includeDeprecated: false) {
        name
        description
        args {
          name
          type { kind name ofType { kind name ofType { kind name } } }
        }
      }
    }
  }
}
""".strip()

# Lightweight detection probe — same as introspection but without args, so a
# server with introspection disabled at the resolver level may still respond
# 200 with errors[]. Either way the endpoint is identified.
_DETECTION_PROBE = '{"query":"{ __typename }"}'

# Cap operations returned to keep DAST scan duration sane on huge schemas
# (Shopify's Storefront has ~150 query fields; that's plenty without going
# unbounded).
MAX_OPERATIONS_PER_TYPE = 100


# ── Data shapes ────────────────────────────────────────────────────────────

@dataclass
class GraphqlOperation:
    """One executable operation derived from the schema."""
    name: str                       # field name from the schema
    op_type: str                    # "query" or "mutation"
    args: list[dict]                # [{name, type_kind, type_name}]
    request_body: str               # JSON-encoded POST body, ready to send

    def as_target(self, endpoint: str) -> dict:
        """Shape DAST / pentest can consume directly."""
        return {
            "url": endpoint,
            "method": "POST",
            "body": self.request_body,
            "content_type": "application/json",
            "operation": f"{self.op_type}:{self.name}",
        }


@dataclass
class IntrospectionResult:
    endpoint: Optional[str] = None
    introspection_enabled: bool = False
    operations: list[GraphqlOperation] = field(default_factory=list)
    detection_path: Optional[str] = None
    error: Optional[str] = None


# ── Public entrypoints ─────────────────────────────────────────────────────

def detect_endpoint(
    base_url: str,
    *,
    probe_paths: tuple[str, ...] = DEFAULT_PROBE_PATHS,
    timeout_secs: float = 5.0,
    extra_headers: Optional[dict[str, str]] = None,
) -> Optional[str]:
    """
    Probe ``base_url`` + each path until one looks like a GraphQL endpoint.

    Returns the absolute URL that responded, or None if none did. The probe
    sends a tiny ``{ __typename }`` query — every spec-compliant server
    answers it with a 200 and JSON containing ``data`` *or* ``errors``. We
    treat either as a positive signal (errors mean "introspection blocked",
    not "wrong URL"). Anything else (4xx/5xx, non-JSON, no response) is a
    negative.
    """
    headers = {"Content-Type": "application/json", "Accept": "application/json"}
    if extra_headers:
        headers.update(extra_headers)

    parsed = urlparse(base_url)
    if not parsed.scheme:
        base_url = "http://" + base_url

    with httpx.Client(timeout=timeout_secs, follow_redirects=True, verify=False) as client:
        for path in probe_paths:
            url = urljoin(base_url + ("/" if not base_url.endswith("/") else ""), path.lstrip("/"))
            try:
                resp = client.post(url, content=_DETECTION_PROBE, headers=headers)
            except Exception as exc:
                log.debug("probe %s failed: %s", url, exc)
                continue
            if resp.status_code != 200:
                continue
            try:
                body = resp.json()
            except Exception:
                continue
            if isinstance(body, dict) and ("data" in body or "errors" in body):
                log.info("graphql endpoint detected at %s (status=%d)", url, resp.status_code)
                return url
    return None


def introspect(
    endpoint: str,
    *,
    timeout_secs: float = 10.0,
    extra_headers: Optional[dict[str, str]] = None,
) -> IntrospectionResult:
    """
    Run the full introspection query against ``endpoint`` and return the
    operations the schema declares.

    On any failure — endpoint unreachable, introspection disabled, malformed
    response — returns an ``IntrospectionResult`` with the error captured but
    still pointing at the endpoint, so downstream code can record the
    endpoint as a target even without the schema.
    """
    headers = {"Content-Type": "application/json", "Accept": "application/json"}
    if extra_headers:
        headers.update(extra_headers)

    body = json.dumps({"query": _INTROSPECTION_QUERY, "operationName": "IntrospectionQuery"})

    try:
        with httpx.Client(timeout=timeout_secs, verify=False) as client:
            resp = client.post(endpoint, content=body, headers=headers)
    except Exception as exc:
        return IntrospectionResult(endpoint=endpoint, error=f"network error: {exc}")

    if resp.status_code != 200:
        return IntrospectionResult(
            endpoint=endpoint,
            error=f"introspection returned status {resp.status_code}",
        )

    try:
        payload = resp.json()
    except Exception as exc:
        return IntrospectionResult(endpoint=endpoint, error=f"non-JSON response: {exc}")

    schema = (payload.get("data") or {}).get("__schema")
    if not schema:
        # Common: introspection disabled — `errors` populated, no data.
        msg = "introspection disabled or denied"
        if isinstance(payload.get("errors"), list) and payload["errors"]:
            first = payload["errors"][0]
            msg += f" ({(first or {}).get('message', '')})"
        return IntrospectionResult(endpoint=endpoint, error=msg)

    query_type_name    = (schema.get("queryType")    or {}).get("name")
    mutation_type_name = (schema.get("mutationType") or {}).get("name")
    types              = schema.get("types") or []

    operations: list[GraphqlOperation] = []
    for t in types:
        if not isinstance(t, dict):
            continue
        type_name = t.get("name")
        if type_name == query_type_name:
            operations.extend(_extract_operations(t, "query", endpoint))
        elif type_name == mutation_type_name:
            operations.extend(_extract_operations(t, "mutation", endpoint))

    return IntrospectionResult(
        endpoint=endpoint,
        introspection_enabled=True,
        operations=operations,
    )


def detect_and_introspect(
    base_url: str,
    *,
    probe_paths: tuple[str, ...] = DEFAULT_PROBE_PATHS,
    extra_headers: Optional[dict[str, str]] = None,
) -> IntrospectionResult:
    """One-shot: detect endpoint, then introspect. The convenience wrapper
    most callers want.
    """
    endpoint = detect_endpoint(
        base_url, probe_paths=probe_paths, extra_headers=extra_headers,
    )
    if not endpoint:
        return IntrospectionResult(error="no graphql endpoint found at common paths")
    result = introspect(endpoint, extra_headers=extra_headers)
    result.detection_path = urlparse(endpoint).path or "/"
    return result


# ── Schema walk helpers ────────────────────────────────────────────────────

def _extract_operations(
    type_def: dict,
    op_type: str,
    endpoint: str,
) -> list[GraphqlOperation]:
    fields = type_def.get("fields") or []
    out: list[GraphqlOperation] = []
    for field in fields[:MAX_OPERATIONS_PER_TYPE]:
        if not isinstance(field, dict):
            continue
        name = field.get("name")
        if not name:
            continue
        args = [_normalize_arg(a) for a in (field.get("args") or [])]
        body = _build_request_body(name, op_type, args)
        out.append(GraphqlOperation(
            name=name,
            op_type=op_type,
            args=args,
            request_body=body,
        ))
    return out


def _normalize_arg(arg: dict) -> dict:
    """Flatten the nested type info into a flat record we can serialize."""
    arg_type = arg.get("type") or {}
    kind, name = _unwrap_type(arg_type)
    return {
        "name": arg.get("name", ""),
        "type_kind": kind,
        "type_name": name,
        "non_null": (arg_type.get("kind") == "NON_NULL"),
    }


def _unwrap_type(t: dict) -> tuple[str, str]:
    """Walk NON_NULL/LIST wrappers down to the named type."""
    while isinstance(t, dict) and t.get("kind") in ("NON_NULL", "LIST") and t.get("ofType"):
        t = t["ofType"]
    if not isinstance(t, dict):
        return ("UNKNOWN", "")
    return (t.get("kind") or "UNKNOWN", t.get("name") or "")


def _sample_value(arg: dict) -> object:
    """
    Pick a deterministic minimal value for a GraphQL arg.

    Mirrors the OpenAPI extractor's philosophy: we want the resolver to
    accept the call, not to deeply fuzz inputs. DAST/pentest tools layer
    real payload mutation on top of these baseline requests.
    """
    name = (arg.get("type_name") or "").lower()
    kind = arg.get("type_kind")
    # Scalar fast path
    if name in ("int", "long", "bigint"):
        return 1
    if name in ("float", "double", "decimal"):
        return 1.0
    if name in ("boolean", "bool"):
        return True
    if name == "id":
        return "1"
    if "uuid" in name:
        return "00000000-0000-0000-0000-000000000000"
    if name in ("datetime", "date"):
        return "2024-01-01T00:00:00Z"
    if kind == "ENUM":
        # We don't have the enum values from the abbreviated introspection;
        # send a literal-shaped string and let the server's coercion answer.
        return "TEST"
    if kind == "INPUT_OBJECT":
        # Empty object is invalid for inputs with required nested fields, but
        # produces a clean GraphQL parse error rather than a 400 — still a
        # signal for DAST.
        return {}
    return "test"


def _build_request_body(
    op_name: str,
    op_type: str,
    args: list[dict],
) -> str:
    """
    Emit a minimal GraphQL POST body that invokes ``op_name`` with sample
    args. Variables are inlined into the document for simplicity — no need
    to maintain a parallel ``variables`` map.
    """
    if not args:
        # Field with no args — selection set must be valid for OBJECT
        # returns; ``__typename`` is universally selectable.
        document = f"{op_type} Probe_{op_name} {{ {op_name} {{ __typename }} }}"
    else:
        # Inline the args: name: <literal>
        rendered: list[str] = []
        for a in args:
            val = _sample_value(a)
            rendered.append(f"{a['name']}: {_to_graphql_literal(val)}")
        arg_str = ", ".join(rendered)
        document = (
            f"{op_type} Probe_{op_name} {{ {op_name}({arg_str}) {{ __typename }} }}"
        )

    return json.dumps({
        "query": document,
        "operationName": f"Probe_{op_name}",
    })


def _to_graphql_literal(value: object) -> str:
    """Format a Python value as a GraphQL literal for inline-arg substitution."""
    if isinstance(value, bool):
        return "true" if value else "false"
    if isinstance(value, (int, float)):
        return str(value)
    if isinstance(value, dict):
        # Empty input object literal — covers our INPUT_OBJECT placeholder.
        if not value:
            return "{}"
        parts = [f"{k}: {_to_graphql_literal(v)}" for k, v in value.items()]
        return "{" + ", ".join(parts) + "}"
    if isinstance(value, list):
        return "[" + ", ".join(_to_graphql_literal(v) for v in value) + "]"
    # String — escape just enough for safety. GraphQL strings use double quotes.
    s = str(value).replace("\\", "\\\\").replace('"', '\\"')
    return f'"{s}"'


__all__ = [
    "GraphqlOperation",
    "IntrospectionResult",
    "detect_endpoint",
    "introspect",
    "detect_and_introspect",
    "DEFAULT_PROBE_PATHS",
]
