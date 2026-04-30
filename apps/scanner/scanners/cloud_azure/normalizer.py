"""
Prowler OCSF → BreachLens NormalizedFinding mapping.

Field source map (post-normalizer-rewrite):

  Field            ← OCSF source                              Why
  ─────────────────────────────────────────────────────────────────────
  title            ← derive_title(message, resource, account) FAIL-aware
                                                              narrative,
                                                              with resource
                                                              name + sub
                                                              stripped (those
                                                              are columns).
  description      ← risk_details                              "Why does this
                                                              matter" — the
                                                              business
                                                              impact prose,
                                                              what an AI
                                                              analyst should
                                                              read first.
                                                              Fallback to
                                                              finding_info.desc.
  remediation      ← remediation.desc + unmapped.notes        How to fix +
                                                              short
                                                              operational note.
  references       ← remediation.references                    Prowler hub
                                                              + Microsoft
                                                              Learn URLs.
  evidence.azure.* ← cloud.account/org + resources[0].*       Subscription
                                                              + tenant +
                                                              resource
                                                              identity.
  evidence.compl.. ← unmapped.compliance                       Framework
                                                              mappings.
  evidence.cat..   ← unmapped.categories                       e.g.
                                                              "internet-
                                                              exposed".
  evidence.message ← message                                   Prowler's full
                                                              FAIL narrative
                                                              kept verbatim
                                                              for the AI
                                                              analyst's
                                                              context.


Prowler 4.x emits findings as OCSF v1.1 `compliance_finding` records when
invoked with `--output-modes json-ocsf`. This module maps each OCSF
finding into a `NormalizedFinding` ready for upsert via the API's
findingService.

Why we only emit findings for status FAIL:
  Prowler reports both PASS and FAIL records. PASS records exist so
  compliance reports can show "rule X applied to N resources, all
  compliant". BreachLens already shows PASS-counts in the scan summary,
  and emitting them as Findings would 10x the row count without value.

Severity mapping:
  Prowler uses an "Informational | Low | Medium | High | Critical"
  severity scale; we map 1-1 with the BreachLens enum.

Confidence:
  CSPM checks are deterministic on resource state — Prowler reads the
  Azure ARM API and asserts a property. There's no probabilistic
  detection. Hence confidence = LIKELY by default. The CONFIRMED tier
  is reserved for in-platform proof-of-exploit (PENTEST tools that
  reproduce the issue with a payload); a CSPM check that says
  "storage allows public blob access" is strong evidence the
  configuration is wrong, but doesn't itself prove an attacker is
  exploiting it.

References:
  Prowler exposes `remediation.references` as an array of objects with
  `url` field. We surface those plus the canonical Microsoft Learn
  link Prowler stores under `metadata.event_code`'s associated
  documentation when present.
"""
from __future__ import annotations

import re
from typing import Any, Optional

from models import (
    Confidence,
    NormalizedFinding,
    ScanRequest,
    ScanType,
    Severity,
)
from ..base import BaseScanner


# ── Severity translation ────────────────────────────────────────────────

_PROWLER_SEVERITY_MAP: dict[str, Severity] = {
    "CRITICAL":      Severity.CRITICAL,
    "HIGH":          Severity.HIGH,
    "MEDIUM":        Severity.MEDIUM,
    "LOW":           Severity.LOW,
    "INFORMATIONAL": Severity.INFO,
    "INFO":          Severity.INFO,  # alt spelling
}


def _coerce_severity(raw: Any) -> Severity:
    if not raw:
        return Severity.INFO
    return _PROWLER_SEVERITY_MAP.get(str(raw).upper(), Severity.INFO)


# ── OCSF accessors ──────────────────────────────────────────────────────
# OCSF v1.1 lays out the compliance_finding object with several nested
# wrappers; these helpers keep the normalizer readable.

def _first_resource(item: dict) -> dict:
    """OCSF compliance_finding.resources[] — pick the first; CSPM checks
    are normally scoped to one resource per finding. Empty dict on miss
    so downstream `.get()` calls don't blow up."""
    resources = item.get("resources") or []
    return resources[0] if resources else {}


def _cloud_block(item: dict) -> dict:
    """OCSF compliance_finding.cloud is at the TOP LEVEL of the
    finding, NOT nested inside resources[0]. Earlier versions of this
    normalizer mistakenly read `resources[0].cloud` (which is empty)
    and lost the subscription / account / tenant context. This helper
    encapsulates the correct path."""
    return item.get("cloud") or {}


def _unmapped_block(item: dict) -> dict:
    """OCSF spec relegates provider-specific extras to `unmapped`.
    Prowler stuffs `notes`, `categories`, and `compliance` here. We
    surface all three on the BreachLens evidence record."""
    return item.get("unmapped") or {}


def _derive_title(message: str, resource_name: Optional[str], account_name: Optional[str]) -> str:
    """Strip resource-name + subscription-name boilerplate from the OCSF
    `message` so the title reads as a pure issue statement.

    Operator feedback: the title was "VM wazuh-deployemtn in subscription
    PROD_INFRASTRUCTURE01 does not have JIT access enabled." — but
    Resource, Resource Type, and Account already have their own columns
    in the table. The title should focus on the FINDING NATURE, not
    repeat what's already on the row.

    Examples (input → output):

      "Storage account cvsstrgaccount26042026 from subscription
       PROD_INFRASTRUCTURE01 has shared key access enabled."
        → "Storage account has shared key access enabled."

      "VM wazuh-deployemtn in subscription PROD_INFRASTRUCTURE01
       does not have JIT (Just-in-Time) access enabled."
        → "VM does not have JIT (Just-in-Time) access enabled."

      "Subscription PROD_INFRASTRUCTURE01 does not have Defender
       for Servers enabled."
        → "Subscription does not have Defender for Servers enabled."

    Implementation:
      1. Remove the resource-name token (e.g. "cvsstrgaccount26042026").
      2. Remove the "(from|in) subscription <NAME>" clause.
      3. Collapse double-spaces, capitalise the leading char.

    Returns the original message verbatim if no transformation applied
    (better than risking a malformed string from a regex miss).
    """
    if not message:
        return ""
    title = message

    # 1. Drop the resource-name occurrence ("Storage account
    #    cvsstrgaccount26042026 has..." → "Storage account has...").
    if resource_name:
        title = re.sub(
            r'\s+' + re.escape(resource_name) + r'(?=\s)',
            '',
            title,
        )

    # 2. Drop "(from|in) subscription <NAME>" — both prepositions show up
    #    across Prowler's check phrasings ("from subscription X" for
    #    storage / sql / cosmosdb, "in subscription X" for vm / aks).
    if account_name:
        title = re.sub(
            r'\s+(?:from|in)\s+subscription\s+' + re.escape(account_name) + r'\b',
            '',
            title,
            flags=re.IGNORECASE,
        )
    # Generic fallback when account_name isn't available — strips the
    # whole clause regardless of subscription value.
    title = re.sub(
        r'\s+(?:from|in)\s+subscription\s+\S+',
        '',
        title,
        flags=re.IGNORECASE,
    )

    # 3. Cleanup
    title = re.sub(r'\s+', ' ', title).strip()
    if title and title[0].islower():
        title = title[0].upper() + title[1:]
    return title


def _check_id(item: dict) -> str:
    """Prowler stores its native check id (e.g.
    'storage_default_network_access_rule_is_denied') under
    metadata.event_code AND finding_info.uid in different versions —
    fall through both for forward-compat."""
    md = item.get("metadata") or {}
    if md.get("event_code"):
        return str(md["event_code"])
    fi = item.get("finding_info") or {}
    if fi.get("uid"):
        return str(fi["uid"])
    return "unknown-check"


def _remediation_text(item: dict) -> Optional[str]:
    rem = item.get("remediation") or {}
    desc = rem.get("desc")
    return str(desc) if desc else None


def _remediation_references(item: dict) -> list[str]:
    rem = item.get("remediation") or {}
    refs = rem.get("references") or []
    out: list[str] = []
    for r in refs:
        if isinstance(r, str):
            out.append(r)
        elif isinstance(r, dict):
            url = r.get("url") or r.get("href")
            if url:
                out.append(str(url))
    return out


def _github_repo_metadata(item: dict) -> Optional[dict]:
    """Phase 29 Slice C1.5a — Extract GitHub repo state from a finding's
    `resources[0].data.metadata` block.

    Prowler's GitHub provider ships an unusually rich metadata payload:
    every finding contains a complete posture snapshot of its target
    repository (12 branch-protection booleans + 6 hygiene flags + last-
    push timestamp + visibility/archived state).

    Returns None for org-level findings where the resource isn't a
    repository (the 5 org-level Prowler checks scope to the org itself,
    not a repo).
    """
    resource = _first_resource(item)
    if (resource.get("group") or {}).get("name") != "repository":
        return None
    metadata = (resource.get("data") or {}).get("metadata") or {}
    if not metadata:
        return None
    return {
        "fullName":                metadata.get("full_name"),
        "owner":                   metadata.get("owner"),
        "private":                 metadata.get("private"),
        "archived":                metadata.get("archived"),
        "pushedAt":                metadata.get("pushed_at"),
        "secretScanningEnabled":   metadata.get("secret_scanning_enabled"),
        "dependabotAlertsEnabled": metadata.get("dependabot_alerts_enabled"),
        "securitymd":              metadata.get("securitymd"),
        "codeownersExists":        metadata.get("codeowners_exists"),
        "immutableReleasesEnabled": metadata.get("immutable_releases_enabled"),
        "deleteBranchOnMerge":     metadata.get("delete_branch_on_merge"),
        "defaultBranch":           metadata.get("default_branch"),  # full sub-object — 12 booleans + name + approval_count
    }


def _additional_urls(item: dict) -> list[str]:
    """Phase 29 Slice C1.5a — separate from `remediation.references`.
    Prowler GitHub findings carry `unmapped.additional_urls` with links
    to GitHub's own docs; surface them in the drawer's Documentation
    section so operators can learn-more without leaving BreachLens."""
    unmapped = _unmapped_block(item)
    raw = unmapped.get("additional_urls") or []
    if not isinstance(raw, list):
        return []
    return [str(u) for u in raw if u]


def _compliance_frameworks(item: dict) -> dict[str, list[str]]:
    """Prowler's OCSF output stores compliance mappings under unmapped
    when no canonical OCSF field exists. Shape varies by version:
        unmapped.compliance: { "CIS-2.0-Azure": ["1.1.1", "1.1.2"], ... }
    Returns the dict as-is; consumers can downstream-map to BreachLens
    compliance frameworks (Phase 16 mapping service)."""
    unmapped = item.get("unmapped") or {}
    compliance = unmapped.get("compliance") or {}
    if not isinstance(compliance, dict):
        return {}
    cleaned: dict[str, list[str]] = {}
    for k, v in compliance.items():
        if isinstance(v, list):
            cleaned[str(k)] = [str(x) for x in v]
        elif isinstance(v, str):
            cleaned[str(k)] = [v]
    return cleaned


# ── Public entry point ──────────────────────────────────────────────────

def normalize_prowler_findings(
    prowler_data: list[dict],
    request: ScanRequest,
) -> list[NormalizedFinding]:
    """Map a Prowler json-ocsf output array into NormalizedFinding[].

    Skips PASS / MANUAL records — only FAIL records become findings. The
    scan summary view shows pass/fail counts via the raw Prowler output
    so consumers who care about coverage still see them; finding rows
    stay focused on actionable misconfigs.
    """
    if not isinstance(prowler_data, list):
        return []

    findings: list[NormalizedFinding] = []
    creds = request.cloud_credentials
    subscription_id = creds.subscription_id if creds else None

    for item in prowler_data:
        if not isinstance(item, dict):
            continue

        # Status filter — drop PASS + MANUAL. Prowler uses status_code
        # under finding_info or top-level depending on version; check
        # both. Default-skip on missing field (don't accidentally emit
        # everything).
        status = (
            item.get("status_code")
            or (item.get("finding_info") or {}).get("status_code")
            or item.get("status")
            or ""
        )
        if str(status).upper() not in ("FAIL", "FAILED", "FAIL_OPEN"):
            continue

        # Resource block (resources[0]) — describes the AZURE OBJECT the
        # finding applies to (vm/storage account/keyvault/etc).
        resource          = _first_resource(item)
        resource_uid      = str(resource.get("uid")  or resource.get("id") or "unknown")
        resource_name     = str(resource.get("name") or resource_uid.split("/")[-1] or resource_uid)
        resource_type     = str(resource.get("type") or "unknown")
        resource_region   = resource.get("region")
        resource_group    = (resource.get("group") or {}).get("name")
        cloud_partition   = resource.get("cloud_partition")

        # Cloud block is TOP-LEVEL (not nested in resources). Carries
        # subscription / tenant identity. Earlier versions of this
        # normalizer read `resources[0].cloud` and lost everything.
        cloud         = _cloud_block(item)
        account       = cloud.get("account") or {}
        org           = cloud.get("org") or {}
        account_uid   = str(account.get("uid")  or subscription_id or "unknown")
        account_name  = account.get("name")          # e.g. "PROD_INFRASTRUCTURE01"
        tenant_uid    = org.get("uid")                # tenant GUID
        tenant_name   = org.get("name")               # often "Unknown tenant domain (missing AAD permissions)"
        cloud_region  = cloud.get("region")           # subscription region
        provider_name = cloud.get("provider")         # "azure"

        # Title — derive from the FAIL-aware `message`, with the
        # resource name + subscription clause stripped (those are
        # already shown in the Resource and Account columns). Operator
        # feedback: "subscription name and storage account name … is
        # not required. Focus on the finding."
        finding_info = item.get("finding_info") or {}
        message      = (item.get("message") or "").strip()
        if message:
            title = _derive_title(message, resource_name, account_name)
        else:
            # Fallback for older Prowler versions: use finding_info.title
            # raw. Operator's other UI cues (severity badge, OPEN status)
            # signal that the title's a FAIL.
            title = finding_info.get("title") or item.get("title") or "Cloud misconfiguration"

        # Description — Prowler ships TWO description-like fields:
        #   risk_details      — explains WHY the misconfig matters
        #                       (business impact prose: "Allowing Shared
        #                       Key undermines confidentiality… A leaked
        #                       key grants broad read/write/delete…").
        #                       This is what an operator (and the AI
        #                       analyst) wants to read first.
        #   finding_info.desc — describes the CHECK CRITERION ("Storage
        #                       accounts are evaluated for whether
        #                       Shared Key authorization is disabled…").
        #                       Useful as fallback but doesn't explain
        #                       impact.
        # Use risk_details when present, fall through to finding_info.desc.
        risk_details = (item.get("risk_details") or "").strip()
        description  = risk_details or finding_info.get("desc") or item.get("desc") or ""

        # Severity
        severity_raw = item.get("severity") or finding_info.get("severity")
        severity     = _coerce_severity(severity_raw)

        # Check id (used for fingerprinting + UI rule_id)
        check_id = _check_id(item)

        # Unmapped block — Prowler-specific extras OCSF doesn't model:
        #   notes      — short remediation hint ("Enable Defender for
        #                Servers Standard tier in Azure Portal.")
        #   categories — semantic tags (["internet-exposed"])
        #   compliance — framework → controls mapping (already extracted)
        unmapped         = _unmapped_block(item)
        prowler_notes    = unmapped.get("notes") or None
        prowler_categories = unmapped.get("categories") or []
        if not isinstance(prowler_categories, list):
            prowler_categories = []

        # Fingerprint: stable across runs for same (account, resource,
        # check). NOTE: BaseScanner.compute_fingerprint signature takes
        # file_path + line; we pass the resource_uid as file_path for
        # CSPM (the "file" is the cloud resource) and 0 line.
        fingerprint = BaseScanner.compute_fingerprint(
            org_id=request.org_id,
            target_id=request.target_id,
            scan_type=request.scan_type,
            rule_id=check_id,
            file_path=resource_uid,
            line=0,
        )

        # Evidence — provider-shaped + Prowler-specific data the UI /
        # correlation engine / AI analyst all consume. Provider-specific
        # blocks (azure / github / aws / gcp) are populated based on
        # cloud.provider so each scan type carries the right context.
        is_github = (provider_name or "").lower() == "github"
        evidence: dict[str, Any] = {
            "source":    "prowler",
            "check_id":  check_id,
            # Categories from Prowler's unmapped.categories — semantic
            # tags like "internet-exposed" / "identity-access" / "secrets"
            # / "software-supply-chain" that operators filter by AND
            # that the AI analyst can use for context.
            "categories": prowler_categories,
            # Prowler's quick remediation hint (one-liner). The full
            # markdown remediation is on Finding.remediation; this is
            # the shorter operational note ("Enable Defender for X in
            # Azure Portal" etc).
            "prowlerNotes": prowler_notes,
            # Keep the full FAIL narrative verbatim. The Title was
            # derived from this (with resource + sub stripped) — the
            # AI analyst gets the unstripped version here for richer
            # context when re-analysing.
            "message":      message or None,
            "compliance":   _compliance_frameworks(item),
        }

        if is_github:
            # Phase 29 Slice C1.5a — GitHub posture extraction.
            # Repository sub-block carries the full per-repo state
            # (branch protection + hygiene flags) so the drawer can
            # render the 12-row checklist without re-querying GitHub.
            evidence["github"] = {
                "accountLogin":   account_uid,                  # "fayezrajab84-hue"
                "repository":     _github_repo_metadata(item),  # None for org-level findings
                "additionalUrls": _additional_urls(item),
            }
        else:
            # Default Azure-shape (Slice A). Future C2 will add aws,
            # C3 will add m365 etc — branch the same way.
            evidence["azure"] = {
                "subscriptionId":   account_uid,
                "subscriptionName": account_name,             # "PROD_INFRASTRUCTURE01" — recognisable label
                "tenantId":         tenant_uid,
                "tenantName":       tenant_name,
                "resourceId":       resource_uid,
                "resourceType":     resource_type,
                "resourceName":     resource_name,
                "region":           resource_region or cloud_region,
                "serviceGroup":     resource_group,            # "vm" / "storage" / etc — Prowler's authoritative grouping
                "cloudPartition":   cloud_partition,           # "AzureCloud" / "AzureUSGovernment" / etc
                "provider":         provider_name,
            }

        # Sanitise: drop None values from nested provider dicts + top-level
        # for compact JSON in the DB.
        if "azure" in evidence:
            evidence["azure"] = {k: v for k, v in evidence["azure"].items() if v is not None}
        if "github" in evidence:
            # Drop None repository for org-level findings; drop empty
            # additionalUrls so the drawer doesn't render a blank section.
            gh = evidence["github"]
            if gh.get("repository") is None:
                gh.pop("repository", None)
            if not gh.get("additionalUrls"):
                gh.pop("additionalUrls", None)
        if not evidence["categories"]:
            evidence.pop("categories")
        if evidence["prowlerNotes"] is None or evidence["prowlerNotes"] == "":
            evidence.pop("prowlerNotes")
        if evidence["message"] is None:
            evidence.pop("message")

        # Combine Prowler's remediation markdown with its short
        # operational note when both exist. The note often calls out
        # WHERE to apply the fix (Azure Portal vs CLI vs ARM template),
        # which the longer markdown sometimes omits.
        rem_text = _remediation_text(item)
        if rem_text and prowler_notes:
            full_remediation = f"{rem_text}\n\n**Note:** {prowler_notes}"
        elif rem_text:
            full_remediation = rem_text
        elif prowler_notes:
            full_remediation = prowler_notes
        else:
            full_remediation = None

        findings.append(NormalizedFinding(
            fingerprint=fingerprint,
            rule_id=check_id,
            title=title,
            description=description,
            severity=severity,
            scan_type=request.scan_type,
            scanner="prowler",
            file_path=resource_uid,    # the resource arn IS the locator
            remediation=full_remediation,
            references=_remediation_references(item),
            raw_output=item,
            evidence=evidence,
            confidence=Confidence.LIKELY,
        ))

    return findings
