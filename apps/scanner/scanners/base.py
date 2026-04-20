from __future__ import annotations
import hashlib
import os
import re as _re
import shutil
import subprocess
import time
import uuid
from abc import ABC, abstractmethod
from typing import Optional

import httpx as _httpx

from config import settings
from models import AuthConfig, AuthType, NormalizedFinding, OAuth2GrantType, ScanRequest, ScanType, Severity

_CLONE_CACHE_DIR = "/tmp/scan_clone_cache"
_CLONE_CACHE_TTL = 1800  # 30 minutes


class BaseScanner(ABC):
    """Abstract base for all security scanners."""

    @abstractmethod
    def scan(self, request: ScanRequest, workspace: str) -> list[NormalizedFinding]:
        """Run the scanner and return normalized findings."""
        ...

    # ── Utilities ──────────────────────────────────────────────────────────

    def run_cmd(
        self,
        cmd: list[str],
        cwd: Optional[str] = None,
        timeout: Optional[int] = None,
        env: Optional[dict] = None,
    ) -> subprocess.CompletedProcess:
        """Run a shell command safely, never logging secrets."""
        return subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            cwd=cwd,
            timeout=timeout or settings.scan_timeout_seconds,
            env={**os.environ, **(env or {})},
        )

    def clone_repo(
        self,
        repo_url: str,
        branch: str,
        git_token: Optional[str],
        target_dir: str,
    ) -> str:
        """Clone repo to target_dir, using a local cache to avoid redundant clones."""
        cache_key = hashlib.sha256(f"{repo_url}:{branch}".encode()).hexdigest()[:24]
        cache_path = os.path.join(_CLONE_CACHE_DIR, cache_key)

        # Use cached clone if fresh
        if os.path.isdir(cache_path):
            age = time.time() - os.path.getmtime(cache_path)
            if age < _CLONE_CACHE_TTL:
                shutil.copytree(cache_path, target_dir, dirs_exist_ok=True)
                return target_dir
            shutil.rmtree(cache_path, ignore_errors=True)

        # Fresh clone
        if git_token:
            parsed = repo_url.replace("https://", f"https://x-access-token:{git_token}@")
        else:
            parsed = repo_url

        cmd = [
            "git", "clone",
            "--depth", str(settings.max_clone_depth),
            "--branch", branch,
            "--single-branch",
            parsed,
            target_dir,
        ]
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=300)
        if result.returncode != 0:
            err = result.stderr.replace(git_token or "", "***") if git_token else result.stderr
            raise RuntimeError(f"Git clone failed: {err[:500]}")

        # Cache for subsequent scan types on the same repo
        os.makedirs(_CLONE_CACHE_DIR, exist_ok=True)
        try:
            shutil.copytree(target_dir, cache_path, dirs_exist_ok=True)
        except Exception:
            pass  # cache write failure is non-fatal

        return target_dir

    @staticmethod
    def compute_fingerprint(
        org_id: str,
        target_id: str,
        scan_type: ScanType,
        rule_id: str,
        file_path: Optional[str],
        line: Optional[int],
    ) -> str:
        raw = f"{org_id}:{target_id}:{scan_type}:{rule_id}:{file_path or ''}:{line or 0}"
        return hashlib.sha256(raw.encode()).hexdigest()

    @staticmethod
    def map_semgrep_severity(sev: str) -> Severity:
        mapping = {
            "CRITICAL": Severity.CRITICAL,
            "ERROR": Severity.HIGH,
            "WARNING": Severity.MEDIUM,
            "INFO": Severity.INFO,
        }
        return mapping.get(sev.upper(), Severity.INFO)

    @staticmethod
    def map_cvss_to_severity(score: Optional[float]) -> Severity:
        if score is None:
            return Severity.INFO
        if score >= 9.0:
            return Severity.CRITICAL
        if score >= 7.0:
            return Severity.HIGH
        if score >= 4.0:
            return Severity.MEDIUM
        if score > 0:
            return Severity.LOW
        return Severity.INFO

    @staticmethod
    def make_workspace() -> str:
        path = os.path.join(settings.scan_workspace_dir, str(uuid.uuid4()))
        os.makedirs(path, exist_ok=True)
        return path

    @staticmethod
    def cleanup(path: str) -> None:
        try:
            shutil.rmtree(path, ignore_errors=True)
        except Exception:
            pass

    @staticmethod
    def obtain_oauth2_token(auth: AuthConfig) -> str | None:
        """
        Exchange OAuth2 credentials for a Bearer access token.

        Supports two grant types:
          • client_credentials — M2M, uses clientId + clientSecret only.
            Ideal for API-only targets that use OAuth2 machine tokens.
          • password (ROPC) — username + password + client credentials.
            Deprecated by OAuth2.1 but still widely used in enterprise apps.

        Returns the access token string (without the "Bearer " prefix),
        or None if the exchange fails.
        """
        if not auth.oauth2_token_url or not auth.oauth2_client_id:
            print("[auth] OAuth2: token_url and client_id are required")
            return None

        payload: dict[str, str] = {
            "grant_type":    auth.oauth2_grant_type.value,
            "client_id":     auth.oauth2_client_id,
            "client_secret": auth.oauth2_client_secret or "",
        }
        if auth.oauth2_scope:
            payload["scope"] = auth.oauth2_scope
        if auth.oauth2_grant_type == OAuth2GrantType.PASSWORD:
            if not auth.username or not auth.password:
                print("[auth] OAuth2 password grant requires username + password")
                return None
            payload["username"] = auth.username
            payload["password"] = auth.password   # never logged

        try:
            with _httpx.Client(timeout=15, verify=False) as client:
                resp = client.post(
                    auth.oauth2_token_url,
                    data=payload,
                    headers={"Accept": "application/json"},
                )
                resp.raise_for_status()
                data = resp.json()
                token = data.get("access_token")
                if not token:
                    print(f"[auth] OAuth2: token endpoint returned no access_token: {list(data.keys())}")
                    return None
                token_type = data.get("token_type", "Bearer")
                print(f"[auth] OAuth2: obtained {token_type} token "
                      f"(expires_in={data.get('expires_in', 'unknown')}s)")
                return token
        except Exception as exc:
            print(f"[auth] OAuth2: token exchange failed: {exc}")
            return None

    @staticmethod
    def obtain_session(auth: AuthConfig, base_url: str) -> str | None:
        """
        Obtain a session cookie string from the target using the supplied auth config.

        - FORM: GET the login page, extract any hidden CSRF tokens, POST credentials,
          verify logged_in_pattern in response, return the full cookie jar.
        - HEADER: not a cookie auth — callers use auth_header_dict() instead.
        - COOKIE: returns header_value directly.

        Returns a cookie string like "PHPSESSID=abc123; security=low" on success,
        or None if login failed / not applicable.
        """
        try:
            if auth.auth_type == AuthType.COOKIE:
                return auth.header_value or None

            if auth.auth_type == AuthType.HEADER:
                # Not a cookie — callers decide how to use the header name/value
                return None

            # ── FORM auth ────────────────────────────────────────────────────
            if not auth.login_url or not auth.username or not auth.password:
                return None

            # Resolve login URL (absolute or path-relative)
            if auth.login_url.startswith("http"):
                login_url = auth.login_url
            else:
                login_url = base_url.rstrip("/") + "/" + auth.login_url.lstrip("/")

            with _httpx.Client(
                timeout=15,
                follow_redirects=True,
                verify=False,
            ) as client:
                # GET the login page to collect pre-login cookies + CSRF tokens
                get_resp = client.get(login_url)
                login_body = get_resp.text or ""

                # Extract hidden inputs (CSRF tokens: user_token, _token, etc.)
                # and submit buttons (some apps require the submit name/value)
                extra_fields: dict[str, str] = {}
                for m in _re.finditer(
                    r'<input[^>]+>',
                    login_body,
                    _re.IGNORECASE,
                ):
                    tag = m.group(0)
                    type_m  = _re.search(r'type=["\']([^"\']+)["\']',  tag, _re.IGNORECASE)
                    name_m  = _re.search(r'name=["\']([^"\']+)["\']',  tag, _re.IGNORECASE)
                    value_m = _re.search(r'value=["\']([^"\']*)["\']', tag, _re.IGNORECASE)
                    if not name_m:
                        continue
                    field_type = (type_m.group(1).lower() if type_m else "text")
                    # Include hidden fields (CSRF tokens) and the first submit button
                    if field_type == "hidden":
                        extra_fields[name_m.group(1)] = value_m.group(1) if value_m else ""
                    elif field_type == "submit" and name_m.group(1) not in extra_fields:
                        extra_fields[name_m.group(1)] = value_m.group(1) if value_m else ""

                # Build POST payload: credentials + CSRF tokens + submit button
                post_data = {
                    **extra_fields,
                    auth.username_field: auth.username,
                    auth.password_field: auth.password,
                }

                # POST credentials
                resp = client.post(login_url, data=post_data)

                # Build the cookie jar string from all accumulated cookies
                cookies = dict(client.cookies)
                if not cookies:
                    return None

                cookie_str = "; ".join(f"{k}={v}" for k, v in cookies.items())

                # Verify login succeeded
                body = resp.text or ""
                if auth.logged_in_pattern:
                    if auth.logged_in_pattern.lower() in body.lower():
                        print(f"[auth] login confirmed via '{auth.logged_in_pattern}' in POST response")
                        return cookie_str

                    # POST may have redirected to index — check the final page
                    check = client.get(base_url)
                    if auth.logged_in_pattern.lower() in (check.text or "").lower():
                        print(f"[auth] login confirmed via '{auth.logged_in_pattern}' in home page")
                        return cookie_str

                    print(f"[auth] WARNING: '{auth.logged_in_pattern}' not found — returning cookies anyway")

                return cookie_str

        except Exception as exc:
            print(f"[auth] obtain_session error: {exc}")
            return None

    @staticmethod
    def auth_header_dict(auth: "AuthConfig | None", session_cookie: "str | None") -> dict[str, str]:
        """
        Build an httpx-compatible headers dict for authenticated requests.

        Priority:
          1. Pre-obtained session_cookie (from FORM login or COOKIE type)
          2. auth_config HEADER type (API key / Bearer)
          3. auth_config OAUTH2 type — exchanges credentials for a Bearer token on first call
          4. Empty dict (unauthenticated)
        """
        if session_cookie:
            return {"Cookie": session_cookie}
        if auth and auth.auth_type == AuthType.HEADER and auth.header_name and auth.header_value:
            return {auth.header_name: auth.header_value}
        if auth and auth.auth_type == AuthType.OAUTH2:
            token = BaseScanner.obtain_oauth2_token(auth)
            if token:
                return {"Authorization": f"Bearer {token}"}
        return {}
