import asyncio
import logging
import time
from concurrent.futures import ThreadPoolExecutor
from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware


class _SuppressHealthCheck(logging.Filter):
    """Drop uvicorn access-log lines for GET /health — pure health-check noise."""
    def filter(self, record: logging.LogRecord) -> bool:
        return "GET /health" not in record.getMessage()


logging.getLogger("uvicorn.access").addFilter(_SuppressHealthCheck())

from models import ReconRequest, ReconResult, ScanRequest, ScanResult, ScanType, VerifyRequest, VerifyResponse
from scanners import (
    SASTScanner,
    SCAScanner,
    SecretsScanner,
    IACScanner,
    ContainerScanner,
    DASTScanner,
    PentestScanner,
    PentestFullScanner,
)
from scanners.pentest_full.recon import ReconScanner
from scanners.verify import verify_finding
from scanners.dast_interactive import InteractiveDASTSession

app = FastAPI(
    title="DevSecOps Scanner Service",
    description="Orchestrates security scanning tools",
    version="0.1.0",
)

# Thread pool for blocking scanner work — keeps the async event loop free so
# health checks and other requests are served even during long scans.
_executor = ThreadPoolExecutor(max_workers=8)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # Internal service — API handles auth
    allow_methods=["*"],
    allow_headers=["*"],
)

SCANNER_MAP = {
    ScanType.SAST: SASTScanner,
    ScanType.SCA: SCAScanner,
    ScanType.SECRET: SecretsScanner,
    ScanType.IAC: IACScanner,
    ScanType.CONTAINER: ContainerScanner,
    ScanType.DAST: DASTScanner,
    ScanType.PENTEST: PentestScanner,
    ScanType.PENTEST_FULL: PentestFullScanner,
}


@app.get("/health")
async def health():
    return {"status": "ok", "service": "scanner"}


@app.post("/recon", response_model=ReconResult, response_model_by_alias=True)
async def run_recon(request: ReconRequest) -> ReconResult:
    """
    Lightweight recon endpoint — runs subfinder + httpx to discover and probe subdomains.
    Used by the pentest wizard before the user confirms scope.
    Returns in ~1-2 minutes; does NOT create a ScanJob.
    """
    start_ms = int(time.time() * 1000)
    scanner = ReconScanner()
    workspace = scanner.make_workspace()

    def _run():
        try:
            return scanner.scan_for_recon(request.domain)
        finally:
            scanner.cleanup(workspace)

    loop = asyncio.get_event_loop()
    subdomains = await loop.run_in_executor(_executor, _run)
    return ReconResult(
        domain=request.domain,
        subdomains=subdomains,
        duration_ms=int(time.time() * 1000) - start_ms,
    )


@app.post("/verify", response_model=VerifyResponse, response_model_by_alias=True)
async def run_verify(request: VerifyRequest) -> VerifyResponse:
    """
    Re-runs a specific check to confirm whether a finding still exists.
    Used for false-positive triage: if confidence drops the API marks it FIXED.
    """
    loop = asyncio.get_event_loop()
    result = await loop.run_in_executor(_executor, lambda: verify_finding(request))
    return result


@app.post("/sbom")
async def generate_sbom(request: dict):
    """
    Generate a CycloneDX SBOM JSON for a repository or a container image.
    Request body:
      - target_type: "REPOSITORY" | "CONTAINER"
      - image_ref:   when CONTAINER
      - repo_url, branch, git_token: when REPOSITORY
    Returns CycloneDX JSON directly (response is proxied by the API).
    """
    import json as _json
    import subprocess as _subprocess
    from scanners.base import BaseScanner

    target_type = request.get("target_type")
    if target_type not in ("REPOSITORY", "CONTAINER"):
        raise HTTPException(status_code=400, detail="target_type must be REPOSITORY or CONTAINER")

    import tempfile as _tempfile
    import shutil as _shutil
    import os as _os
    scanner = BaseScanner.__subclasses__()[0]()  # any concrete subclass — only using clone_repo/workspace
    workspace = scanner.make_workspace()
    # Per-request trivy cache dir — avoids "cache may be in use by another process: timeout"
    # when a concurrent scan holds the shared cache lock. We copy the existing
    # default cache (if it exists) so we don't re-download the vuln/java DBs.
    trivy_cache = _tempfile.mkdtemp(prefix="trivy-sbom-cache-")
    default_cache = _os.path.expanduser("~/.cache/trivy")
    # Copy only the read-only DB + policy subdirs (via hardlinks to avoid ~1GB duplication).
    # Leave fanal/ (the per-scan state with its lock file) fresh for each request.
    for sub in ("db", "policy"):
        src = _os.path.join(default_cache, sub)
        if _os.path.isdir(src):
            try:
                _shutil.copytree(src, _os.path.join(trivy_cache, sub), copy_function=_os.link)
            except Exception:
                try:
                    _shutil.copytree(src, _os.path.join(trivy_cache, sub), dirs_exist_ok=True)
                except Exception:
                    pass  # copy failure non-fatal — trivy will re-fetch
    # SBOM only needs package inventory — explicitly disable vuln scanning so trivy
    # doesn't try to download/refresh the vuln DB (which also takes the cache lock).
    # Per-request cache dir avoids lock contention with concurrent vuln scans.
    # We still let trivy fetch the Java DB on demand — without it, container SBOMs
    # miss jar packages. The 15m timeout accommodates first-run DB downloads.
    common = [
        "--cache-dir", trivy_cache,
        "--format", "cyclonedx",
        "--quiet",
        "--timeout", "15m",
    ]
    try:
        if target_type == "CONTAINER":
            image_ref = request.get("image_ref")
            if not image_ref:
                raise HTTPException(status_code=400, detail="image_ref required for CONTAINER")
            cmd = ["trivy", "image", *common, image_ref]
        else:
            repo_url = request.get("repo_url")
            branch   = request.get("branch") or "main"
            if not repo_url:
                raise HTTPException(status_code=400, detail="repo_url required for REPOSITORY")
            scanner.clone_repo(repo_url, branch, request.get("git_token"), workspace)
            cmd = ["trivy", "fs", *common, workspace]

        loop = asyncio.get_event_loop()
        result = await loop.run_in_executor(
            _executor,
            lambda: _subprocess.run(cmd, capture_output=True, text=True, timeout=960),
        )
        if result.returncode != 0:
            raise HTTPException(status_code=500, detail=f"trivy failed: {result.stderr[:500]}")
        try:
            return _json.loads(result.stdout or "{}")
        except _json.JSONDecodeError:
            raise HTTPException(status_code=500, detail="trivy returned invalid JSON")
    finally:
        scanner.cleanup(workspace)
        _shutil.rmtree(trivy_cache, ignore_errors=True)


@app.post("/dast/recording/start")
async def dast_recording_start(payload: dict) -> dict:
    """
    Start an interactive DAST recording session.
    Body: { domain: str, contextName: str }
    Returns the ZAP context info the API persists in RecordingSession.
    """
    domain       = payload.get("domain")
    context_name = payload.get("contextName")
    if not domain or not context_name:
        raise HTTPException(status_code=400, detail="domain and contextName required")
    session = InteractiveDASTSession()
    loop    = asyncio.get_event_loop()
    return await loop.run_in_executor(_executor, lambda: session.start(domain, context_name))


@app.post("/dast/recording/stats")
async def dast_recording_stats(payload: dict) -> dict:
    """
    Body: { contextName: str, targetUrl: str }
    Returns { urlCount, alertCount } for the live session.
    """
    context_name = payload.get("contextName")
    target_url   = payload.get("targetUrl")
    if not context_name or not target_url:
        raise HTTPException(status_code=400, detail="contextName and targetUrl required")
    session = InteractiveDASTSession()
    loop    = asyncio.get_event_loop()
    return await loop.run_in_executor(_executor, lambda: session.stats(context_name, target_url))


@app.post("/dast/recording/scan", response_model=ScanResult, response_model_by_alias=True)
async def dast_recording_scan(payload: dict) -> ScanResult:
    """
    Body: ScanRequest fields + { contextId, contextName, targetUrl }
    Returns the ScanResult with normalized findings, same shape as /scan.
    """
    ctx_id       = payload.get("contextId")
    context_name = payload.get("contextName")
    target_url   = payload.get("targetUrl")
    if not ctx_id or not context_name or not target_url:
        raise HTTPException(status_code=400, detail="contextId, contextName, targetUrl required")

    # Reuse ScanRequest validation for the rest of the payload.
    try:
        scan_request = ScanRequest(**{k: v for k, v in payload.items()
                                      if k not in ("contextId", "contextName", "targetUrl")})
    except Exception as exc:
        raise HTTPException(status_code=400, detail=f"invalid scan request: {exc}")

    session = InteractiveDASTSession()
    start_ms = int(time.time() * 1000)
    loop = asyncio.get_event_loop()
    try:
        findings = await loop.run_in_executor(
            _executor,
            lambda: session.run_active_scan(ctx_id, context_name, target_url, scan_request),
        )
        return ScanResult(
            scan_job_id=scan_request.scan_job_id,
            scan_type=ScanType.DAST_INTERACTIVE,
            scanner="zap-interactive",
            success=True,
            findings=findings,
            duration_ms=int(time.time() * 1000) - start_ms,
        )
    except Exception as exc:
        return ScanResult(
            scan_job_id=scan_request.scan_job_id,
            scan_type=ScanType.DAST_INTERACTIVE,
            scanner="zap-interactive",
            success=False,
            findings=[],
            error=str(exc)[:1000],
            duration_ms=int(time.time() * 1000) - start_ms,
        )


@app.post("/dast/recording/stop")
async def dast_recording_stop(payload: dict) -> dict:
    """Body: { contextName: str }. Removes the ZAP context."""
    context_name = payload.get("contextName")
    if not context_name:
        raise HTTPException(status_code=400, detail="contextName required")
    session = InteractiveDASTSession()
    loop = asyncio.get_event_loop()
    await loop.run_in_executor(_executor, lambda: session.stop(context_name))
    return {"ok": True}


@app.get("/dast/message/{message_id}")
async def dast_fetch_message(message_id: str) -> dict:
    """
    Return the full untruncated HTTP exchange for a ZAP message.
    Used by the drawer's "Load full response" lazy-fetch button.
    404 when ZAP has evicted the message from its in-memory session.
    """
    from scanners.dast import DASTScanner
    helper = DASTScanner()
    loop = asyncio.get_event_loop()
    exchange = await loop.run_in_executor(
        _executor, lambda: helper._fetch_message(message_id, full=True),
    )
    if exchange is None:
        raise HTTPException(status_code=404, detail="message not found in ZAP")
    return exchange


@app.get("/dast/recording/zap-ca")
async def dast_recording_zap_ca() -> dict:
    """Return the URL the API should fetch ZAP's root CA from. The API proxies
    that URL out to the user so it appears to come from the platform."""
    session = InteractiveDASTSession()
    return {"caUrl": session.root_cert_url()}


@app.post("/scan", response_model=ScanResult, response_model_by_alias=True)
async def run_scan(request: ScanRequest) -> ScanResult:
    scanner_cls = SCANNER_MAP.get(request.scan_type)
    if not scanner_cls:
        raise HTTPException(status_code=400, detail=f"Unknown scan type: {request.scan_type}")

    scanner_instance = scanner_cls()
    workspace = scanner_instance.make_workspace()
    start_ms = int(time.time() * 1000)

    def _run():
        try:
            return scanner_instance.scan(request, workspace)
        finally:
            scanner_instance.cleanup(workspace)

    loop = asyncio.get_event_loop()
    try:
        findings = await loop.run_in_executor(_executor, _run)
        return ScanResult(
            scan_job_id=request.scan_job_id,
            scan_type=request.scan_type,
            scanner=findings[0].scanner if findings else request.scan_type.lower(),
            success=True,
            findings=findings,
            duration_ms=int(time.time() * 1000) - start_ms,
        )
    except Exception as exc:
        return ScanResult(
            scan_job_id=request.scan_job_id,
            scan_type=request.scan_type,
            scanner=request.scan_type.value.lower(),
            success=False,
            findings=[],
            error=str(exc)[:1000],
            duration_ms=int(time.time() * 1000) - start_ms,
        )
