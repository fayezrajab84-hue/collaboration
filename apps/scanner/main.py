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
