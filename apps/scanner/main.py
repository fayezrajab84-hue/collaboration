import time
from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware

from models import ScanRequest, ScanResult, ScanType
from scanners import (
    SASTScanner,
    SCAScanner,
    SecretsScanner,
    IACScanner,
    ContainerScanner,
    DASTScanner,
    PentestScanner,
)

app = FastAPI(
    title="DevSecOps Scanner Service",
    description="Orchestrates security scanning tools",
    version="0.1.0",
)

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
}


@app.get("/health")
async def health():
    return {"status": "ok", "service": "scanner"}


@app.post("/scan", response_model=ScanResult)
async def run_scan(request: ScanRequest) -> ScanResult:
    scanner_cls = SCANNER_MAP.get(request.scan_type)
    if not scanner_cls:
        raise HTTPException(status_code=400, detail=f"Unknown scan type: {request.scan_type}")

    scanner_instance = scanner_cls()
    workspace = scanner_instance.make_workspace()
    start_ms = int(time.time() * 1000)

    try:
        findings = scanner_instance.scan(request, workspace)
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
    finally:
        scanner_instance.cleanup(workspace)
