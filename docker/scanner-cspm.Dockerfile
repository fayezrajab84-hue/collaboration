# Phase 29 — Dedicated CSPM scanner container.
#
# Layers BreachLens's scanner FastAPI surface on top of Prowler's official
# container image (prowlercloud/prowler). This is the pattern Prowler
# themselves recommend in their README — and it's the only practical way
# to ship Prowler given:
#
#   1. Prowler hard-pins pydantic to specific versions (5.25.x → 2.12.5).
#      pip's resolver fights the rest of our scanner image's deps for
#      hours and may never converge. The official image has Prowler
#      pre-installed in its own Poetry-managed venv, eliminating the
#      conflict.
#   2. Prowler's transitive Azure SDK + Microsoft Identity dep tree is
#      ~150 MB. Pre-baked in upstream image avoids the download+install
#      cost on every BreachLens build.
#   3. Prowler's check definitions + compliance frameworks are loaded
#      via the Poetry venv's package data; replicating them ad-hoc is
#      brittle.
#
# Architecture:
#
#   Upstream prowlercloud/prowler image (Poetry venv, prowler binary
#   ENTRYPOINT'd via "poetry run prowler") — DO NOT MODIFY.
#       │
#       ▼
#   Our additions:
#     - System-level pip install of FastAPI + uvicorn + pydantic 2.x
#       + httpx (writes to /usr/local/lib/python3.12/site-packages,
#       SEPARATE from Prowler's poetry venv — no conflicts).
#     - /usr/local/bin/prowler shim that shells `poetry run prowler`
#       so our cloud_azure scanner can invoke prowler the same way as
#       any other CLI tool.
#     - apps/scanner code copied to /app (matches main scanner image
#       layout for code-sharing).
#     - ENTRYPOINT/CMD overridden to run uvicorn, NOT prowler directly.
#
# Cost: image is ~2.5 GB — bigger than a hand-rolled minimal image but
# smaller than the abortive pip-install attempt would have been (which
# would have ALSO included the prowler deps + our base scanner deps).

# Pin to a specific Prowler release for reproducibility. Bump on a
# cadence — Prowler ships ~weekly. Latest stable as of 2026-04-29 was
# 5.25.1; tag `stable` also available.
FROM prowlercloud/prowler:5.25.1

USER root

# System Python is /usr/local/bin/python3 (Python 3.12.11 per upstream).
# pip install here writes to /usr/local/lib/python3.12/site-packages,
# which is SEPARATE from Prowler's Poetry venv at /home/prowler/.venv.
# The two environments don't share package state, so pydantic versions
# don't collide.
#
# --break-system-packages because the upstream image marks the system
# Python as "externally managed" (PEP 668). For a single-purpose
# container that's safe; production patterns use venvs but here we want
# the simplest path that matches the rest of our scanner architecture.
RUN pip install --no-cache-dir --break-system-packages \
    fastapi==0.111.0 \
    "uvicorn[standard]==0.29.0" \
    pydantic==2.7.0 \
    pydantic-settings==2.2.1 \
    httpx==0.27.0

# Shim /usr/local/bin/prowler to invoke prowler via Poetry. Our
# cloud_azure scanner code runs `subprocess.run(["prowler", ...])`
# without knowing about Poetry; this shim bridges the gap so we don't
# need to special-case the invocation in scanner.py.
RUN cat > /usr/local/bin/prowler-shim <<'EOF'
#!/bin/sh
cd /home/prowler && exec poetry run prowler "$@"
EOF
RUN chmod +x /usr/local/bin/prowler-shim \
    && ln -sf /usr/local/bin/prowler-shim /usr/local/bin/prowler

# Copy BreachLens scanner code. The cloud_azure scanner module is the
# one that gets dispatched on CLOUD ScanRequests; the rest of the code
# (base.py, models.py, main.py) is required infrastructure even though
# the other scanners' subprocess calls (semgrep, trivy etc) won't work
# in this container — SCANNER_MAP gates that at runtime, and CLOUD is
# the only key that resolves to a working class here.
COPY --chown=prowler:prowler apps/scanner /app

# Workspace for prowler outputs — chmod so prowler user can write.
RUN mkdir -p /tmp/scan_workspace && chown prowler:prowler /tmp/scan_workspace

USER prowler
# COPY apps/scanner /app puts main.py / models.py / scanners/ directly
# under /app (Docker COPY-into-existing-dir-without-trailing-slash-on-src
# semantics). uvicorn imports `main` relative to WORKDIR, so cd here.
WORKDIR /app

# Override the upstream ENTRYPOINT (which ran prowler directly). We run
# uvicorn — our FastAPI server — and shell out to prowler per scan.
ENTRYPOINT []
EXPOSE 8000
CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8000"]
