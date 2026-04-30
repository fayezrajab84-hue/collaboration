# syntax=docker/dockerfile:1.7
# Playwright crawler sidecar — Phase 1
#
# Uses Microsoft's official Playwright Python image so Chromium + all the
# system libs it needs (fonts, libnss, xvfb, etc.) are baked in. Rolling
# our own from python:slim would require ~30 apt packages.
FROM mcr.microsoft.com/playwright/python:v1.47.0-jammy@sha256:f3a3d2e0332df4c7b6992db0ad0687df1653efd4671612b8ca1be6ae5fc06448

# --- OS hygiene: drop root, install curl for the healthcheck -------------
# The base image already ships as root with the `pwuser` user (uid 1000).
USER root
RUN apt-get update \
 && apt-get install -y --no-install-recommends curl tini \
 && rm -rf /var/lib/apt/lists/* \
 && useradd -m -u 1001 -s /bin/bash crawler

WORKDIR /app

# --- Python deps ----------------------------------------------------------
# Install to a venv owned by the non-root user so `pip install` at runtime
# (debug builds) doesn't need root either.
COPY apps/crawler/requirements.txt /app/requirements.txt
RUN pip install --no-cache-dir --upgrade pip \
 && pip install --no-cache-dir -r /app/requirements.txt

# The base image already has Chromium pre-installed at the Playwright
# default path, so `playwright install` is a no-op here.

# --- App code -------------------------------------------------------------
COPY apps/crawler/ /app/

# --- Runtime --------------------------------------------------------------
RUN chown -R crawler:crawler /app
USER crawler

EXPOSE 8001

HEALTHCHECK --interval=15s --timeout=5s --start-period=20s --retries=3 \
    CMD curl -sf http://localhost:8001/health || exit 1

# tini as PID 1 so Chromium zombies get reaped.
ENTRYPOINT ["/usr/bin/tini", "--"]
CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8001"]
