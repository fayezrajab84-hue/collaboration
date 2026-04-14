FROM python:3.12-slim AS base

# ── Install system dependencies and scanner tools ───────────────────────
FROM base AS tools

RUN apt-get update && apt-get install -y --no-install-recommends \
    curl \
    wget \
    git \
    ca-certificates \
    unzip \
    && rm -rf /var/lib/apt/lists/*

# Install Trivy
RUN curl -sfL https://raw.githubusercontent.com/aquasecurity/trivy/main/contrib/install.sh | sh -s -- -b /usr/local/bin

# Install TruffleHog (latest binary)
RUN curl -sSfL https://raw.githubusercontent.com/trufflesecurity/trufflehog/main/scripts/install.sh | sh -s -- -b /usr/local/bin

# Install Nuclei
RUN NUCLEI_VERSION=$(curl -s https://api.github.com/repos/projectdiscovery/nuclei/releases/latest | grep '"tag_name"' | sed -E 's/.*"v([^"]+)".*/\1/') \
    && wget -q "https://github.com/projectdiscovery/nuclei/releases/latest/download/nuclei_${NUCLEI_VERSION}_linux_amd64.zip" -O /tmp/nuclei.zip \
    && unzip /tmp/nuclei.zip -d /tmp/nuclei \
    && mv /tmp/nuclei/nuclei /usr/local/bin/nuclei \
    && chmod +x /usr/local/bin/nuclei \
    && rm -rf /tmp/nuclei /tmp/nuclei.zip

# ── Python dependencies ──────────────────────────────────────────────────
FROM base AS python-deps

WORKDIR /app

# Install system deps needed at runtime
RUN apt-get update && apt-get install -y --no-install-recommends \
    git \
    curl \
    && rm -rf /var/lib/apt/lists/*

COPY apps/scanner/requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# ── Runtime image ────────────────────────────────────────────────────────
FROM base AS runtime

# Create non-root user
RUN addgroup --gid 1001 scanner && adduser --uid 1001 --gid 1001 --disabled-password --gecos "" scanner

# Runtime system deps
RUN apt-get update && apt-get install -y --no-install-recommends \
    git \
    curl \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Copy scanner binaries from tools stage
COPY --from=tools /usr/local/bin/trivy /usr/local/bin/trivy
COPY --from=tools /usr/local/bin/trufflehog /usr/local/bin/trufflehog
COPY --from=tools /usr/local/bin/nuclei /usr/local/bin/nuclei

# Copy Python packages
COPY --from=python-deps /usr/local/lib/python3.12/site-packages /usr/local/lib/python3.12/site-packages
COPY --from=python-deps /usr/local/bin /usr/local/bin

# Copy scanner application
COPY apps/scanner/ .

# Create workspace dir and set permissions
RUN mkdir -p /tmp/scan_workspace && chown -R scanner:scanner /tmp/scan_workspace && chown -R scanner:scanner /app

USER scanner

# Pre-download Nuclei templates (optional, speeds up first scan)
RUN nuclei -update-templates -silent || true

EXPOSE 8000

CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8000"]
