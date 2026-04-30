FROM python:3.12-slim@sha256:46cb7cc2877e60fbd5e21a9ae6115c30ace7a077b9f8772da879e4590c18c2e3 AS base

# ── Install system dependencies and scanner tools ───────────────────────
FROM base AS tools

RUN apt-get update && apt-get install -y --no-install-recommends \
    curl \
    wget \
    git \
    ca-certificates \
    unzip \
    tar \
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

# Install subfinder (passive subdomain enumeration)
RUN SUBFINDER_VERSION=$(curl -s https://api.github.com/repos/projectdiscovery/subfinder/releases/latest | grep '"tag_name"' | sed -E 's/.*"v([^"]+)".*/\1/') \
    && wget -q "https://github.com/projectdiscovery/subfinder/releases/latest/download/subfinder_${SUBFINDER_VERSION}_linux_amd64.zip" -O /tmp/subfinder.zip \
    && unzip /tmp/subfinder.zip -d /tmp/subfinder \
    && mv /tmp/subfinder/subfinder /usr/local/bin/subfinder \
    && chmod +x /usr/local/bin/subfinder \
    && rm -rf /tmp/subfinder /tmp/subfinder.zip

# Install httpx (HTTP probing)
RUN HTTPX_VERSION=$(curl -s https://api.github.com/repos/projectdiscovery/httpx/releases/latest | grep '"tag_name"' | sed -E 's/.*"v([^"]+)".*/\1/') \
    && wget -q "https://github.com/projectdiscovery/httpx/releases/latest/download/httpx_${HTTPX_VERSION}_linux_amd64.zip" -O /tmp/httpx.zip \
    && unzip /tmp/httpx.zip -d /tmp/httpx \
    && mv /tmp/httpx/httpx /usr/local/bin/httpx \
    && chmod +x /usr/local/bin/httpx \
    && rm -rf /tmp/httpx /tmp/httpx.zip

# Install katana (headless JS-aware web crawler)
RUN KATANA_VERSION=$(curl -s https://api.github.com/repos/projectdiscovery/katana/releases/latest | grep '"tag_name"' | sed -E 's/.*"v([^"]+)".*/\1/') \
    && wget -q "https://github.com/projectdiscovery/katana/releases/latest/download/katana_${KATANA_VERSION}_linux_amd64.zip" -O /tmp/katana.zip \
    && unzip /tmp/katana.zip -d /tmp/katana \
    && mv /tmp/katana/katana /usr/local/bin/katana \
    && chmod +x /usr/local/bin/katana \
    && rm -rf /tmp/katana /tmp/katana.zip

# Install ffuf (web fuzzer / directory brute-force)
RUN FFUF_VERSION=$(curl -s https://api.github.com/repos/ffuf/ffuf/releases/latest | grep '"tag_name"' | sed -E 's/.*"v([^"]+)".*/\1/') \
    && wget -q "https://github.com/ffuf/ffuf/releases/latest/download/ffuf_${FFUF_VERSION}_linux_amd64.tar.gz" -O /tmp/ffuf.tar.gz \
    && tar -xzf /tmp/ffuf.tar.gz -C /tmp/ffuf_out --one-top-level=ffuf_out --strip-components=1 2>/dev/null || \
       (mkdir -p /tmp/ffuf_out && tar -xzf /tmp/ffuf.tar.gz -C /tmp/ffuf_out) \
    && find /tmp/ffuf_out -name "ffuf" -type f -exec mv {} /usr/local/bin/ffuf \; \
    && chmod +x /usr/local/bin/ffuf \
    && rm -rf /tmp/ffuf.tar.gz /tmp/ffuf_out

# Install testssl.sh (SSL/TLS testing)
RUN wget -q https://testssl.sh/testssl.sh -O /usr/local/bin/testssl.sh \
    && chmod +x /usr/local/bin/testssl.sh

# Install Nikto (web vulnerability scanner) from source
RUN apt-get update && apt-get install -y --no-install-recommends perl && rm -rf /var/lib/apt/lists/* \
    && git clone --depth 1 https://github.com/sullo/nikto.git /opt/nikto \
    && chmod +x /opt/nikto/program/nikto.pl \
    && ln -s /opt/nikto/program/nikto.pl /usr/local/bin/nikto

# Install SQLMap (Python-based SQL injection confirmation tool)
# Cloned from source — no compilation needed, just requires Python 3
RUN git clone --depth 1 https://github.com/sqlmapproject/sqlmap.git /opt/sqlmap \
    && chmod +x /opt/sqlmap/sqlmap.py \
    && ln -sf /opt/sqlmap/sqlmap.py /usr/local/bin/sqlmap

# Install Dalfox (Go-based XSS confirmation tool)
# Asset naming: dalfox-linux-amd64.tar.gz contains a single binary named
# `dalfox-linux-amd64` (not `dalfox`) — extract and rename in one step.
RUN wget -q "https://github.com/hahwul/dalfox/releases/latest/download/dalfox-linux-amd64.tar.gz" \
         -O /tmp/dalfox.tar.gz \
    && tar -xzf /tmp/dalfox.tar.gz -C /tmp/ \
    && mv /tmp/dalfox-linux-amd64 /usr/local/bin/dalfox \
    && chmod +x /usr/local/bin/dalfox \
    && /usr/local/bin/dalfox version \
    && rm -f /tmp/dalfox.tar.gz

# ── Python dependencies ──────────────────────────────────────────────────
FROM base AS python-deps

WORKDIR /app

# Install system deps needed at runtime + Playwright's Chromium OS deps
RUN apt-get update && apt-get install -y --no-install-recommends \
    git \
    curl \
    # Chromium / Playwright runtime libraries
    libnss3 \
    libnspr4 \
    libdbus-1-3 \
    libatk1.0-0 \
    libatk-bridge2.0-0 \
    libcups2 \
    libdrm2 \
    libxkbcommon0 \
    libxcomposite1 \
    libxdamage1 \
    libxfixes3 \
    libxrandr2 \
    libgbm1 \
    libasound2 \
    libpango-1.0-0 \
    libpangocairo-1.0-0 \
    libx11-6 \
    libx11-xcb1 \
    libxcb1 \
    libxext6 \
    fonts-liberation \
    && rm -rf /var/lib/apt/lists/*

COPY apps/scanner/requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Download Playwright's Chromium browser to a fixed system-wide path.
# PLAYWRIGHT_BROWSERS_PATH makes Playwright look here at runtime instead of ~/.cache.
ENV PLAYWRIGHT_BROWSERS_PATH=/usr/share/ms-playwright
RUN playwright install chromium \
    && chmod -R 755 /usr/share/ms-playwright

# ── Runtime image ────────────────────────────────────────────────────────
FROM base AS runtime

# Create non-root user
RUN addgroup --gid 1001 scanner && adduser --uid 1001 --gid 1001 --disabled-password --gecos "" scanner

# Runtime system deps:
#   - git, curl       — repo cloning and downloads
#   - nmap            — port/service scanning (pentest phase 2)
#   - nikto/perl      — web vulnerability scanner (pentest phase 3)
#   - openssl         — required by testssl.sh
#   - dnsutils        — nslookup/dig for subdomain probing
#   - ca-certificates — TLS trust for scanner HTTP calls
#   - Chromium libs   — required by Playwright headless browser
RUN apt-get update && apt-get install -y --no-install-recommends \
    git \
    curl \
    nmap \
    perl \
    openssl \
    dnsutils \
    ca-certificates \
    dirb \
    # Chromium / Playwright runtime libraries (must match python-deps stage)
    libnss3 \
    libnspr4 \
    libdbus-1-3 \
    libatk1.0-0 \
    libatk-bridge2.0-0 \
    libcups2 \
    libdrm2 \
    libxkbcommon0 \
    libxcomposite1 \
    libxdamage1 \
    libxfixes3 \
    libxrandr2 \
    libgbm1 \
    libasound2 \
    libpango-1.0-0 \
    libpangocairo-1.0-0 \
    libx11-6 \
    libx11-xcb1 \
    libxcb1 \
    libxext6 \
    fonts-liberation \
    && rm -rf /var/lib/apt/lists/*

# Playwright browser path — must match python-deps stage
ENV PLAYWRIGHT_BROWSERS_PATH=/usr/share/ms-playwright

# Unbuffered stdout/stderr so per-phase pentest logs appear in real time
# and survive abrupt container restarts. Without this, Python buffers ~8KB
# before flushing, which was swallowing crashed-phase tracebacks.
ENV PYTHONUNBUFFERED=1

WORKDIR /app

# Copy scanner binaries from tools stage
COPY --from=tools /usr/local/bin/trivy       /usr/local/bin/trivy
COPY --from=tools /usr/local/bin/trufflehog  /usr/local/bin/trufflehog
COPY --from=tools /usr/local/bin/nuclei      /usr/local/bin/nuclei
COPY --from=tools /usr/local/bin/subfinder   /usr/local/bin/subfinder
COPY --from=tools /usr/local/bin/httpx       /usr/local/bin/httpx
COPY --from=tools /usr/local/bin/ffuf        /usr/local/bin/ffuf
COPY --from=tools /usr/local/bin/katana      /usr/local/bin/katana
COPY --from=tools /usr/local/bin/testssl.sh  /usr/local/bin/testssl.sh
COPY --from=tools /opt/nikto                 /opt/nikto
RUN ln -s /opt/nikto/program/nikto.pl /usr/local/bin/nikto
# SQLMap (Python — shipped as source, symlinked)
COPY --from=tools /opt/sqlmap                /opt/sqlmap
RUN ln -sf /opt/sqlmap/sqlmap.py /usr/local/bin/sqlmap
# Dalfox (Go binary)
COPY --from=tools /usr/local/bin/dalfox      /usr/local/bin/dalfox

# Copy Python packages
COPY --from=python-deps /usr/local/lib/python3.12/site-packages /usr/local/lib/python3.12/site-packages
COPY --from=python-deps /usr/local/bin /usr/local/bin

# Copy Playwright Chromium browser (downloaded in python-deps stage)
COPY --from=python-deps /usr/share/ms-playwright /usr/share/ms-playwright

# Copy scanner application
COPY apps/scanner/ .

# Create workspace dir and set permissions
RUN mkdir -p /tmp/scan_workspace && chown -R scanner:scanner /tmp/scan_workspace && chown -R scanner:scanner /app

USER scanner

# Pre-download Nuclei templates (optional, speeds up first scan)
RUN nuclei -update-templates -silent || true

EXPOSE 8000

CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8000"]
