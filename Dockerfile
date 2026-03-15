FROM ubuntu:24.04

ENV DEBIAN_FRONTEND=noninteractive \
    PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1

# System packages — split into two groups for clarity
# Group 1: Python + PAM + SSL
RUN apt-get update && apt-get install -y --no-install-recommends \
        python3 \
        python3-pip \
        python3-venv \
        libpam0g \
        libpam0g-dev \
        libssl-dev \
        curl \
        ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# Group 2: Playwright / Chromium runtime dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
        libnss3 \
        libnspr4 \
        libatk1.0-0 \
        libatk-bridge2.0-0 \
        libcups2 \
        libxkbcommon0 \
        libxcomposite1 \
        libxdamage1 \
        libxfixes3 \
        libxrandr2 \
        libgbm1 \
        libasound2t64 \
        libpango-1.0-0 \
        libcairo2 \
        libatspi2.0-0 \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Install Python dependencies
COPY requirements.txt .
RUN pip3 install --break-system-packages --no-cache-dir -r requirements.txt

# Install Playwright Chromium browser binary
RUN playwright install chromium

# Copy project source
COPY . .

RUN mkdir -p ca && chmod +x run_tests.sh

# Create a dedicated PAM test user.
# The password is set via chpasswd so there is no plaintext secret in any
# RUN argument (it only appears in the container's /etc/shadow, not in any
# image layer metadata visible to `podman history`).
# WEB_UI_PAM_USER / WEB_UI_PAM_PASS env vars tell the test suite which
# credentials to use; they default to the values set here.
ENV WEB_UI_PAM_USER=pypkitest \
    WEB_UI_PAM_PASS=pypkitest123
RUN useradd -m -s /bin/bash pypkitest \
    && echo "pypkitest:pypkitest123" | chpasswd

ENTRYPOINT ["./run_tests.sh"]
