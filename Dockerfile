# Ephemeral browser-agent container with MITM capture.
# Base: Microsoft's Playwright image — ships a pinned Chromium + deps.
FROM mcr.microsoft.com/playwright/python:v1.50.0-noble

ENV DEBIAN_FRONTEND=noninteractive \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1 \
    # Where flows.db + bodies/ + ca/ live. Mount this as a volume to keep captures.
    STATE_DIR=/state \
    # Where Chromium user data lives. /tmp means it's wiped each run unless overridden.
    CHROMIUM_PROFILE=/tmp/chromium-profile \
    # Proxy the entrypoint starts.
    PROXY_HOST=127.0.0.1 \
    PROXY_PORT=8888
# Note: SSL_CERT_FILE / NODE_EXTRA_CA_CERTS / REQUESTS_CA_BUNDLE are *deliberately*
# not set here. They'd point to a file that only exists after entrypoint.sh runs
# update-ca-certificates, and pip uses REQUESTS_CA_BUNDLE at build time — setting
# them here breaks `pip install`. The entrypoint exports them at runtime instead.

# libnss3-tools gives us certutil, needed to add the CA to Chromium's NSS DB.
# ca-certificates + update-ca-certificates handle the system trust store.
RUN apt-get update && apt-get install -y --no-install-recommends \
        ca-certificates \
        libnss3-tools \
        sqlite3 \
        curl \
        jq \
        tini \
    && rm -rf /var/lib/apt/lists/*

# mitmproxy does the MITM + CA minting + h2 + WebSockets.
# We pin a version so addon API stays stable.
#
# mcp[cli] gives us the FastMCP server used by mcp_server.py.
# jq is the Python binding used by mcp_server.py's query_body tool.
RUN pip install --no-cache-dir \
        "mitmproxy==11.0.2" \
        "playwright==1.50.0" \
        "mcp[cli]>=1.2.0" \
        "jq>=1.6.0"

# Playwright browsers are already baked into the base image — don't re-download.

# App code
WORKDIR /app
COPY entrypoint.sh /usr/local/bin/entrypoint.sh
COPY mitm_addon.py /app/mitm_addon.py
COPY flows.py /app/flows.py
COPY agent_example.py /app/agent_example.py
COPY mcp_server.py /app/mcp_server.py

RUN chmod +x /usr/local/bin/entrypoint.sh \
    && mkdir -p "$STATE_DIR"

# tini reaps zombies; important when the entrypoint backgrounds mitmproxy.
ENTRYPOINT ["/usr/bin/tini", "--", "/usr/local/bin/entrypoint.sh"]

# Default command: run the example agent. Override with your own agent script.
CMD ["python", "-u", "/app/agent_example.py"]
