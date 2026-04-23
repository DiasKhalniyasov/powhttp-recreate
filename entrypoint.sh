#!/usr/bin/env bash
# Boot sequence inside the container:
#   1. Ensure a root CA exists in $STATE_DIR/ca (generate on first run).
#   2. Install the CA into every trust store the agent's tools might use.
#   3. Start mitmproxy in the background with our SQLite-logging addon.
#   4. Wait for the proxy to be reachable.
#   5. exec the agent command, inheriting the proxy-aware env.
#
# Because this is ephemeral-per-task, we default to a fresh CA on every run
# unless $STATE_DIR/ca is mounted and already populated.

set -euo pipefail

: "${STATE_DIR:=/state}"
: "${PROXY_HOST:=127.0.0.1}"
: "${PROXY_PORT:=8888}"

CA_DIR="$STATE_DIR/ca"
CA_CERT="$CA_DIR/mitmproxy-ca-cert.pem"
CA_SYS_PATH="/usr/local/share/ca-certificates/powhttp-root.crt"
NSSDB="${HOME:-/root}/.pki/nssdb"
FLOWS_DB="$STATE_DIR/flows.db"

log() { printf '[entrypoint] %s\n' "$*" >&2; }

# --- 1. CA bootstrap ---------------------------------------------------------
mkdir -p "$CA_DIR"
if [ ! -f "$CA_CERT" ]; then
    log "Generating new MITM root CA in $CA_DIR"
    # mitmproxy writes its CA to ~/.mitmproxy on first run; we force the dir.
    mitmdump --set confdir="$CA_DIR" --no-server -q &
    MITM_BOOTSTRAP_PID=$!
    # Wait for the cert to appear (usually <1s), then kill the bootstrap.
    for _ in $(seq 1 50); do
        [ -f "$CA_CERT" ] && break
        sleep 0.1
    done
    kill "$MITM_BOOTSTRAP_PID" 2>/dev/null || true
    wait "$MITM_BOOTSTRAP_PID" 2>/dev/null || true
    if [ ! -f "$CA_CERT" ]; then
        log "ERROR: mitmproxy did not create $CA_CERT"; exit 1
    fi
fi

# --- 2. Install CA into every trust store ------------------------------------
# System trust (covers curl, wget, most native HTTP libs).
log "Installing CA into system trust store"
cp "$CA_CERT" "$CA_SYS_PATH"
update-ca-certificates --fresh >/dev/null

# NSS DB (Chromium on Linux reads from here, NOT from the system store).
log "Installing CA into NSS DB at $NSSDB"
mkdir -p "$NSSDB"
if [ ! -f "$NSSDB/cert9.db" ]; then
    certutil -N --empty-password -d "sql:$NSSDB"
fi
# Import is idempotent; -t "C,," marks it as a trusted CA for server TLS.
certutil -A -n "powhttp-root" -t "C,," -i "$CA_CERT" -d "sql:$NSSDB"

# Now that the CA file exists at $CA_SYS_PATH, export the bundle env vars that
# non-browser HTTP clients (requests, node-fetch, go's net/http with SSL_CERT_FILE)
# honor. These are *deliberately* not set in the Dockerfile — pip itself uses
# REQUESTS_CA_BUNDLE at build time and would fail if it pointed at a nonexistent
# file during `docker build`.
export SSL_CERT_FILE="$CA_SYS_PATH"
export NODE_EXTRA_CA_CERTS="$CA_SYS_PATH"
export REQUESTS_CA_BUNDLE="$CA_SYS_PATH"

# --- 3. Start mitmproxy in the background ------------------------------------
log "Starting mitmproxy on $PROXY_HOST:$PROXY_PORT"
mkdir -p "$STATE_DIR/bodies"
export POWHTTP_FLOWS_DB="$FLOWS_DB"
export POWHTTP_BODIES_DIR="$STATE_DIR/bodies"
export POWHTTP_PROXY_PORT="$PROXY_PORT"

# Pre-mint the session ULID so the agent process can reference it via the same
# env var the addon uses — lets session_id flow through to MCP tools / logs.
if [ -z "${POWHTTP_SESSION_ID:-}" ]; then
    export POWHTTP_SESSION_ID="$(python3 -c 'import sys, os; sys.path.insert(0, "/app"); from ids import new_ulid; print(new_ulid())')"
fi
log "Session ULID: $POWHTTP_SESSION_ID"

# DoH upstream resolver — matches powhttp's 1.12.12.12 / 9.9.9.11 / 8.8.8.8
# choice. Opt-in: set POWHTTP_DOH=on in the container env to enable.
: "${POWHTTP_DOH:=off}"
: "${POWHTTP_DOH_FALLBACK:=system}"
export POWHTTP_DOH POWHTTP_DOH_FALLBACK
if [ "${POWHTTP_DOH}" = "on" ]; then
    log "DoH upstream resolver: ON (endpoints=${POWHTTP_DOH_ENDPOINT:-defaults})"
fi

# mitmdump = mitmproxy headless. --set flow_detail=0 keeps stderr quiet.
mitmdump \
    --set confdir="$CA_DIR" \
    --listen-host "$PROXY_HOST" \
    --listen-port "$PROXY_PORT" \
    --set flow_detail=0 \
    --set block_global=false \
    --scripts /app/mitm_addon.py \
    > "$STATE_DIR/mitmproxy.log" 2>&1 &
MITM_PID=$!
log "mitmproxy pid=$MITM_PID, log=$STATE_DIR/mitmproxy.log"

# SIGTERM → stop mitmproxy cleanly so SQLite flushes.
trap 'log "Shutting down mitmproxy (pid=$MITM_PID)"; kill -TERM "$MITM_PID" 2>/dev/null || true; wait "$MITM_PID" 2>/dev/null || true' EXIT

# --- 4. Wait for proxy to accept connections ---------------------------------
for _ in $(seq 1 50); do
    if curl -fsS --max-time 1 -x "http://$PROXY_HOST:$PROXY_PORT" http://mitm.it/ >/dev/null 2>&1; then
        break
    fi
    sleep 0.1
done

# --- 5. Hand off to the agent ------------------------------------------------
log "Launching agent: $*"
export HTTP_PROXY="http://$PROXY_HOST:$PROXY_PORT"
export HTTPS_PROXY="http://$PROXY_HOST:$PROXY_PORT"
export NO_PROXY="localhost,127.0.0.1,::1"
export POWHTTP_PROXY_URL="http://$PROXY_HOST:$PROXY_PORT"

# Run the agent in the foreground; its exit code becomes the container's.
"$@"
