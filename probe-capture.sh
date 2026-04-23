#!/usr/bin/env bash
# End-to-end verifier for the capture-fidelity rewrite.
#
# Builds the image, runs the container with /app/probe_capture.py as CMD, and
# prints the per-table pass/fail report. Container exits after the probe
# finishes — no lingering proxy process.
#
# Usage:
#   ./probe-capture.sh           # build + run (ephemeral state)
#   ./probe-capture.sh --keep    # mount ./probe-state so you can inspect the DB after
#   ./probe-capture.sh --doh     # turn on DoH upstream resolver for this run
#
# Requires docker on PATH and a network that can reach cloudflare.com,
# echo.websocket.events, and sse.dev.

set -euo pipefail

cd "$(dirname "$0")"

IMAGE="${IMAGE:-powhttp-agent-box:probe}"
KEEP=0
DOH_FLAG=""
for arg in "$@"; do
    case "$arg" in
        --keep) KEEP=1 ;;
        --doh)  DOH_FLAG="-e POWHTTP_DOH=on" ;;
        *) echo "unknown arg: $arg" >&2; exit 2 ;;
    esac
done

echo "[probe] building $IMAGE"
docker build -q -t "$IMAGE" . >/dev/null

MOUNT_ARGS=()
if [ "$KEEP" = "1" ]; then
    mkdir -p probe-state
    echo "[probe] mounting ./probe-state — DB will survive after exit"
    MOUNT_ARGS+=(-v "$(pwd)/probe-state:/state")
fi

echo "[probe] running container"
# The entrypoint already boots mitmproxy + installs the CA. When CMD is the
# probe script, it hits endpoints via 127.0.0.1:8888, then queries the DB.
#
# Note: the ${ARR[@]+"${ARR[@]}"} dance is the portable way to expand an
# array that may be empty under `set -u` on macOS's bash 3.2.
docker run --rm \
    $DOH_FLAG \
    ${MOUNT_ARGS[@]+"${MOUNT_ARGS[@]}"} \
    "$IMAGE" \
    python -u /app/probe_capture.py

echo "[probe] done"
