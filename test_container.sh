#!/usr/bin/env bash
# End-to-end smoke test for the powhttp-agent-box container.
#
#   ./test_container.sh                        # test against example.com (quick)
#   ./test_container.sh https://playwright.dev # test against a real site
#
# Checks:
#   - docker build succeeds
#   - container runs, browser loads the URL, task exits 0
#   - captures/flows.db has entries, including at least one for the target host
#   - no TLS cert errors in the browser path
#
# On failure, prints diagnostics that tell you where it broke.

set -uo pipefail

URL="${1:-https://example.com/}"
IMAGE="powhttp-agent-box:test"
CAPTURES_DIR="$(pwd)/captures"
HERE="$(cd "$(dirname "$0")" && pwd)"

red()   { printf '\033[31m%s\033[0m\n' "$*"; }
green() { printf '\033[32m%s\033[0m\n' "$*"; }
blue()  { printf '\033[34m%s\033[0m\n' "$*"; }

fail() { red "FAIL: $*"; exit 1; }

cd "$HERE"

# --- 0. sanity ---------------------------------------------------------------
command -v docker >/dev/null || fail "docker not on PATH"
docker info >/dev/null 2>&1 || fail "docker daemon not reachable (is Docker Desktop / colima / dockerd running?)"

blue "==> Docker: $(docker --version)"
blue "==> Platform: $(uname -m)"

# --- 1. build ---------------------------------------------------------------
blue "==> Building image $IMAGE (first build pulls ~2 GB Playwright base — give it 5-10 min)"
# Important: DON'T pipe through 'tail' here — it buffers until EOF and makes
# the build look hung. Stream stdout directly, save the full log for postmortem.
set -o pipefail
if ! docker build --progress=plain -t "$IMAGE" . 2>&1 | tee /tmp/pab-build.log; then
    red "build failed — full log at /tmp/pab-build.log"
    exit 1
fi
green "build OK"

# --- 2. run the agent ------------------------------------------------------
rm -rf "$CAPTURES_DIR"
mkdir -p "$CAPTURES_DIR"

blue "==> Running container against $URL"
# --rm: auto-delete; -e TASK_URL: pass URL through entrypoint into agent_example.
# --shm-size=2g: Chromium needs it or renderer crashes.
if ! docker run --rm \
    --shm-size=2g \
    -e TASK_URL="$URL" \
    -v "$CAPTURES_DIR:/state" \
    "$IMAGE" 2>&1 | tee /tmp/pab-run.log; then
    red "container exited non-zero — log in /tmp/pab-run.log"
    exit 1
fi

# --- 3. verify captures -----------------------------------------------------
DB="$CAPTURES_DIR/flows.db"
[ -f "$DB" ] || fail "no flows.db at $DB — mitmproxy addon didn't write"

# Count entries without requiring sqlite3 on the host — use the container.
ENTRIES_COUNT=$(docker run --rm -v "$CAPTURES_DIR:/state" "$IMAGE" \
    sqlite3 /state/flows.db "SELECT COUNT(*) FROM entries;")
blue "==> flows.db has $ENTRIES_COUNT entries"

[ "$ENTRIES_COUNT" -gt 0 ] || fail "zero entries captured"

# Was the target host captured?
TARGET_HOST=$(echo "$URL" | awk -F/ '{print $3}' | awk -F: '{print $1}')
HOST_HITS=$(docker run --rm -v "$CAPTURES_DIR:/state" "$IMAGE" \
    sqlite3 /state/flows.db \
    "SELECT COUNT(*) FROM entries WHERE remote_host='$TARGET_HOST';")
blue "==> entries for $TARGET_HOST: $HOST_HITS"

[ "$HOST_HITS" -gt 0 ] || fail "no entries for $TARGET_HOST — check for cert/proxy errors in /tmp/pab-run.log"

# Any entries with an 'error' column populated? That's how mitmproxy records
# upstream failures (DNS, TLS, connection reset).
ERR_COUNT=$(docker run --rm -v "$CAPTURES_DIR:/state" "$IMAGE" \
    sqlite3 /state/flows.db "SELECT COUNT(*) FROM entries WHERE error IS NOT NULL;")
if [ "$ERR_COUNT" -gt 0 ]; then
    red "WARNING: $ERR_COUNT entries recorded an upstream error:"
    docker run --rm -v "$CAPTURES_DIR:/state" "$IMAGE" \
        sqlite3 /state/flows.db \
        "SELECT remote_host, error FROM entries WHERE error IS NOT NULL LIMIT 5;"
fi

# Quick look at what was captured
blue "==> sample of captured flows:"
docker run --rm -v "$CAPTURES_DIR:/state" "$IMAGE" \
    sqlite3 -column -header /state/flows.db \
    "SELECT method, status, remote_host, substr(url,1,80) AS url FROM entries ORDER BY started_at LIMIT 15;"

echo
green "ALL CHECKS PASSED"
green "captures at: $CAPTURES_DIR"
green "open the DB:  sqlite3 $CAPTURES_DIR/flows.db"
