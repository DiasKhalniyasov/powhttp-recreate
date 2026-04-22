#!/usr/bin/env bash
# One-shot: run our agent-box against $URL, then diff against a powhttp HAR.
#
# Usage:
#   ./compare.sh https://playwright.dev/ fixtures/playwrightdev-powhttp.har
#
# Produces:
#   runs/agentbox.jsonl  — our capture, normalized
#   runs/powhttp.jsonl   — powhttp capture, normalized
#   runs/report.md       — human-readable diff
#   runs/diff.jsonl      — machine-readable diff (one JSON record per flow/pair)
#
# Preconditions:
#   - docker is running
#   - the powhttp-agent-box:test image is already built (see ../test_container.sh)
#   - powhttp.har was exported from the real powhttp app for the same URL

set -euo pipefail

# Snapshot the caller's cwd so we can resolve relative paths passed on argv
# BEFORE we cd into the compare/ directory.
ORIG_PWD="$PWD"
HERE="$(cd "$(dirname "$0")" && pwd)"

URL="${1:?usage: $0 <url> <powhttp-har-path>}"
HAR="${2:?usage: $0 <url> <powhttp-har-path>}"

# If HAR is relative, resolve it against the caller's cwd.
if [[ "$HAR" != /* ]]; then
    HAR="$ORIG_PWD/$HAR"
fi

cd "$HERE"

IMAGE="${POWHTTP_AGENT_BOX_IMAGE:-powhttp-agent-box:test}"
RUNS="$HERE/runs"
BOX_CAPTURES="$HERE/runs/agentbox_captures"

mkdir -p "$RUNS"
rm -rf "$BOX_CAPTURES"
mkdir -p "$BOX_CAPTURES"

blue()  { printf '\033[34m==> %s\033[0m\n' "$*"; }
green() { printf '\033[32m%s\033[0m\n' "$*"; }
red()   { printf '\033[31m%s\033[0m\n' "$*"; }

[ -f "$HAR" ] || { red "HAR not found: $HAR"; exit 1; }

blue "Running agent-box against $URL"
docker run --rm \
    --shm-size=2g \
    -e TASK_URL="$URL" \
    -v "$BOX_CAPTURES:/state" \
    "$IMAGE" 2>&1 | tail -20

[ -f "$BOX_CAPTURES/flows.db" ] || { red "no flows.db after run"; exit 1; }

blue "Dumping agent-box flows.db to JSONL"
python3 pull_agentbox.py "$BOX_CAPTURES/flows.db" "$RUNS/agentbox.jsonl"

blue "Parsing powhttp HAR to JSONL"
python3 parse_har.py "$HAR" "$RUNS/powhttp.jsonl"

blue "Diffing"
python3 diff_flows.py "$RUNS/powhttp.jsonl" "$RUNS/agentbox.jsonl" "$RUNS/report.md" "$RUNS/diff.jsonl"

echo
green "DONE"
green "report:      $RUNS/report.md"
green "diff.jsonl:  $RUNS/diff.jsonl"
green "powhttp:     $RUNS/powhttp.jsonl"
green "agent-box:   $RUNS/agentbox.jsonl  (flows.db still at $BOX_CAPTURES/flows.db)"
