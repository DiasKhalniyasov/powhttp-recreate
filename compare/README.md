# compare/ — diff our agent-box captures against real powhttp

Compares what the ephemeral Docker agent-box captured (via mitmproxy →
`flows.db`) against what the real powhttp desktop app captured (exported as
HAR). Produces a markdown report and a JSONL diff.

## Pieces

| File | Purpose |
|---|---|
| `normalize.py` | Shared schema — both sides get boiled to `NormFlow` records. |
| `parse_har.py` | HAR 1.3 → normalized JSONL. |
| `pull_agentbox.py` | Our `flows.db` (+ `bodies/`) → normalized JSONL. |
| `diff_flows.py` | Two JSONLs → `report.md` + `diff.jsonl`. |
| `compare.sh` | One-shot: docker-run the box, parse HAR, diff. |
| `fixtures/` | Known-good HAR fixtures you want to regress against. |
| `runs/` | Per-invocation outputs (gitignored-worthy). |

## Normalized schema

Each flow becomes:

```json
{
  "source": "powhttp | agentbox",
  "started_at_ms": 1776884381893,
  "method": "GET",
  "url": "https://playwright.dev/",
  "scheme": "https",
  "host": "playwright.dev",
  "path": "/",
  "status": 200,
  "http_version": "HTTP/2",
  "content_type": "text/html; charset=utf-8",
  "req_headers": [[name, value], ...],   // pseudo-headers, cookies, UA stripped
  "resp_headers": [[name, value], ...],  // CF-Ray, Date, Age stripped
  "req_body_size": 0,
  "resp_body_size": 12345,
  "req_body_sha256": null,
  "resp_body_sha256": "abc123…"
}
```

**Matching key**: `(method, host, path)`. Query strings are stripped because
they often carry nonce/jitter between runs.

**Headers intentionally stripped from the diff** — noise that differs by design
between a real Chrome profile and a headless container:
`user-agent`, `sec-ch-ua*`, `accept-language`, `cookie`, `set-cookie`, `date`,
`age`, `cf-ray`, `cf-cache-status`, `server-timing`, `alt-svc`, `report-to`,
`nel`, `x-powered-by`, `x-client-data`, and all HTTP/2 pseudo-headers (`:method`, `:authority`, ...).

Edit `_IGNORED_HEADER_NAMES` in `normalize.py` if you want to include them.

## End-to-end: one command

```bash
# from repo root (so docker can see the build context)
./compare/compare.sh https://playwright.dev/ compare/fixtures/playwrightdev-powhttp.har
```

What that does:

1. `docker run` the agent-box against `$URL`, mounts a fresh
   `runs/agentbox_captures/` as `/state`. Comes out with a clean
   `flows.db`.
2. `pull_agentbox.py` dumps it to `runs/agentbox.jsonl`.
3. `parse_har.py` dumps the HAR to `runs/powhttp.jsonl`.
4. `diff_flows.py` produces `runs/report.md` and `runs/diff.jsonl`.

## How to get the powhttp side

In the real powhttp desktop app:

1. Start a new session (or note the current session's entry count so you can
   scope the export).
2. Open your browser with powhttp as its proxy (SwitchyOmega → `127.0.0.1:8888`).
3. Navigate to the target URL; let it finish.
4. In powhttp: **File → Export → HAR** (or whatever the current menu path is).
5. Save to `compare/fixtures/<something>.har`.

## Reading the report

`runs/report.md` has six sections:

1. **Summary counts** — totals on each side, matched/unmatched, differing.
2. **Host coverage** — per-host counts, both sides side-by-side.
3. **Only in powhttp** — flows the real browser made that our container didn't.
   Expect: browser-extension phone-home (AdGuard, uBlock), Chrome Safe Browsing,
   Google account sync, favicon pre-fetch for other tabs, etc.
4. **Only in agentbox** — flows only our container made. Expect: the
   `mitm.it` readiness probe from `entrypoint.sh`, and nothing else if our
   capture is complete.
5. **Matched but differ** — the interesting section. Pairs where the normalized
   flow isn't byte-identical: different status, content-type family, response
   size >5% different, response body SHA different, or different set of
   response-header keys.
6. **Top header keys that differ** — rollup of "which headers appeared on one
   side but not the other" across the differing pairs.

### What "good" looks like

For a public, mostly-static site like `playwright.dev`:

- **Matched pairs ≈ 30+**. The actual site assets.
- **Only in powhttp**: 5-10 (browser chrome, extensions).
- **Only in agentbox**: 1 (mitm.it probe).
- **Matched but differ**: 0-3, all of them trivial (e.g. one-off headers,
  slightly different gzip sizes under the 5% tolerance).

If **matched pairs is small** and **only_in_agentbox is large**, we're making
requests powhttp isn't — likely a Playwright-driven preload or a different
Chromium version. Worth investigating.

If **matched pairs is small** and **only_in_powhttp is large**, we're missing
requests — either the real browser has extensions/Safe-Browsing that the
headless container can't produce (expected), or we have a capture bug (not
expected — check `runs/agentbox_captures/mitmproxy.log`).

## Running the pieces individually

```bash
# HAR → JSONL
python3 parse_har.py fixtures/playwrightdev-powhttp.har runs/powhttp.jsonl

# flows.db → JSONL  (give it the state-dir from a docker run)
python3 pull_agentbox.py runs/agentbox_captures/flows.db runs/agentbox.jsonl

# Diff
python3 diff_flows.py runs/powhttp.jsonl runs/agentbox.jsonl runs/report.md runs/diff.jsonl
```

All three scripts print a one-line summary to stderr — good for wiring into CI.

## Tweaking matching

- **Exact URL match instead of (method, host, path)**: in `normalize.py`,
  change `match_key` to include the query string.
- **Pair by timing**: the current pairing uses chronological order *within*
  each key bucket. If two captures ran far apart, you can still diff; the
  `started_at_ms` is for information only.
- **Tighter body-size tolerance**: `diff_pair` in `diff_flows.py` uses 5%.
  Drop to 0% to flag every byte-count difference, including gzip jitter.
- **Include cookies / UA in diff**: remove entries from `_IGNORED_HEADER_NAMES`
  in `normalize.py`. Be warned, the diff becomes noisy fast.
