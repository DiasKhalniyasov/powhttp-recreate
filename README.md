# powhttp-agent-box

Ephemeral Docker container that bundles **mitmproxy + Chromium + Playwright + an MCP-style flow query API** so an agent running inside the container captures every network call its browser makes.

```
┌──────────────────────── container (ephemeral) ───────────────────────┐
│                                                                       │
│   ┌─────────────────┐   cdp     ┌─────────────────────┐               │
│   │  agent.py       │──────────►│  Chromium (headless)│               │
│   │  (Playwright)   │           │  --proxy-server=… ──┼──┐            │
│   └────────┬────────┘           └─────────────────────┘  │            │
│            │ sqlite3 query                               │            │
│            ▼                   ┌─────────────────────────▼─┐          │
│   ┌─────────────────┐          │  mitmproxy :8888          │          │
│   │  flows.db       │◄─addon───┤  addon: mitm_addon.py     │──► internet
│   │  + bodies/      │  writes  │  uses generated root CA   │          │
│   └─────────────────┘          └───────────────────────────┘          │
│                                                                       │
│   Root CA lives in /state/ca, pre-installed into:                     │
│     - /usr/local/share/ca-certificates  (system)                      │
│     - /root/.pki/nssdb                  (Chromium)                    │
│     - NODE_EXTRA_CA_CERTS, SSL_CERT_FILE env                          │
│                                                                       │
└───────────────────────────────────────────────────────────────────────┘
                                │
                     /state volume (mounted on host)
                     flows.db + bodies/ exported after task
```

## Quick start

```bash
# Build
docker build -t powhttp-agent-box .

# Run an agent task; mount /state to keep captures after teardown
docker run --rm \
  -v "$PWD/captures:/state" \
  -e TASK_URL="https://httpbin.org/anything/hello" \
  powhttp-agent-box
```

After the container exits you have a full SQLite database of every HTTP flow the browser made, indexed by host, path, method, status, and full-text on URL + bodies:

```bash
sqlite3 captures/flows.db "SELECT method,url,status FROM entries ORDER BY started_at DESC LIMIT 20;"
```

## Why this design

| Decision | Reason |
|---|---|
| mitmproxy, not a custom Rust proxy | Mature MITM + CA minting out of the box; its addon API means the SQLite logger is 80 lines of Python. Swap for `hudsucker` later if perf matters. |
| CA pre-installed at build time | No first-run prompt, no trust-store negotiation — we own the VM. Chromium and Node see a clean chain. |
| Playwright launches Chromium with `--proxy-server` | No need for `--ignore-certificate-errors`: the CA is trusted so validation stays real. This means we still catch upstream cert problems. |
| Ephemeral container, state in `/state` volume | One task → one container → one flow database. No cross-task contamination. |
| Agent runs in the same container | No RPC boundary. Agent reads `flows.db` directly via `flows.py`. MCP-over-localhost also available for Claude Code. |
| Per-task Chromium profile in `/tmp` | Every run is cookieless / clean unless the task mounts its own profile. |

## Known limitations

- **Chromium HSTS-pinned hosts** (`*.google.com`, some banking, Chrome's built-in pins). User-installed CAs don't override Chrome's hardcoded pins. Workaround: add `--ignore-certificate-errors-spki-list=<spki-hash-of-our-CA>` for those specific hosts. Ship a helper that computes it.
- **HTTP/3 (QUIC).** Chromium will prefer h3 when servers advertise it. mitmproxy handles h1/h2 but not h3. We pass `--disable-quic` to Chromium; traffic falls back to h2.
- **Non-browser egress.** If the agent also runs `curl`/`requests`/`node`, those processes also need the CA. This image sets `SSL_CERT_FILE`, `NODE_EXTRA_CA_CERTS`, and `REQUESTS_CA_BUNDLE` globally to catch them.
- **Certificate pinning in non-browser binaries** (e.g. apps that ship their own cert list): out of scope. Use eBPF uprobes (Phase 4 in the main design doc) if you need those.

## Files

| File | Purpose |
|---|---|
| `Dockerfile` | Base image + tool install. |
| `entrypoint.sh` | CA bootstrap, trust-store install, mitmproxy launch, then `exec`s the agent. |
| `mitm_addon.py` | mitmproxy addon that writes every flow to SQLite. |
| `flows.py` | Python helper the agent uses to query captured flows. |
| `mcp_server.py` | FastMCP server exposing the flow store to Claude agents. |
| `agent_example.py` | Sample Playwright agent: navigate to a URL, wait for idle, query flows, print them. |
| `docker-compose.yml` | One-task invocation with mounted volume. |

## MCP server — give Claude agents a query surface

`mcp_server.py` exposes the capture store over MCP so a Claude agent
(Claude Code, Claude Agent SDK, etc.) can ask structured questions about the
traffic its browser made. The tool names deliberately mirror the upstream
`powhttp-mcp` surface so prompts port over.

Tools:

| Tool | Use it for |
|---|---|
| `session_mark(description)` | Drop a checkpoint before an action. Returns a `mark_id`. |
| `session_entries_since_mark(mark_id?, host?, path_like?, method?, status?, limit)` | List flows captured since a mark — the "what did clicking this button fire?" primitive. Defaults to the latest mark. |
| `session_list_marks(limit)` | Enumerate session marks, newest first. |
| `search_entries(host?, path_like?, method?, status?, since_ms?, fts?, limit)` | General filter. `fts` hits sqlite's fts5 index over URL + bodies. |
| `get_entry(entry_id, body_mode, body_limit)` | Full request+response. `body_mode` is `truncated` / `raw` / `none`. |
| `extract_endpoints(since_ms?, mark_id?)` | Cluster URLs with `/users/101` vs `/users/202` collapsed — the "what endpoints did this session hit?" view. |
| `query_body(entry_id, expression, mode, max_results)` | JQ against JSON bodies, regex against anything. `mode=auto` picks based on content-type. |
| `inspect_body(entry_id, sample_limit)` | JSON shape / HTML element counts — use before `query_body` to know what expression to write. |

Transports (controlled by env):

- `POWHTTP_MCP_TRANSPORT=stdio` (default) — the agent spawns `mcp_server.py`
  as a subprocess. Best when the agent runs **inside** the container.
- `POWHTTP_MCP_TRANSPORT=sse` — bind HTTP+SSE on
  `POWHTTP_MCP_HOST:POWHTTP_MCP_PORT` (defaults `0.0.0.0:7878`). Best when
  the agent runs on the host or in a sibling container.

### Wiring the MCP into Claude Code

Run the container with port 7878 published and the MCP server on SSE:

```bash
docker run --rm -d --name powhttp-box \
  -p 7878:7878 \
  -v "$PWD/captures:/state" \
  -e POWHTTP_MCP_TRANSPORT=sse \
  -e TASK_URL="https://example.com" \
  powhttp-agent-box \
  bash -lc 'python -u /app/mcp_server.py & python -u /app/agent_example.py; wait'
```

Then register it with Claude Code:

```bash
claude mcp add --transport sse powhttp-box http://localhost:7878/sse
```

For stdio (simpler, no port exposure), exec into a running container and
register a local command:

```json
{
  "mcpServers": {
    "powhttp-box": {
      "command": "docker",
      "args": ["exec", "-i", "powhttp-box", "python", "-u", "/app/mcp_server.py"]
    }
  }
}
```

### Wiring the MCP into the Claude Agent SDK

```python
from anthropic import Anthropic  # for completeness
from claude_agent_sdk import ClaudeAgent, McpServerSpec

agent = ClaudeAgent(
    mcp_servers=[
        McpServerSpec(name="powhttp-box", transport="sse",
                      url="http://localhost:7878/sse"),
        # plus a browser-control MCP, e.g. @playwright/mcp
    ],
)
```

### Example agent loop

```
1. session_mark(description="open login page")
2. <agent drives browser: navigate, fill creds, click Login>
3. session_entries_since_mark()
       → sees POST /api/session (200), then GET /api/me (200)
4. extract_endpoints(mark_id=...)      # group flows into patterns
5. get_entry(entry_id=…, body_mode="truncated")
6. query_body(entry_id=…, expression=".token", mode="jq")
```

This is exactly the "ephemeral browser box + mark/diff flow inspection"
loop the real `powhttp` desktop app offers, with a Linux-native substrate.

## Next steps

1. **Export HAR** alongside SQLite at teardown so any HAR viewer (Chrome DevTools, Charles, etc.) can open the capture.
2. **Per-host SPKI override helper** so pinned Google hosts work.
3. **Flows-to-S3 uploader** for fleet-scale captures.
4. **Bundled browser-control MCP** (e.g. `@playwright/mcp`) so the agent has one image for both capture and driving.
