"""MCP server for the powhttp-agent-box.

Exposes captured HTTP traffic to a Claude agent as MCP tools. Deliberately
mirrors the names and semantics of the core powhttp-mcp tools so prompts and
muscle memory transfer. Covers only the capture/query surface — feed execution
and GitHub PR tools from upstream powhttp-mcp are out of scope for this box.

Tools:
    session_mark                   — drop a checkpoint before the agent acts
    session_entries_since_mark     — list flows captured since a mark
    session_list_marks             — enumerate active marks
    search_entries                 — filter by host/path/method/status/time
    get_entry                      — full request+response for one entry_id
    extract_endpoints              — cluster similar URLs (powhttp's endpoint groups)
    query_body                     — JQ / regex against captured response bodies
    inspect_body                   — JSON shape / schema inference for a body

Transport: stdio by default (for Claude Code / SDK subprocess spawning).
Set POWHTTP_MCP_TRANSPORT=http to bind HTTP+SSE on :7878 instead — useful
when the MCP runs in the container and the agent runs elsewhere.
"""

from __future__ import annotations

import json
import os
import re
import sys
import time
import uuid
from dataclasses import asdict, dataclass, field
from typing import Any, Literal

# Reuse the query helper we already built and verified.
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import flows  # noqa: E402

try:
    from mcp.server.fastmcp import FastMCP
except ImportError:
    sys.stderr.write(
        "ERROR: `mcp` package not installed. Add `pip install 'mcp[cli]'` to the Dockerfile.\n"
    )
    raise

try:
    import jq as _jq  # python-jq binding to libjq
    HAS_JQ = True
except ImportError:
    HAS_JQ = False


SERVER_NAME = "powhttp-box"
SERVER_DESCRIPTION = (
    "Query the HTTP traffic captured by the agent's browser. Use session_mark "
    "before navigating, then session_entries_since_mark to see what fired."
)

mcp = FastMCP(SERVER_NAME, instructions=SERVER_DESCRIPTION)


# ---------------------------------------------------------------------------
# In-memory mark store. Matches powhttp: marks are session-scoped and ephemeral
# (they reset when the container restarts, which is per-task anyway).
# ---------------------------------------------------------------------------

@dataclass
class Mark:
    id: str
    created_at_ms: int
    description: str
    entry_count_at_mark: int


_marks: dict[str, Mark] = {}


def _total_entries() -> int:
    import sqlite3
    conn = sqlite3.connect(flows.DB_PATH)
    try:
        return conn.execute("SELECT COUNT(*) FROM entries").fetchone()[0]
    finally:
        conn.close()


def _entry_summary(e: flows.Entry) -> dict:
    """Compact row the LLM sees in list responses. Full entry → get_entry."""
    return {
        "entry_id": e.entry_id,
        "ts": e.started_at,
        "method": e.method,
        "status": e.status,
        "host": e.host,
        "url": e.url,
        "content_type": e.content_type,
        "http_version": e.http_version,
        "cluster_id": e.cluster_id,
    }


# ---------------------------------------------------------------------------
# Session tools
# ---------------------------------------------------------------------------

@mcp.tool()
def session_mark(description: str = "") -> dict:
    """Drop a checkpoint before the agent takes an action.

    The mark records the current entry count; pair with session_entries_since_mark
    after the action to see exactly which HTTP flows the action produced. This is
    the right primitive when you want to attribute traffic to a specific step in
    your workflow.

    Args:
        description: Optional human-readable label (e.g. "clicked login").

    Returns:
        Mark metadata. Save the `id` to pass to session_entries_since_mark later.
    """
    m = Mark(
        id="mk_" + uuid.uuid4().hex[:12],
        created_at_ms=int(time.time() * 1000),
        description=description,
        entry_count_at_mark=_total_entries(),
    )
    _marks[m.id] = m
    return asdict(m)


@mcp.tool()
def session_entries_since_mark(
    mark_id: str | None = None,
    host: str | None = None,
    path_like: str | None = None,
    method: str | None = None,
    status: int | None = None,
    limit: int = 100,
) -> dict:
    """List HTTP flows captured since a mark.

    If mark_id is omitted, uses the most recently created mark. Filters stack
    and are ANDed; all are optional. Returns summaries only — use get_entry
    to fetch headers and body for a specific flow.

    Args:
        mark_id: Mark to compare against; defaults to the latest mark.
        host: Exact remote host match (e.g. "api.example.com").
        path_like: SQL LIKE pattern on URL path (e.g. "/api/%").
        method: HTTP method filter (GET, POST, …).
        status: HTTP status filter (200, 404, …).
        limit: Maximum rows to return (default 100).
    """
    if not _marks:
        return {"error": "no marks exist; call session_mark first"}
    if mark_id is None:
        mark_id = max(_marks.values(), key=lambda m: m.created_at_ms).id
    mark = _marks.get(mark_id)
    if mark is None:
        return {"error": f"unknown mark_id: {mark_id}", "known_marks": list(_marks)}

    entries = flows.search_entries(
        host=host,
        path_like=path_like,
        method=method,
        status=status,
        since_ms=mark.created_at_ms,
        limit=limit,
    )
    return {
        "mark": asdict(mark),
        "entries_now": _total_entries(),
        "new_count": len(entries),
        "entries": [_entry_summary(e) for e in entries],
        "truncated": len(entries) == limit,
    }


@mcp.tool()
def session_list_marks(limit: int = 20) -> dict:
    """List recent session marks, newest first."""
    ms = sorted(_marks.values(), key=lambda m: m.created_at_ms, reverse=True)[:limit]
    return {"total": len(_marks), "marks": [asdict(m) for m in ms]}


# ---------------------------------------------------------------------------
# Query tools
# ---------------------------------------------------------------------------

@mcp.tool()
def search_entries(
    host: str | None = None,
    path_like: str | None = None,
    method: str | None = None,
    status: int | None = None,
    since_ms: int | None = None,
    fts: str | None = None,
    limit: int = 50,
) -> dict:
    """General search over captured HTTP flows.

    Filters are ANDed. Prefer `fts` for "find a flow whose body contains X";
    prefer the structured filters when you know the host/path.

    Args:
        host: Exact host match.
        path_like: SQL LIKE pattern on path.
        method: HTTP method.
        status: Status code.
        since_ms: Unix millis — entries whose started_at is >= this.
        fts: Full-text query over URL + request body + response body (sqlite fts5).
        limit: Max rows (default 50).
    """
    if fts:
        results = flows.fts_search(fts, limit=limit)
    else:
        results = flows.search_entries(
            host=host,
            path_like=path_like,
            method=method,
            status=status,
            since_ms=since_ms,
            limit=limit,
        )
    return {
        "count": len(results),
        "truncated": len(results) == limit,
        "entries": [_entry_summary(e) for e in results],
    }


@mcp.tool()
def get_entry(
    entry_id: str,
    body_mode: Literal["raw", "truncated", "none"] = "truncated",
    body_limit: int = 65536,
) -> dict:
    """Full request + response for a single flow.

    Args:
        entry_id: The entry's ULID/UUID as returned by search or session tools.
        body_mode:
            - "truncated" (default): return up to body_limit chars of each body.
            - "raw": return the full body (can be large — use with care).
            - "none": headers-only, no body payload.
        body_limit: Byte cap for truncated mode.
    """
    try:
        return flows.get_entry(entry_id, body_mode=body_mode, body_limit=body_limit)
    except KeyError:
        return {"error": f"entry not found: {entry_id}"}


@mcp.tool()
def active_session() -> dict:
    """Current capture session — ULID and ordered list of entry IDs.

    Equivalent to powhttp's `/sessions/active`. Use this to get a handle on
    the run in progress before drilling into specific entries.
    """
    s = flows.active_session()
    return s or {"error": "no sessions recorded yet"}


@mcp.tool()
def list_sessions(limit: int = 50) -> dict:
    """All recorded proxy-daemon runs, newest first."""
    rows = flows.list_sessions(limit=limit)
    return {"count": len(rows), "sessions": rows}


@mcp.tool()
def get_tls_connection(connection_id: str) -> dict:
    """Full TLS handshake record — JA3/JA4, cipher, cert chain, client cert.

    `connection_id` comes from an entry's `tls_conn_id` field (fetch it via
    get_entry). Raw ClientHello bytes are returned hex-encoded.
    """
    row = flows.get_tls_connection(connection_id)
    return row or {"error": f"tls connection not found: {connection_id}"}


@mcp.tool()
def get_http2_stream_frames(
    connection_id: str,
    stream_id: int | None = None,
    limit: int = 500,
) -> dict:
    """HTTP/2 frame-level trace (DATA, HEADERS, WINDOW_UPDATE, RST_STREAM, …).

    Equivalent to powhttp's `/http2/{conn}/streams/{sid}`. Omit `stream_id`
    to see the full connection — useful for SETTINGS/PING/GOAWAY which live
    on stream 0.

    Args:
        connection_id: h2_conn_id from a captured entry.
        stream_id: optional — filter to a specific stream.
        limit: max frames to return.
    """
    frames = flows.get_http2_stream_frames(connection_id, stream_id=stream_id, limit=limit)
    return {
        "connection_id": connection_id,
        "stream_id": stream_id,
        "count": len(frames),
        "truncated": len(frames) == limit,
        "frames": frames,
    }


@mcp.tool()
def get_ws_messages(entry_id: str, limit: int = 1000) -> dict:
    """WebSocket frames for an upgrade entry, in arrival order.

    Binary payloads are hex-encoded. The direction field is 'from_client'
    or 'from_server'.
    """
    msgs = flows.get_ws_messages(entry_id, limit=limit)
    return {
        "entry_id": entry_id,
        "count": len(msgs),
        "truncated": len(msgs) == limit,
        "messages": msgs,
    }


@mcp.tool()
def get_sse_events(entry_id: str, limit: int = 1000) -> dict:
    """Parsed Server-Sent Events for a text/event-stream entry."""
    events = flows.get_sse_events(entry_id, limit=limit)
    return {
        "entry_id": entry_id,
        "count": len(events),
        "truncated": len(events) == limit,
        "events": events,
    }


@mcp.tool()
def extract_endpoints(since_ms: int | None = None, mark_id: str | None = None) -> dict:
    """Cluster captured flows into endpoint groups.

    Groups URLs with differing numeric / opaque path segments (e.g.
    /api/users/101 and /api/users/202) under one cluster_id, so you can
    see "this pattern fired N times" instead of N rows for N IDs.

    Args:
        since_ms: Only include entries with started_at >= this.
        mark_id: Convenience — if set, derives since_ms from the mark.
    """
    if mark_id:
        m = _marks.get(mark_id)
        if not m:
            return {"error": f"unknown mark_id: {mark_id}"}
        since_ms = m.created_at_ms
    rows = flows.extract_endpoints(since_ms=since_ms)
    return {"count": len(rows), "clusters": rows}


# ---------------------------------------------------------------------------
# Body analysis tools
# ---------------------------------------------------------------------------

@mcp.tool()
def query_body(
    entry_id: str,
    expression: str,
    mode: Literal["jq", "regex", "auto"] = "auto",
    max_results: int = 100,
) -> dict:
    """Run a JQ or regex expression against a captured response body.

    JQ mode needs the `jq` Python package to be installed (pip install jq).
    Regex mode is always available. "auto" picks JQ when content-type looks
    like JSON, otherwise regex.

    Args:
        entry_id: The flow to query.
        expression: JQ expression (e.g. ".data[] | .id") or regex pattern.
        mode: "jq", "regex", or "auto".
        max_results: Cap on regex matches or JQ output list length.

    Returns:
        Results, plus metadata about content-type and which mode was applied.
    """
    try:
        entry = flows.get_entry(entry_id, body_mode="raw")
    except KeyError:
        return {"error": f"entry not found: {entry_id}"}

    body = entry.get("resp_body") or ""
    ct = (entry.get("content_type") or "").lower()

    if mode == "auto":
        mode = "jq" if "json" in ct else "regex"

    if mode == "jq":
        if not HAS_JQ:
            return {"error": "jq mode requested but python-jq not installed; use mode='regex'"}
        try:
            parsed = json.loads(body)
        except json.JSONDecodeError as e:
            return {"error": f"body is not valid JSON: {e}", "content_type": ct}
        try:
            results = _jq.compile(expression).input(parsed).all()
        except ValueError as e:
            return {"error": f"jq compile/eval error: {e}"}
        return {
            "mode": "jq",
            "content_type": ct,
            "count": len(results),
            "results": results[:max_results],
            "truncated": len(results) > max_results,
        }

    # regex mode
    try:
        rx = re.compile(expression, re.MULTILINE | re.DOTALL)
    except re.error as e:
        return {"error": f"bad regex: {e}"}
    matches = []
    for m in rx.finditer(body):
        matches.append(m.groupdict() if m.groupdict() else (m.groups() or m.group(0)))
        if len(matches) >= max_results:
            break
    return {
        "mode": "regex",
        "content_type": ct,
        "count": len(matches),
        "results": matches,
        "truncated": len(matches) == max_results,
    }


@mcp.tool()
def inspect_body(entry_id: str, sample_limit: int = 5) -> dict:
    """Summarize the shape of a captured response body.

    For JSON: returns top-level type, keys (if object), and up to sample_limit
    example items (if array). For HTML: element counts + a few title/heading
    samples. For everything else: content-type + size + first 400 bytes.

    Use this before query_body to figure out what expression to write.
    """
    try:
        entry = flows.get_entry(entry_id, body_mode="raw")
    except KeyError:
        return {"error": f"entry not found: {entry_id}"}

    body = entry.get("resp_body") or ""
    ct = (entry.get("content_type") or "").lower()
    size = len(body.encode("utf-8")) if body else 0

    base = {"entry_id": entry_id, "content_type": ct, "size_bytes": size}

    if "json" in ct:
        try:
            parsed = json.loads(body)
        except json.JSONDecodeError as e:
            return {**base, "shape": "json-malformed", "error": str(e)}
        return {**base, "shape": _json_shape(parsed, sample_limit)}

    if "html" in ct or "xml" in ct:
        # Rough, regex-based — avoids a heavy lxml dep. Good enough for
        # "what's on this page at a glance".
        return {
            **base,
            "shape": "html/xml",
            "element_counts": _count_elements(body),
            "titles": re.findall(r"<title[^>]*>([^<]{1,200})</title>", body, re.I)[:sample_limit],
            "h1": re.findall(r"<h1[^>]*>(.*?)</h1>", body, re.I | re.DOTALL)[:sample_limit],
        }

    return {
        **base,
        "shape": "text/binary",
        "preview": body[:400] if body else "",
    }


def _json_shape(obj: Any, sample_limit: int, _depth: int = 0) -> dict:
    if _depth > 3:
        return {"type": type(obj).__name__, "truncated": True}
    if isinstance(obj, dict):
        return {
            "type": "object",
            "keys": list(obj)[:25],
            "field_types": {k: type(v).__name__ for k, v in list(obj.items())[:25]},
        }
    if isinstance(obj, list):
        return {
            "type": "array",
            "length": len(obj),
            "sample_element_shape": _json_shape(obj[0], sample_limit, _depth + 1) if obj else None,
        }
    return {"type": type(obj).__name__, "value_preview": str(obj)[:100]}


def _count_elements(html: str) -> dict:
    return {
        tag: len(re.findall(rf"<{tag}[\s>]", html, re.I))
        for tag in ("a", "script", "img", "form", "input", "iframe", "div", "span")
    }


# ---------------------------------------------------------------------------
# Transport
# ---------------------------------------------------------------------------

def main() -> None:
    transport = os.environ.get("POWHTTP_MCP_TRANSPORT", "stdio").lower()
    if transport in ("http", "sse", "streamable-http"):
        # Bind HTTP+SSE — use when the agent runs outside the container.
        # FastMCP reads host/port from its settings object; mcp.run(transport=...)
        # doesn't accept them as kwargs.
        host = os.environ.get("POWHTTP_MCP_HOST", "0.0.0.0")
        port = int(os.environ.get("POWHTTP_MCP_PORT", "7878"))
        mcp.settings.host = host
        mcp.settings.port = port
        chosen = "streamable-http" if transport == "streamable-http" else "sse"
        sys.stderr.write(f"[powhttp-mcp] serving {chosen} on http://{host}:{port}\n")
        mcp.run(transport=chosen)
    else:
        sys.stderr.write("[powhttp-mcp] stdio transport\n")
        mcp.run(transport="stdio")


if __name__ == "__main__":
    main()
