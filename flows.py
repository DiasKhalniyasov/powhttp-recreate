"""Tiny read-side helper the agent uses to query captured flows.

Agent-facing surface that mirrors the MCP tool names in powhttp-mcp so we can
swap in the real `da-powhttp-mcp` binary later without changing agent code.
"""

from __future__ import annotations

import json
import os
import sqlite3
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable

DB_PATH = Path(os.environ.get("POWHTTP_FLOWS_DB", "/state/flows.db"))
BODIES_DIR = Path(os.environ.get("POWHTTP_BODIES_DIR", "/state/bodies"))


@dataclass
class Entry:
    entry_id: str
    started_at: int
    method: str
    url: str
    host: str
    status: int | None
    http_version: str | None
    content_type: str | None
    cluster_id: str

    @classmethod
    def from_row(cls, row: sqlite3.Row) -> "Entry":
        return cls(
            entry_id=row["entry_id"],
            started_at=row["started_at"],
            method=row["method"],
            url=row["url"],
            host=row["remote_host"],
            status=row["status"],
            http_version=row["http_version"],
            content_type=row["content_type"],
            cluster_id=row["cluster_id"],
        )


def _connect() -> sqlite3.Connection:
    conn = sqlite3.connect(DB_PATH, isolation_level=None)
    conn.row_factory = sqlite3.Row
    return conn


def search_entries(
    host: str | None = None,
    path_like: str | None = None,
    method: str | None = None,
    status: int | None = None,
    since_ms: int | None = None,
    limit: int = 100,
) -> list[Entry]:
    """powhttp_search_entries-equivalent."""
    sql = ["SELECT * FROM entries WHERE 1=1"]
    params: list = []
    if host:
        sql.append("AND remote_host = ?"); params.append(host)
    if path_like:
        sql.append("AND path LIKE ?"); params.append(path_like)
    if method:
        sql.append("AND method = ?"); params.append(method.upper())
    if status is not None:
        sql.append("AND status = ?"); params.append(status)
    if since_ms is not None:
        sql.append("AND started_at >= ?"); params.append(since_ms)
    sql.append("ORDER BY started_at DESC LIMIT ?"); params.append(limit)
    with _connect() as conn:
        rows = conn.execute(" ".join(sql), params).fetchall()
    return [Entry.from_row(r) for r in rows]


def get_entry(entry_id: str, body_mode: str = "truncated", body_limit: int = 64 * 1024) -> dict:
    """powhttp_get_entry-equivalent. body_mode: 'raw' | 'truncated' | 'none'."""
    with _connect() as conn:
        row = conn.execute("SELECT * FROM entries WHERE entry_id = ?", (entry_id,)).fetchone()
    if not row:
        raise KeyError(entry_id)
    out = {k: row[k] for k in row.keys()}
    out["req_headers"] = json.loads(row["req_headers"] or "[]")
    out["resp_headers"] = json.loads(row["resp_headers"] or "[]")
    if body_mode == "none":
        out["req_body"] = out["resp_body"] = None
    else:
        out["req_body"] = _read_body(row["req_body_inline"], row["req_body_ref"], body_mode, body_limit)
        out["resp_body"] = _read_body(row["resp_body_inline"], row["resp_body_ref"], body_mode, body_limit)
    # Strip the raw columns we just materialized.
    for k in ("req_body_inline", "req_body_ref", "resp_body_inline", "resp_body_ref"):
        out.pop(k, None)
    return out


def _read_body(inline: bytes | None, ref: str | None, mode: str, limit: int) -> str | None:
    blob: bytes | None = None
    if inline is not None:
        blob = bytes(inline)
    elif ref:
        p = BODIES_DIR / ref[:2] / ref
        if p.exists():
            blob = p.read_bytes()
    if blob is None:
        return None
    if mode == "truncated" and len(blob) > limit:
        blob = blob[:limit]
    try:
        return blob.decode("utf-8")
    except UnicodeDecodeError:
        return blob.decode("utf-8", errors="replace")


def extract_endpoints(since_ms: int | None = None) -> list[dict]:
    """powhttp_extract_endpoints-equivalent: group by cluster_id."""
    sql = [
        "SELECT cluster_id, method, remote_host,",
        "       COUNT(*) AS hits,",
        "       MIN(url) AS example_url,",
        "       MIN(started_at) AS first_seen,",
        "       MAX(started_at) AS last_seen",
        "FROM entries",
    ]
    params: list = []
    if since_ms is not None:
        sql.append("WHERE started_at >= ?"); params.append(since_ms)
    sql.append("GROUP BY cluster_id, method, remote_host ORDER BY hits DESC")
    with _connect() as conn:
        rows = conn.execute(" ".join(sql), params).fetchall()
    return [dict(r) for r in rows]


def fts_search(query: str, limit: int = 50) -> list[Entry]:
    """Full-text across URL + req_body + resp_body."""
    sql = """
        SELECT e.* FROM entries e
        JOIN entries_fts f ON f.rowid = e.rowid
        WHERE entries_fts MATCH ?
        ORDER BY e.started_at DESC
        LIMIT ?
    """
    with _connect() as conn:
        rows = conn.execute(sql, (query, limit)).fetchall()
    return [Entry.from_row(r) for r in rows]


if __name__ == "__main__":
    # Tiny CLI for debugging from inside the container.
    import argparse, sys
    ap = argparse.ArgumentParser()
    sub = ap.add_subparsers(dest="cmd", required=True)
    sub.add_parser("list")
    gp = sub.add_parser("get"); gp.add_argument("entry_id")
    sp = sub.add_parser("search"); sp.add_argument("q")
    ep = sub.add_parser("endpoints")
    args = ap.parse_args()

    if args.cmd == "list":
        for e in search_entries(limit=50):
            print(f"{e.started_at}  {e.method:6} {e.status}  {e.url}")
    elif args.cmd == "get":
        print(json.dumps(get_entry(args.entry_id), indent=2, default=str))
    elif args.cmd == "search":
        for e in fts_search(args.q):
            print(f"{e.method:6} {e.status}  {e.url}")
    elif args.cmd == "endpoints":
        for row in extract_endpoints():
            print(f"{row['hits']:5}x  {row['method']:6} {row['remote_host']}  {row['example_url']}")
