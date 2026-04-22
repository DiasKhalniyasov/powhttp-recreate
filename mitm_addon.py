"""mitmproxy addon: persist every HTTP flow to SQLite + blob store.

Loaded by mitmdump via `--scripts /app/mitm_addon.py`. Reads config from env:
  POWHTTP_FLOWS_DB    — sqlite file path (required)
  POWHTTP_BODIES_DIR  — directory for body blobs >64 KB (required)

Schema matches the `entries` table described in powhttp-linux-design.md §7.1,
trimmed to what we can actually fill in from mitmproxy's HTTPFlow object.
"""

from __future__ import annotations

import hashlib
import json
import logging
import os
import sqlite3
import time
import uuid
from pathlib import Path
from typing import Any

from mitmproxy import http

log = logging.getLogger("mitm_addon")

DB_PATH = Path(os.environ["POWHTTP_FLOWS_DB"])
BODIES_DIR = Path(os.environ["POWHTTP_BODIES_DIR"])
INLINE_BODY_MAX = 64 * 1024  # bodies smaller than this go inline in SQLite

SCHEMA = """
CREATE TABLE IF NOT EXISTS entries (
    entry_id        TEXT PRIMARY KEY,
    started_at      INTEGER NOT NULL,
    ended_at        INTEGER,
    remote_host     TEXT NOT NULL,
    remote_port     INTEGER NOT NULL,
    remote_ip       TEXT,
    sni             TEXT,
    alpn            TEXT,
    http_version    TEXT,
    method          TEXT NOT NULL,
    url             TEXT NOT NULL,
    scheme          TEXT,
    path            TEXT,
    req_headers     TEXT NOT NULL,        -- JSON list of [name, value]
    req_body_inline BLOB,
    req_body_ref    TEXT,                  -- sha256 hex if on disk
    req_body_size   INTEGER,
    status          INTEGER,
    resp_headers    TEXT,
    resp_body_inline BLOB,
    resp_body_ref   TEXT,
    resp_body_size  INTEGER,
    content_type    TEXT,
    error           TEXT,
    cluster_id      TEXT
);

CREATE INDEX IF NOT EXISTS entries_by_time ON entries(started_at DESC);
CREATE INDEX IF NOT EXISTS entries_by_host ON entries(remote_host, started_at DESC);
CREATE INDEX IF NOT EXISTS entries_by_status ON entries(status, started_at DESC);
CREATE INDEX IF NOT EXISTS entries_by_cluster ON entries(cluster_id, started_at DESC);

CREATE VIRTUAL TABLE IF NOT EXISTS entries_fts USING fts5(
    url, req_body, resp_body,
    content='entries',
    content_rowid='rowid'
);
"""


def _open_db() -> sqlite3.Connection:
    BODIES_DIR.mkdir(parents=True, exist_ok=True)
    DB_PATH.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(DB_PATH, isolation_level=None, check_same_thread=False)
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA synchronous=NORMAL")
    conn.executescript(SCHEMA)
    return conn


def _persist_body(blob: bytes | None) -> tuple[bytes | None, str | None, int]:
    """Return (inline_bytes, on_disk_ref, size). Large bodies are content-addressed."""
    if not blob:
        return None, None, 0
    size = len(blob)
    if size <= INLINE_BODY_MAX:
        return blob, None, size
    digest = hashlib.sha256(blob).hexdigest()
    path = BODIES_DIR / digest[:2] / digest
    if not path.exists():
        path.parent.mkdir(parents=True, exist_ok=True)
        tmp = path.with_suffix(".tmp")
        tmp.write_bytes(blob)
        tmp.rename(path)
    return None, digest, size


def _headers_to_json(headers: Any) -> str:
    return json.dumps([[k, v] for k, v in headers.items(multi=True)], ensure_ascii=False)


def _cluster_id(method: str, host: str, path: str) -> str:
    """Coarse endpoint grouping — numeric + long-opaque path segments become {id}."""
    import re
    normalized = []
    for seg in path.split("/"):
        if not seg:
            normalized.append(seg)
            continue
        if re.fullmatch(r"\d+", seg):
            normalized.append("{id}")
        elif re.fullmatch(r"[0-9a-fA-F-]{16,}", seg):
            normalized.append("{id}")
        elif re.fullmatch(r"[A-Za-z0-9_-]{24,}", seg):
            normalized.append("{id}")
        else:
            normalized.append(seg)
    key = f"{method.upper()}|{host.lower()}|{'/'.join(normalized)}"
    return hashlib.blake2s(key.encode(), digest_size=8).hexdigest()


class Persist:
    def __init__(self) -> None:
        self.conn = _open_db()
        log.info(f"[powhttp] logging flows to {DB_PATH}")

    def response(self, flow: http.HTTPFlow) -> None:
        """mitmproxy fires this once request+response are both complete."""
        self._record(flow)

    def error(self, flow: http.HTTPFlow) -> None:
        """Connection errors, TLS failures, upstream resets."""
        self._record(flow, error=str(flow.error) if flow.error else "unknown")

    def _record(self, flow: http.HTTPFlow, error: str | None = None) -> None:
        try:
            req = flow.request
            resp = flow.response
            host = req.pretty_host
            port = req.port
            method = req.method
            url = req.pretty_url
            path = req.path or "/"
            scheme = req.scheme

            req_inline, req_ref, req_size = _persist_body(req.raw_content)
            resp_inline, resp_ref, resp_size = (None, None, 0)
            status = None
            resp_headers_json = None
            content_type = None
            if resp is not None:
                resp_inline, resp_ref, resp_size = _persist_body(resp.raw_content)
                status = resp.status_code
                resp_headers_json = _headers_to_json(resp.headers)
                content_type = resp.headers.get("content-type")

            started_ms = int(flow.timestamp_created * 1000)
            ended_ms = None
            if resp is not None and resp.timestamp_end:
                ended_ms = int(resp.timestamp_end * 1000)

            alpn = None
            sni = None
            if flow.server_conn and flow.server_conn.tls_established:
                alpn = (flow.server_conn.alpn or b"").decode(errors="replace") or None
                sni = flow.server_conn.sni

            http_version = None
            if resp is not None and resp.http_version:
                http_version = resp.http_version
            elif req.http_version:
                http_version = req.http_version

            entry_id = str(uuid.uuid4())
            cid = _cluster_id(method, host, path)

            self.conn.execute(
                """
                INSERT INTO entries (
                    entry_id, started_at, ended_at,
                    remote_host, remote_port, remote_ip,
                    sni, alpn, http_version,
                    method, url, scheme, path,
                    req_headers, req_body_inline, req_body_ref, req_body_size,
                    status, resp_headers, resp_body_inline, resp_body_ref, resp_body_size,
                    content_type, error, cluster_id
                ) VALUES (?,?,?, ?,?,?, ?,?,?, ?,?,?,?, ?,?,?,?, ?,?,?,?,?, ?,?,?)
                """,
                (
                    entry_id, started_ms, ended_ms,
                    host, port, flow.server_conn.peername[0] if flow.server_conn and flow.server_conn.peername else None,
                    sni, alpn, http_version,
                    method, url, scheme, path,
                    _headers_to_json(req.headers), req_inline, req_ref, req_size,
                    status, resp_headers_json, resp_inline, resp_ref, resp_size,
                    content_type, error, cid,
                ),
            )

            # Mirror text-ish body content into FTS. Skip binary types.
            self._index_fts(entry_id, url, req.raw_content, resp.raw_content if resp else None, content_type)
        except Exception as e:
            log.warning(f"[powhttp] persist failed: {e!r}")

    def _index_fts(self, entry_id: str, url: str, req_body: bytes | None, resp_body: bytes | None, content_type: str | None) -> None:
        def text_of(blob: bytes | None) -> str:
            if not blob:
                return ""
            if len(blob) > 512 * 1024:   # don't FTS huge bodies
                return ""
            try:
                return blob.decode("utf-8", errors="ignore")
            except Exception:
                return ""
        # rowid is the implicit rowid of the row we just inserted; look it up.
        row = self.conn.execute("SELECT rowid FROM entries WHERE entry_id=?", (entry_id,)).fetchone()
        if not row:
            return
        self.conn.execute(
            "INSERT INTO entries_fts(rowid, url, req_body, resp_body) VALUES (?,?,?,?)",
            (row[0], url, text_of(req_body), text_of(resp_body)),
        )


addons = [Persist()]
