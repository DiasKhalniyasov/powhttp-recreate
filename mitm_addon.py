"""mitmproxy addon: persist every HTTP flow to SQLite + blob store.

Loaded by mitmdump via `--scripts /app/mitm_addon.py`. Reads config from env:
  POWHTTP_FLOWS_DB    — sqlite file path (required)
  POWHTTP_BODIES_DIR  — directory for body blobs >64 KB (required)
  POWHTTP_SESSION_ID  — optional ULID; if absent we mint one

Captures — to match powhttp's wire model:
  sessions          — one row per addon lifetime (ULID, started_at, ended_at)
  entries           — per HTTP transaction (ULID), FK → sessions
  tls_connections   — per TLS handshake (cipher, cert chain, JA3/JA4, client cert)
  h2_frames         — frame-level tap via hyper-h2 monkey-patch
  ws_messages       — WebSocket frames (text/binary, direction, timestamp)
  sse_events        — Server-Sent Events parsed from text/event-stream responses

Entries carry FKs to the TLS connection and (if HTTP/2) the h2 connection so
the MCP layer can walk from a flow → its handshake → its frames the same way
powhttp's Tauri IPC does.
"""

from __future__ import annotations

import hashlib
import json
import logging
import os
import re
import sqlite3
import sys
import time
from pathlib import Path
from typing import Any

from mitmproxy import http, tls

# Allow importing sibling helpers whether the addon is loaded via absolute
# /app path (Docker) or relative during dev.
sys.path.insert(0, str(Path(__file__).resolve().parent))

from ids import new_ulid  # noqa: E402
from ja3 import compute as compute_fingerprint  # noqa: E402
import h2_tap  # noqa: E402
import doh  # noqa: E402

log = logging.getLogger("mitm_addon")

DB_PATH = Path(os.environ["POWHTTP_FLOWS_DB"])
BODIES_DIR = Path(os.environ["POWHTTP_BODIES_DIR"])
INLINE_BODY_MAX = 64 * 1024  # bodies smaller than this go inline in SQLite

SCHEMA = """
CREATE TABLE IF NOT EXISTS sessions (
    session_id   TEXT PRIMARY KEY,
    started_at   INTEGER NOT NULL,
    ended_at     INTEGER,
    proxy_port   INTEGER,
    pid          INTEGER,
    hostname     TEXT
);

CREATE TABLE IF NOT EXISTS tls_connections (
    connection_id     TEXT PRIMARY KEY,
    session_id        TEXT NOT NULL,
    started_at        INTEGER NOT NULL,
    sni               TEXT,
    alpn_offered      TEXT,             -- JSON list
    alpn_negotiated   TEXT,
    tls_version       TEXT,             -- e.g. "TLSv1.3"
    cipher_suite      TEXT,
    ja3               TEXT,
    ja3_hash          TEXT,
    ja4               TEXT,
    client_hello_raw  BLOB,             -- raw CH bytes for later re-parse
    server_cert_chain TEXT,             -- JSON list of PEM strings
    client_cert_subject TEXT,
    peer_ip           TEXT,
    peer_port         INTEGER,
    handshake_error   TEXT,
    FOREIGN KEY(session_id) REFERENCES sessions(session_id)
);

CREATE INDEX IF NOT EXISTS tls_by_session ON tls_connections(session_id, started_at DESC);

CREATE TABLE IF NOT EXISTS entries (
    entry_id        TEXT PRIMARY KEY,
    session_id      TEXT NOT NULL,
    tls_conn_id     TEXT,
    h2_conn_id      TEXT,
    h2_stream_id    INTEGER,
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
    req_headers     TEXT NOT NULL,        -- JSON list of [name, value] — order preserved
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
    cluster_id      TEXT,
    FOREIGN KEY(session_id) REFERENCES sessions(session_id),
    FOREIGN KEY(tls_conn_id) REFERENCES tls_connections(connection_id)
);

CREATE INDEX IF NOT EXISTS entries_by_time ON entries(started_at DESC);
CREATE INDEX IF NOT EXISTS entries_by_session ON entries(session_id, started_at DESC);
CREATE INDEX IF NOT EXISTS entries_by_host ON entries(remote_host, started_at DESC);
CREATE INDEX IF NOT EXISTS entries_by_status ON entries(status, started_at DESC);
CREATE INDEX IF NOT EXISTS entries_by_cluster ON entries(cluster_id, started_at DESC);
CREATE INDEX IF NOT EXISTS entries_by_h2 ON entries(h2_conn_id, h2_stream_id);

CREATE TABLE IF NOT EXISTS h2_frames (
    seq           INTEGER PRIMARY KEY AUTOINCREMENT,
    session_id    TEXT NOT NULL,
    h2_conn_id    TEXT NOT NULL,
    ts_ms         INTEGER NOT NULL,
    direction     TEXT NOT NULL,         -- 'inbound' | 'outbound'
    frame_type    TEXT NOT NULL,
    stream_id     INTEGER,
    flags         INTEGER,
    length        INTEGER,
    payload_json  TEXT NOT NULL,
    FOREIGN KEY(session_id) REFERENCES sessions(session_id)
);

CREATE INDEX IF NOT EXISTS h2_frames_by_conn ON h2_frames(h2_conn_id, seq);
CREATE INDEX IF NOT EXISTS h2_frames_by_stream ON h2_frames(h2_conn_id, stream_id, seq);

CREATE TABLE IF NOT EXISTS ws_messages (
    seq          INTEGER PRIMARY KEY AUTOINCREMENT,
    entry_id     TEXT NOT NULL,
    ts_ms        INTEGER NOT NULL,
    direction    TEXT NOT NULL,           -- 'from_client' | 'from_server'
    opcode       TEXT NOT NULL,           -- 'text' | 'binary' | 'close' | 'ping' | 'pong'
    text_payload TEXT,
    bin_payload  BLOB,
    size         INTEGER,
    FOREIGN KEY(entry_id) REFERENCES entries(entry_id)
);

CREATE INDEX IF NOT EXISTS ws_by_entry ON ws_messages(entry_id, seq);

CREATE TABLE IF NOT EXISTS sse_events (
    seq         INTEGER PRIMARY KEY AUTOINCREMENT,
    entry_id    TEXT NOT NULL,
    event_id    TEXT,
    event_type  TEXT,
    data        TEXT NOT NULL,
    retry_ms    INTEGER,
    FOREIGN KEY(entry_id) REFERENCES entries(entry_id)
);

CREATE INDEX IF NOT EXISTS sse_by_entry ON sse_events(entry_id, seq);

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
    conn.execute("PRAGMA foreign_keys=ON")
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
    """Preserve original order AND casing. mitmproxy's multi() iterates in
    wire order and gives raw names."""
    return json.dumps([[k, v] for k, v in headers.items(multi=True)], ensure_ascii=False)


def _cluster_id(method: str, host: str, path: str) -> str:
    """Coarse endpoint grouping — numeric + long-opaque path segments become {id}."""
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


def _tls_version_name(v: Any) -> str | None:
    """mitmproxy exposes TLS version as a string like 'TLSv1.3' or an int."""
    if v is None:
        return None
    if isinstance(v, str):
        return v
    mapping = {0x0304: "TLSv1.3", 0x0303: "TLSv1.2", 0x0302: "TLSv1.1", 0x0301: "TLSv1.0"}
    return mapping.get(int(v), str(v))


def _cert_chain_pem(server_conn: Any) -> str | None:
    """Dump the negotiated server cert chain as JSON list of PEM strings."""
    if not server_conn or not getattr(server_conn, "certificate_list", None):
        return None
    pems: list[str] = []
    for cert in server_conn.certificate_list:
        try:
            pems.append(cert.to_pem().decode("ascii"))
        except Exception:
            continue
    return json.dumps(pems) if pems else None


class Persist:
    def __init__(self) -> None:
        self.conn = _open_db()

        # Session bookkeeping
        self.session_id = os.environ.get("POWHTTP_SESSION_ID") or new_ulid()
        started_ms = int(time.time() * 1000)
        self.conn.execute(
            "INSERT OR IGNORE INTO sessions (session_id, started_at, proxy_port, pid, hostname) "
            "VALUES (?, ?, ?, ?, ?)",
            (
                self.session_id,
                started_ms,
                int(os.environ.get("POWHTTP_PROXY_PORT", "8888")),
                os.getpid(),
                os.uname().nodename if hasattr(os, "uname") else None,
            ),
        )

        # Map from mitmproxy client_conn id → minted TLS connection_id. Filled
        # in `tls_clienthello`, consumed by every downstream hook.
        self._tls_by_client_conn: dict[int, str] = {}
        # Map h2 connection identity (id(H2Connection)) → our connection_id.
        self._h2_conn_ids: dict[int, str] = {}

        # DoH — opt-in via env
        doh.install()

        # hyper-h2 tap — best-effort, never fatal
        result = h2_tap.install(self._record_h2_frame)
        if not result.installed:
            log.warning(f"[powhttp] h2_tap unavailable: {result.reason}")
        else:
            log.info(f"[powhttp] h2_tap: {result.reason}")

        log.info(f"[powhttp] session={self.session_id} db={DB_PATH}")

    # --------------------------------------------------------------- shutdown

    def done(self) -> None:
        try:
            self.conn.execute(
                "UPDATE sessions SET ended_at=? WHERE session_id=?",
                (int(time.time() * 1000), self.session_id),
            )
        except Exception as e:
            log.warning(f"[powhttp] close session failed: {e!r}")

    # ------------------------------------------------------------------- TLS

    def tls_clienthello(self, data: tls.ClientHelloData) -> None:
        """First TLS hook — the client_hello bytes are parsed.

        We mint the connection_id here so every later event on this client
        conn can find the row by lookup.
        """
        try:
            client_conn = data.context.client
            conn_key = id(client_conn)
            connection_id = new_ulid()
            self._tls_by_client_conn[conn_key] = connection_id

            ch = data.client_hello
            legacy = getattr(ch, "legacy_version", 0x0303)
            fp = compute_fingerprint(ch, legacy_version=legacy)
            alpn_offered = json.dumps(
                [
                    p.decode("ascii", errors="replace") if isinstance(p, (bytes, bytearray)) else str(p)
                    for p in (getattr(ch, "alpn_protocols", None) or [])
                ]
            )
            raw = getattr(ch, "raw_bytes", None)
            if callable(raw):
                try:
                    raw = raw()
                except Exception:
                    raw = None

            peer_ip = None
            peer_port = None
            if getattr(client_conn, "peername", None):
                try:
                    peer_ip, peer_port = client_conn.peername[0], int(client_conn.peername[1])
                except Exception:
                    pass

            self.conn.execute(
                """
                INSERT OR REPLACE INTO tls_connections (
                    connection_id, session_id, started_at,
                    sni, alpn_offered, ja3, ja3_hash, ja4,
                    client_hello_raw, peer_ip, peer_port
                ) VALUES (?,?,?, ?,?,?,?,?, ?,?,?)
                """,
                (
                    connection_id, self.session_id, int(time.time() * 1000),
                    getattr(ch, "sni", None), alpn_offered, fp.ja3, fp.ja3_hash, fp.ja4,
                    bytes(raw) if raw else None,
                    peer_ip, peer_port,
                ),
            )
        except Exception as e:
            log.warning(f"[powhttp] tls_clienthello failed: {e!r}")

    def tls_established_client(self, data: tls.TlsData) -> None:
        """Client↔proxy handshake done. Fill negotiated version + cipher."""
        try:
            conn_key = id(data.context.client)
            cid = self._tls_by_client_conn.get(conn_key)
            if not cid:
                return
            c = data.context.client
            self.conn.execute(
                "UPDATE tls_connections SET tls_version=?, cipher_suite=?, alpn_negotiated=?, "
                "client_cert_subject=? WHERE connection_id=?",
                (
                    _tls_version_name(getattr(c, "tls_version", None)),
                    getattr(c, "cipher", None),
                    (c.alpn or b"").decode(errors="replace") if getattr(c, "alpn", None) else None,
                    self._client_cert_subject(c),
                    cid,
                ),
            )
        except Exception as e:
            log.warning(f"[powhttp] tls_established_client failed: {e!r}")

    def tls_established_server(self, data: tls.TlsData) -> None:
        """Proxy↔upstream handshake done. Record the server cert chain."""
        try:
            conn_key = id(data.context.client)
            cid = self._tls_by_client_conn.get(conn_key)
            if not cid:
                return
            s = data.context.server
            chain = _cert_chain_pem(s)
            if chain is not None:
                self.conn.execute(
                    "UPDATE tls_connections SET server_cert_chain=? WHERE connection_id=?",
                    (chain, cid),
                )
        except Exception as e:
            log.warning(f"[powhttp] tls_established_server failed: {e!r}")

    def tls_failed_client(self, data: tls.TlsData) -> None:
        self._record_tls_error(data, "client")

    def tls_failed_server(self, data: tls.TlsData) -> None:
        self._record_tls_error(data, "server")

    def _record_tls_error(self, data: tls.TlsData, side: str) -> None:
        try:
            conn_key = id(data.context.client)
            cid = self._tls_by_client_conn.get(conn_key)
            if not cid:
                return
            msg = f"{side}: {getattr(data, 'conn', None) and getattr(data.conn, 'error', None)}"
            self.conn.execute(
                "UPDATE tls_connections SET handshake_error=? WHERE connection_id=?",
                (msg, cid),
            )
        except Exception as e:
            log.warning(f"[powhttp] tls_failed_{side} failed: {e!r}")

    @staticmethod
    def _client_cert_subject(c: Any) -> str | None:
        cert = getattr(c, "mitmcert", None) or getattr(c, "certificate", None)
        if cert is None:
            return None
        try:
            subj = getattr(cert, "subject", None)
            if subj is None:
                return None
            return ", ".join(f"{rdn.rfc4514_string()}" for rdn in subj) if hasattr(subj, "__iter__") else str(subj)
        except Exception:
            return None

    # -------------------------------------------------------------- HTTP/2

    def _record_h2_frame(self, *, conn_key: int, direction: str, frame_type: str,
                         stream_id: int | None, flags: int, length: int,
                         payload: dict[str, Any]) -> None:
        """Sink callback for h2_tap. Mints a stable conn id lazily."""
        try:
            h2_id = self._h2_conn_ids.get(conn_key)
            if h2_id is None:
                h2_id = new_ulid()
                self._h2_conn_ids[conn_key] = h2_id
            self.conn.execute(
                "INSERT INTO h2_frames (session_id, h2_conn_id, ts_ms, direction, "
                "frame_type, stream_id, flags, length, payload_json) "
                "VALUES (?,?,?,?,?,?,?,?,?)",
                (
                    self.session_id, h2_id, int(time.time() * 1000),
                    direction, frame_type, stream_id, int(flags or 0), int(length or 0),
                    json.dumps(payload, default=str),
                ),
            )
        except Exception as e:
            log.debug(f"[powhttp] h2 frame persist failed: {e!r}")

    # --------------------------------------------------------------- WebSocket

    def websocket_message(self, flow: http.HTTPFlow) -> None:
        """Called once per WS frame (both directions). Last message is in
        flow.websocket.messages[-1]."""
        try:
            if not flow.websocket or not flow.websocket.messages:
                return
            msg = flow.websocket.messages[-1]
            entry_id = flow.metadata.get("powhttp_entry_id")
            if not entry_id:
                # Upgrade response hasn't been persisted yet — stash and flush later.
                flow.metadata.setdefault("_ws_pending", []).append(msg)
                return
            self._insert_ws_message(entry_id, msg)
        except Exception as e:
            log.warning(f"[powhttp] websocket_message failed: {e!r}")

    def _insert_ws_message(self, entry_id: str, msg: Any) -> None:
        is_text = bool(getattr(msg, "is_text", False))
        content = getattr(msg, "content", b"") or b""
        direction = "from_client" if getattr(msg, "from_client", False) else "from_server"
        ts = int((getattr(msg, "timestamp", None) or time.time()) * 1000)
        opcode = "text" if is_text else "binary"
        text_payload = None
        bin_payload: bytes | None = None
        if is_text:
            try:
                text_payload = content.decode("utf-8", errors="replace")
            except Exception:
                bin_payload = bytes(content)
        else:
            bin_payload = bytes(content)
        self.conn.execute(
            "INSERT INTO ws_messages (entry_id, ts_ms, direction, opcode, "
            "text_payload, bin_payload, size) VALUES (?,?,?,?,?,?,?)",
            (entry_id, ts, direction, opcode, text_payload, bin_payload, len(content)),
        )

    # ------------------------------------------------- streaming response hook

    def responseheaders(self, flow: http.HTTPFlow) -> None:
        """Fires when response headers land, before the body streams in.

        For text/event-stream we can't rely on the later `response` hook —
        SSE streams never complete, so mitmproxy either buffers forever (if
        streaming is off) or skips the `response` hook entirely (if on).
        So we mint an entry_id *now*, insert a stub row so sse_events can
        FK to it, and install a tee that parses complete events and inserts
        them as they arrive.
        """
        if flow.response is None:
            return
        ct = (flow.response.headers.get("content-type") or "").lower()
        # Diagnostic: prove the hook fires and show what we decided. `print`
        # (not log) so it lands on mitmproxy stderr → /state/mitmproxy.log.
        print(
            f"[powhttp] responseheaders {flow.request.pretty_url} ct={ct!r}",
            file=sys.stderr,
        )
        if "text/event-stream" not in ct:
            return

        # Early-mint the entry row so inline SSE parsing has a row to point at.
        entry_id = new_ulid()
        flow.metadata["powhttp_entry_id"] = entry_id
        self._insert_entry_stub(flow, entry_id)
        print(f"[powhttp] SSE detected → entry_id={entry_id}, streaming on", file=sys.stderr)

        pending = bytearray()

        def _tee(chunk: bytes) -> bytes:
            # Called once per chunk on mitmproxy's asyncio thread. Accumulate,
            # carve off complete \n\n- or \r\n\r\n-delimited events, and
            # insert each one as an sse_events row.
            print(f"[powhttp] SSE tee: {len(chunk)} bytes for {entry_id}", file=sys.stderr)
            try:
                pending.extend(chunk)
                while True:
                    data = bytes(pending)
                    idx = data.find(b"\n\n")
                    sep_len = 2
                    r_idx = data.find(b"\r\n\r\n")
                    if r_idx >= 0 and (idx < 0 or r_idx < idx):
                        idx, sep_len = r_idx, 4
                    if idx < 0:
                        break
                    event_bytes = data[:idx]
                    del pending[: idx + sep_len]
                    try:
                        event_text = event_bytes.decode("utf-8", errors="replace")
                    except Exception:
                        continue
                    self._insert_sse_event(entry_id, event_text)
            except Exception as e:
                log.debug(f"[powhttp] sse tee error: {e!r}")
            return chunk

        # mitmproxy: assigning .stream to a callable enables streaming AND
        # routes each chunk through the callable. True alone just bypasses
        # buffering.
        flow.response.stream = _tee

    # --------------------------------------------------------- HTTP response

    def response(self, flow: http.HTTPFlow) -> None:
        self._record(flow)

    def error(self, flow: http.HTTPFlow) -> None:
        self._record(flow, error=str(flow.error) if flow.error else "unknown")

    def _insert_entry_stub(self, flow: http.HTTPFlow, entry_id: str) -> None:
        """Insert a partial entries row. Used by responseheaders() for SSE
        flows where the full response never completes. Only the NOT NULL
        columns and whatever we have at header-time get filled; status /
        resp_headers / resp_body_* stay null."""
        req = flow.request
        host = req.pretty_host
        port = req.port
        method = req.method
        url = req.pretty_url
        path = req.path or "/"
        scheme = req.scheme
        started_ms = int(flow.timestamp_created * 1000)

        tls_conn_id = None
        if flow.client_conn:
            tls_conn_id = self._tls_by_client_conn.get(id(flow.client_conn))

        sni = None
        alpn = None
        remote_ip = None
        if flow.server_conn:
            if flow.server_conn.tls_established:
                alpn = (flow.server_conn.alpn or b"").decode(errors="replace") or None
                sni = flow.server_conn.sni
            if flow.server_conn.peername:
                remote_ip = flow.server_conn.peername[0]

        http_version = None
        if flow.response is not None and flow.response.http_version:
            http_version = flow.response.http_version
        elif req.http_version:
            http_version = req.http_version

        content_type = None
        if flow.response is not None:
            content_type = flow.response.headers.get("content-type")

        self.conn.execute(
            """
            INSERT OR IGNORE INTO entries (
                entry_id, session_id, tls_conn_id,
                started_at, remote_host, remote_port, remote_ip,
                sni, alpn, http_version,
                method, url, scheme, path,
                req_headers, content_type, cluster_id
            ) VALUES (?,?,?, ?,?,?,?, ?,?,?, ?,?,?,?, ?,?,?)
            """,
            (
                entry_id, self.session_id, tls_conn_id,
                started_ms, host, port, remote_ip,
                sni, alpn, http_version,
                method, url, scheme, path,
                _headers_to_json(req.headers), content_type,
                _cluster_id(method, host, path),
            ),
        )

    def _record(self, flow: http.HTTPFlow, error: str | None = None) -> None:
        # Responseheaders may have already inserted a stub for this flow (SSE
        # streaming path). If so, don't re-insert or re-parse — sse_events
        # rows were appended inline from the tee.
        if flow.metadata.get("powhttp_entry_id"):
            return
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
            tls_conn_id = None
            remote_ip = None
            if flow.client_conn:
                tls_conn_id = self._tls_by_client_conn.get(id(flow.client_conn))
            if flow.server_conn:
                if flow.server_conn.tls_established:
                    alpn = (flow.server_conn.alpn or b"").decode(errors="replace") or None
                    sni = flow.server_conn.sni
                if flow.server_conn.peername:
                    remote_ip = flow.server_conn.peername[0]

            http_version = None
            if resp is not None and resp.http_version:
                http_version = resp.http_version
            elif req.http_version:
                http_version = req.http_version

            # HTTP/2 cross-reference. mitmproxy exposes per-flow stream_id
            # via flow.metadata on h2 flows.
            h2_conn_id = None
            h2_stream_id = None
            if http_version and "2" in http_version:
                h2_stream_id = flow.metadata.get("h2-stream-id") or flow.metadata.get("stream_id")
                # Our tap keyed conns by id(H2Connection); mitmproxy doesn't
                # expose that object on the flow. Best we can do is attach the
                # session's most-recent h2 conn when there's exactly one.
                if len(self._h2_conn_ids) == 1:
                    h2_conn_id = next(iter(self._h2_conn_ids.values()))

            entry_id = new_ulid()
            flow.metadata["powhttp_entry_id"] = entry_id
            cid = _cluster_id(method, host, path)

            self.conn.execute(
                """
                INSERT INTO entries (
                    entry_id, session_id, tls_conn_id, h2_conn_id, h2_stream_id,
                    started_at, ended_at,
                    remote_host, remote_port, remote_ip,
                    sni, alpn, http_version,
                    method, url, scheme, path,
                    req_headers, req_body_inline, req_body_ref, req_body_size,
                    status, resp_headers, resp_body_inline, resp_body_ref, resp_body_size,
                    content_type, error, cluster_id
                ) VALUES (?,?,?,?,?, ?,?, ?,?,?, ?,?,?, ?,?,?,?, ?,?,?,?, ?,?,?,?,?, ?,?,?)
                """,
                (
                    entry_id, self.session_id, tls_conn_id, h2_conn_id,
                    int(h2_stream_id) if h2_stream_id is not None else None,
                    started_ms, ended_ms,
                    host, port, remote_ip,
                    sni, alpn, http_version,
                    method, url, scheme, path,
                    _headers_to_json(req.headers), req_inline, req_ref, req_size,
                    status, resp_headers_json, resp_inline, resp_ref, resp_size,
                    content_type, error, cid,
                ),
            )

            self._index_fts(entry_id, url, req.raw_content, resp.raw_content if resp else None, content_type)

            # SSE — if a response is non-streamed (short / bounded) and arrived
            # here with a text/event-stream body, batch-parse it. Streamed SSE
            # goes through responseheaders() → tee instead and never reaches
            # this branch (the early-return at the top of _record skips it).
            if resp is not None and content_type and "text/event-stream" in content_type.lower():
                self._record_sse(entry_id, resp.raw_content or b"")

            # Flush any WS frames that arrived before the upgrade response was persisted.
            pending = flow.metadata.pop("_ws_pending", None)
            if pending:
                for msg in pending:
                    self._insert_ws_message(entry_id, msg)
        except Exception as e:
            log.warning(f"[powhttp] persist failed: {e!r}")

    # ------------------------------------------------------------------ SSE

    def _insert_sse_event(self, entry_id: str, event_text: str) -> None:
        """Parse one SSE event block (fields separated by single newlines)
        and insert it. Spec: https://html.spec.whatwg.org/#event-stream."""
        event_text = event_text.strip("\r\n")
        if not event_text:
            return
        event_id = None
        event_type = None
        retry = None
        data_lines: list[str] = []
        for line in event_text.split("\n"):
            line = line.rstrip("\r")
            if not line or line.startswith(":"):
                continue
            if ":" in line:
                field, _, value = line.partition(":")
                value = value[1:] if value.startswith(" ") else value
            else:
                field, value = line, ""
            if field == "id":
                event_id = value
            elif field == "event":
                event_type = value
            elif field == "retry":
                try:
                    retry = int(value)
                except ValueError:
                    pass
            elif field == "data":
                data_lines.append(value)
        if data_lines or event_type or event_id:
            self.conn.execute(
                "INSERT INTO sse_events (entry_id, event_id, event_type, data, retry_ms) "
                "VALUES (?,?,?,?,?)",
                (entry_id, event_id, event_type, "\n".join(data_lines), retry),
            )

    def _record_sse(self, entry_id: str, body: bytes) -> None:
        """Batch-parse a full SSE body (used when a non-streamed response
        completes with text/event-stream content)."""
        try:
            text = body.decode("utf-8", errors="replace")
        except Exception:
            return
        for raw_event in re.split(r"\r?\n\r?\n", text):
            self._insert_sse_event(entry_id, raw_event)

    # ------------------------------------------------------------------ FTS

    def _index_fts(self, entry_id: str, url: str, req_body: bytes | None,
                   resp_body: bytes | None, content_type: str | None) -> None:
        def text_of(blob: bytes | None) -> str:
            if not blob:
                return ""
            if len(blob) > 512 * 1024:   # don't FTS huge bodies
                return ""
            try:
                return blob.decode("utf-8", errors="ignore")
            except Exception:
                return ""
        row = self.conn.execute("SELECT rowid FROM entries WHERE entry_id=?", (entry_id,)).fetchone()
        if not row:
            return
        self.conn.execute(
            "INSERT INTO entries_fts(rowid, url, req_body, resp_body) VALUES (?,?,?,?)",
            (row[0], url, text_of(req_body), text_of(resp_body)),
        )


addons = [Persist()]
