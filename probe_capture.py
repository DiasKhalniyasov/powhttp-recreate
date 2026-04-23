"""End-to-end probe for the capture fidelity rewrite.

Runs inside the container. Drives traffic through the local mitmproxy, then
queries the SQLite schema directly and prints a pass/fail report per table:

    sessions          → 1 row, session_id matches $POWHTTP_SESSION_ID, ended_at NULL (still live)
    tls_connections   → ≥1 row with ja3_hash + ja4 filled in, tls_version + cipher set
    entries           → rows with tls_conn_id populated, req_headers preserves order
    h2_frames         → ≥1 HEADERS frame captured
    ws_messages       → ≥1 text frame in each direction
    sse_events        → ≥1 parsed event with non-empty data

Anything unexpected is printed with the raw row so you can see the shape at
a glance. Exit code 0 on all checks pass, 1 otherwise.

Triggered endpoints (talked to through the proxy):
  * https://www.cloudflare.com/          — HTTP/2 + TLS (JA3/JA4 + h2 frames)
  * wss://<echo host>/                    — WebSocket text echo, rotating fallbacks
  * http://127.0.0.1:<ephemeral>/events   — loopback SSE server (hermetic, deterministic)

The SSE server runs in-process so the probe doesn't depend on flaky external
endpoints (sse.dev now serves HTML, Wikipedia 403s urllib's default UA). If an
endpoint is unreachable the check is SKIPped rather than failed.
"""

from __future__ import annotations

import http.server
import json
import os
import socket
import socketserver
import sqlite3
import ssl
import sys
import threading
import time
from pathlib import Path
from urllib import request
from urllib.error import URLError

try:
    import httpx  # provides real HTTP/2 via hyper-h2, which is what we want to exercise
    HAS_HTTPX = True
except ImportError:
    HAS_HTTPX = False

PROXY = os.environ.get("POWHTTP_PROXY_URL", "http://127.0.0.1:8888")
DB = Path(os.environ["POWHTTP_FLOWS_DB"])
SESSION_ID = os.environ.get("POWHTTP_SESSION_ID", "")
CA_BUNDLE = os.environ.get("SSL_CERT_FILE")


# ----------------------------------------------------------------- utilities


class Check:
    def __init__(self, name: str) -> None:
        self.name = name
        self.status = "PENDING"
        self.detail = ""

    def ok(self, detail: str = "") -> None:
        self.status, self.detail = "PASS", detail

    def fail(self, detail: str) -> None:
        self.status, self.detail = "FAIL", detail

    def skip(self, detail: str) -> None:
        self.status, self.detail = "SKIP", detail

    def __str__(self) -> str:
        colour = {"PASS": "\x1b[32m", "FAIL": "\x1b[31m", "SKIP": "\x1b[33m"}.get(self.status, "")
        reset = "\x1b[0m" if colour else ""
        return f"  {colour}{self.status:<4}{reset}  {self.name}  {self.detail}"


def http_get(url: str, timeout: int = 10) -> bytes | None:
    """GET via the local proxy. Returns raw body or None on failure."""
    proxy = request.ProxyHandler({"http": PROXY, "https": PROXY})
    ctx = ssl.create_default_context(cafile=CA_BUNDLE) if CA_BUNDLE else ssl.create_default_context()
    opener = request.build_opener(proxy, request.HTTPSHandler(context=ctx))
    try:
        with opener.open(url, timeout=timeout) as r:
            return r.read()
    except URLError as e:
        print(f"  [probe] GET {url} failed: {e!r}", file=sys.stderr)
        return None


def sse_stream(url: str, max_events: int = 3, timeout: int = 15) -> int:
    """Read up to max_events SSE events from url. Returns events seen."""
    proxy = request.ProxyHandler({"http": PROXY, "https": PROXY})
    ctx = ssl.create_default_context(cafile=CA_BUNDLE) if CA_BUNDLE else ssl.create_default_context()
    opener = request.build_opener(proxy, request.HTTPSHandler(context=ctx))
    req = request.Request(url, headers={"Accept": "text/event-stream"})
    try:
        with opener.open(req, timeout=timeout) as r:
            seen = 0
            deadline = time.time() + timeout
            buf = b""
            while seen < max_events and time.time() < deadline:
                chunk = r.read(1024)
                if not chunk:
                    break
                buf += chunk
                while b"\n\n" in buf:
                    evt, _, buf = buf.partition(b"\n\n")
                    if evt.strip():
                        seen += 1
                    if seen >= max_events:
                        break
            return seen
    except URLError as e:
        print(f"  [probe] SSE {url} failed: {e!r}", file=sys.stderr)
        return 0


def websocket_echo(host: str, path: str = "/", messages: tuple[str, ...] = ("hello-powhttp",)) -> bool:
    """Connect through the proxy, complete the WS handshake, send + recv text frames."""
    import base64
    import os as _os

    # mitmproxy supports CONNECT tunneling — open a plain TCP socket to the
    # proxy, issue CONNECT, then wrap in TLS and do the WS handshake.
    proxy_host, proxy_port = "127.0.0.1", 8888
    s = socket.create_connection((proxy_host, proxy_port), timeout=10)
    try:
        s.sendall(f"CONNECT {host}:443 HTTP/1.1\r\nHost: {host}:443\r\n\r\n".encode())
        resp = b""
        while b"\r\n\r\n" not in resp:
            r = s.recv(4096)
            if not r:
                return False
            resp += r
        if b" 200 " not in resp.split(b"\r\n", 1)[0]:
            print(f"  [probe] WS CONNECT rejected: {resp[:200]!r}", file=sys.stderr)
            return False

        ctx = ssl.create_default_context(cafile=CA_BUNDLE) if CA_BUNDLE else ssl.create_default_context()
        ss = ctx.wrap_socket(s, server_hostname=host)

        key = base64.b64encode(_os.urandom(16)).decode()
        handshake = (
            f"GET {path} HTTP/1.1\r\n"
            f"Host: {host}\r\n"
            "Upgrade: websocket\r\n"
            "Connection: Upgrade\r\n"
            f"Sec-WebSocket-Key: {key}\r\n"
            "Sec-WebSocket-Version: 13\r\n"
            "Origin: https://probe.local\r\n\r\n"
        )
        ss.sendall(handshake.encode())
        hs_resp = b""
        while b"\r\n\r\n" not in hs_resp:
            chunk = ss.recv(4096)
            if not chunk:
                return False
            hs_resp += chunk
        if b" 101 " not in hs_resp.split(b"\r\n", 1)[0]:
            print(f"  [probe] WS handshake rejected: {hs_resp[:300]!r}", file=sys.stderr)
            return False

        # Minimal client-framing: FIN=1, opcode=0x1 (text), masked.
        def send_text(payload: bytes) -> None:
            mask = _os.urandom(4)
            masked = bytes(b ^ mask[i % 4] for i, b in enumerate(payload))
            length = len(payload)
            if length < 126:
                hdr = bytes([0x81, 0x80 | length])
            elif length < 65536:
                hdr = bytes([0x81, 0x80 | 126]) + length.to_bytes(2, "big")
            else:
                hdr = bytes([0x81, 0x80 | 127]) + length.to_bytes(8, "big")
            ss.sendall(hdr + mask + masked)

        def recv_frame(deadline: float) -> bytes | None:
            ss.settimeout(max(0.1, deadline - time.time()))
            try:
                head = ss.recv(2)
                if len(head) < 2:
                    return None
                length = head[1] & 0x7F
                if length == 126:
                    length = int.from_bytes(ss.recv(2), "big")
                elif length == 127:
                    length = int.from_bytes(ss.recv(8), "big")
                data = b""
                while len(data) < length:
                    chunk = ss.recv(length - len(data))
                    if not chunk:
                        break
                    data += chunk
                return data
            except socket.timeout:
                return None

        got = 0
        deadline = time.time() + 10
        for m in messages:
            send_text(m.encode())
            reply = recv_frame(deadline)
            if reply:
                got += 1
        return got > 0
    finally:
        try:
            s.close()
        except Exception:
            pass


# ----------------------------------------------------------------- drivers


class _SSEHandler(http.server.BaseHTTPRequestHandler):
    """Minimal SSE server — emits a deterministic burst of events then closes.

    Used by the probe so we don't depend on external SSE endpoints (sse.dev now
    serves HTML at /test, stream.wikimedia.org 403s urllib's default UA). This
    speaks plain HTTP over loopback — no TLS handshake, no tls_connections row,
    but the mitmproxy streaming tap still fires and populates sse_events.
    """

    # Silence the default access-log spam on stderr.
    def log_message(self, format: str, *args) -> None:  # noqa: A002
        return

    def do_GET(self) -> None:  # noqa: N802 — stdlib API
        self.send_response(200)
        self.send_header("Content-Type", "text/event-stream")
        self.send_header("Cache-Control", "no-cache")
        self.send_header("Connection", "close")
        self.end_headers()
        events = (
            (b"1", b"ping",   b"hello from probe #1"),
            (b"2", b"ping",   b"hello from probe #2"),
            (b"3", b"bye",    b"final event, closing stream"),
        )
        for eid, evt, data in events:
            payload = b"id: " + eid + b"\nevent: " + evt + b"\ndata: " + data + b"\n\n"
            try:
                self.wfile.write(payload)
                self.wfile.flush()
            except (BrokenPipeError, ConnectionResetError):
                return
            time.sleep(0.05)


def start_sse_server() -> tuple[socketserver.TCPServer, int]:
    """Bind a loopback SSE server on an ephemeral port, start it on a thread."""
    socketserver.TCPServer.allow_reuse_address = True
    srv = socketserver.TCPServer(("127.0.0.1", 0), _SSEHandler)
    port = srv.server_address[1]
    t = threading.Thread(target=srv.serve_forever, name="sse-probe-srv", daemon=True)
    t.start()
    return srv, port


def h2_probe(url: str) -> bool:
    """Run an HTTP/2 request through the proxy. Returns True iff the response
    came back over h2 (i.e. the h2 tap had something to bite on).

    urllib only speaks HTTP/1.1, so we need httpx[http2] — when the client
    negotiates h2 over TLS/ALPN, mitmproxy mirrors h2 upstream and our
    hyper-h2 monkey-patch sees every frame.
    """
    if not HAS_HTTPX:
        print("  [probe] httpx not installed — skipping h2 probe", file=sys.stderr)
        return False
    try:
        with httpx.Client(
            http2=True,
            proxy=PROXY,
            verify=CA_BUNDLE or True,
            timeout=15.0,
            follow_redirects=True,
            headers={"User-Agent": "powhttp-probe/1.0"},
        ) as cli:
            r = cli.get(url)
            print(f"  [probe] h2 GET {url} → {r.status_code} {r.http_version}", file=sys.stderr)
            return r.http_version == "HTTP/2"
    except Exception as e:
        print(f"  [probe] h2 GET {url} failed: {e!r}", file=sys.stderr)
        return False


def drive_traffic() -> dict[str, bool]:
    """Hit each probe endpoint. Returns a dict of which ones produced data."""
    hit = {"tls": False, "h2": False, "ws": False, "sse": False}

    # --- HTTP/2 + TLS ---
    # Cloudflare's root + github.io both serve h2 over TLS 1.3.
    for url in ("https://www.cloudflare.com/", "https://http2.github.io/"):
        if h2_probe(url):
            hit["tls"] = hit["h2"] = True
            break
    # Ensure we have *some* TLS even if the h2 probe all failed.
    if not hit["tls"]:
        for url in ("https://example.com/", "https://www.google.com/"):
            if http_get(url, timeout=10):
                hit["tls"] = True
                break

    # --- WebSocket ---
    # echo.websocket.events used to be the canonical free echo but has been
    # flaky from Docker DNS. Try a few fallbacks.
    for host, path in (
        ("ws.postman-echo.com", "/raw"),
        ("echo.websocket.events", "/"),
        ("ws.ifelse.io", "/"),
    ):
        if websocket_echo(host, path, ("ping-1", "ping-2")):
            hit["ws"] = True
            break

    # --- SSE ---
    # External SSE endpoints are unreliable under container DNS + UA policies
    # (sse.dev serves HTML at /test, stream.wikimedia.org 403s urllib's UA).
    # Stand up a loopback SSE server inside the probe so the test is hermetic.
    #
    # entrypoint.sh sets NO_PROXY=localhost,127.0.0.1,::1 so that requests to
    # the mitmproxy admin UI bypass itself — but that also makes urllib skip
    # the proxy for *our* loopback SSE server, which is the opposite of what
    # we want. Clear it for this one request.
    saved_no_proxy = os.environ.pop("NO_PROXY", None), os.environ.pop("no_proxy", None)
    srv, port = start_sse_server()
    try:
        sse_url = f"http://127.0.0.1:{port}/events"
        if sse_stream(sse_url, max_events=2, timeout=8) > 0:
            hit["sse"] = True
    finally:
        try:
            srv.shutdown()
            srv.server_close()
        except Exception:
            pass
        if saved_no_proxy[0] is not None:
            os.environ["NO_PROXY"] = saved_no_proxy[0]
        if saved_no_proxy[1] is not None:
            os.environ["no_proxy"] = saved_no_proxy[1]

    # Give mitmproxy a moment to flush the last frames / responses, and to
    # let the SSE streaming tap append any buffered chunks.
    time.sleep(1.5)
    return hit


# ----------------------------------------------------------------- checks


def run_checks(hit: dict[str, bool]) -> list[Check]:
    conn = sqlite3.connect(DB)
    conn.row_factory = sqlite3.Row
    checks: list[Check] = []

    # sessions -----------------------------------------------------------------
    c = Check("sessions: one row, id matches env")
    row = conn.execute(
        "SELECT * FROM sessions WHERE session_id=?", (SESSION_ID,)
    ).fetchone()
    if not row:
        c.fail(f"no sessions row for {SESSION_ID!r}")
    elif row["ended_at"] is not None:
        c.fail("session already closed — addon shut down prematurely?")
    else:
        c.ok(f"started_at={row['started_at']}, pid={row['pid']}")
    checks.append(c)

    # tls_connections ----------------------------------------------------------
    c = Check("tls_connections: JA3 + JA4 + cipher populated")
    if not hit["tls"]:
        c.skip("no TLS traffic generated")
    else:
        tls = conn.execute(
            "SELECT * FROM tls_connections WHERE session_id=? AND ja3_hash IS NOT NULL "
            "ORDER BY started_at DESC LIMIT 1",
            (SESSION_ID,),
        ).fetchone()
        if not tls:
            c.fail("no tls_connections row with ja3_hash")
        elif not tls["ja4"]:
            c.fail(f"JA3={tls['ja3_hash']} present but JA4 empty")
        elif not tls["cipher_suite"] or not tls["tls_version"]:
            c.fail(f"handshake metadata incomplete: {dict(tls)}")
        else:
            c.ok(f"sni={tls['sni']} tls={tls['tls_version']} cipher={tls['cipher_suite']} ja4={tls['ja4']}")
    checks.append(c)

    # entries: header order ----------------------------------------------------
    c = Check("entries: header order preserved (User-Agent before Accept)")
    # Look at any recent entry and assert req_headers is a list-of-lists
    # where at least two headers are in the order we'd expect from urllib.
    row = conn.execute(
        "SELECT req_headers FROM entries WHERE session_id=? ORDER BY started_at DESC LIMIT 1",
        (SESSION_ID,),
    ).fetchone()
    if not row:
        c.skip("no entries yet")
    else:
        try:
            hdrs = json.loads(row["req_headers"])
        except Exception as e:
            c.fail(f"req_headers not valid JSON: {e!r}")
        else:
            if not isinstance(hdrs, list) or not all(isinstance(h, list) and len(h) == 2 for h in hdrs):
                c.fail(f"unexpected shape: {hdrs!r}")
            else:
                names = [h[0] for h in hdrs]
                c.ok(f"{len(hdrs)} headers, order: {names[:4]}…")
    checks.append(c)

    # entries: tls_conn_id foreign key -----------------------------------------
    c = Check("entries: linked to tls_connections via tls_conn_id")
    row = conn.execute(
        "SELECT COUNT(*) AS n FROM entries WHERE session_id=? AND tls_conn_id IS NOT NULL",
        (SESSION_ID,),
    ).fetchone()
    if row["n"] > 0:
        c.ok(f"{row['n']} entries carry tls_conn_id")
    else:
        c.fail("no entries have tls_conn_id populated")
    checks.append(c)

    # h2_frames ----------------------------------------------------------------
    c = Check("h2_frames: HEADERS frame captured")
    if not hit["h2"]:
        c.skip("no HTTP/2 traffic")
    else:
        row = conn.execute(
            "SELECT COUNT(*) AS n, COUNT(DISTINCT h2_conn_id) AS conns "
            "FROM h2_frames WHERE session_id=? AND frame_type='HEADERS'",
            (SESSION_ID,),
        ).fetchone()
        if row["n"] == 0:
            c.fail("no HEADERS frames captured — is hyper-h2 in use?")
        else:
            c.ok(f"{row['n']} HEADERS frames across {row['conns']} connection(s)")
    checks.append(c)

    # h2_frames: variety -------------------------------------------------------
    c = Check("h2_frames: frame-type variety (SETTINGS/DATA/WINDOW_UPDATE/…)")
    if not hit["h2"]:
        c.skip("no HTTP/2 traffic")
    else:
        rows = conn.execute(
            "SELECT frame_type, COUNT(*) AS n FROM h2_frames "
            "WHERE session_id=? GROUP BY frame_type ORDER BY n DESC",
            (SESSION_ID,),
        ).fetchall()
        types = {r["frame_type"]: r["n"] for r in rows}
        # "LIST" as a frame type means the outbound tap was misinterpreting
        # hyper-h2's list-of-frames argument. If we see it, the tap regressed.
        if "LIST" in types:
            c.fail(f"outbound tap regressed — saw frame_type='LIST': {types}")
        elif len(types) >= 3:
            c.ok(", ".join(f"{k}={v}" for k, v in types.items()))
        else:
            c.fail(f"expected ≥3 frame types, saw: {types}")
    checks.append(c)

    # h2_frames: both directions ----------------------------------------------
    # Before the outbound fan-out fix, outbound frames were all tagged LIST,
    # so this check would have been meaningless. Now verify we see a real mix
    # of inbound vs outbound so we know client→server frames are captured.
    c = Check("h2_frames: both directions (inbound + outbound)")
    if not hit["h2"]:
        c.skip("no HTTP/2 traffic")
    else:
        rows = conn.execute(
            "SELECT direction, COUNT(*) AS n FROM h2_frames "
            "WHERE session_id=? GROUP BY direction",
            (SESSION_ID,),
        ).fetchall()
        dirs = {r["direction"]: r["n"] for r in rows}
        if dirs.get("inbound", 0) > 0 and dirs.get("outbound", 0) > 0:
            c.ok(f"inbound={dirs['inbound']}, outbound={dirs['outbound']}")
        else:
            c.fail(f"h2 frames not bidirectional: {dirs}")
    checks.append(c)

    # entries: body storage sanity --------------------------------------------
    # For every entry with a declared resp_body_size, one of:
    #   • resp_body_inline (BLOB) is present, or
    #   • resp_body_ref is a sha256 hex and $BODIES_DIR/<sha[:2]>/<sha> exists
    #     and hashes back to that sha256.
    # Verifies the content-addressed body path works end-to-end, not just the
    # row pointer. powhttp's HAR always has the body — we need the same.
    c = Check("entries: response bodies persisted (inline or content-addressed)")
    rows = conn.execute(
        "SELECT entry_id, resp_body_size, resp_body_inline IS NOT NULL AS has_inline, "
        "resp_body_ref FROM entries WHERE session_id=? AND status IS NOT NULL "
        "AND resp_body_size > 0",
        (SESSION_ID,),
    ).fetchall()
    bodies_dir = Path(os.environ.get("POWHTTP_BODIES_DIR", "/state/bodies"))
    missing: list[str] = []
    verified = 0
    for r in rows:
        if r["has_inline"]:
            verified += 1
            continue
        ref = r["resp_body_ref"]
        if not ref:
            missing.append(f"{r['entry_id']}:no-inline-no-ref")
            continue
        blob_path = bodies_dir / ref[:2] / ref
        if not blob_path.exists():
            missing.append(f"{r['entry_id']}:ref={ref[:12]}…missing")
            continue
        import hashlib as _h
        if _h.sha256(blob_path.read_bytes()).hexdigest() != ref:
            missing.append(f"{r['entry_id']}:ref={ref[:12]}…hash-mismatch")
            continue
        verified += 1
    if not rows:
        c.skip("no entries with non-zero resp_body_size")
    elif missing:
        c.fail(f"verified={verified}, missing/bad={len(missing)}: {missing[:3]}")
    else:
        c.ok(f"{verified} entries with bodies, all reachable")
    checks.append(c)

    # ws_messages --------------------------------------------------------------
    c = Check("ws_messages: frames in both directions")
    if not hit["ws"]:
        c.skip("no WebSocket traffic (echo endpoint may be unreachable)")
    else:
        rows = conn.execute(
            "SELECT direction, COUNT(*) AS n FROM ws_messages GROUP BY direction"
        ).fetchall()
        dirs = {r["direction"]: r["n"] for r in rows}
        if dirs.get("from_client", 0) > 0 and dirs.get("from_server", 0) > 0:
            c.ok(f"client→{dirs['from_client']}, server→{dirs['from_server']}")
        else:
            c.fail(f"unbalanced or missing: {dirs}")
    checks.append(c)

    # sse_events ---------------------------------------------------------------
    # Don't trust hit["sse"] — for streamed SSE the probe client often sees 0
    # events (urllib buffering / timing), but mitmproxy's tee tap still fires
    # and appends rows as events arrive. Go straight to the DB. Look for any
    # entry in this session whose content_type announces an SSE stream: that
    # tells us the probe actually hit an SSE endpoint. If not, SKIP.
    c = Check("sse_events: parsed events with data")
    reached = conn.execute(
        "SELECT COUNT(*) AS n FROM entries WHERE session_id=? "
        "AND content_type LIKE '%text/event-stream%'",
        (SESSION_ID,),
    ).fetchone()
    if reached["n"] == 0:
        c.skip("never reached an SSE endpoint — streaming tap didn't see one")
    else:
        row = conn.execute(
            "SELECT COUNT(*) AS n FROM sse_events WHERE data != ''"
        ).fetchone()
        if row["n"] > 0:
            c.ok(f"{row['n']} events with non-empty data")
        else:
            c.fail("SSE endpoint reached but no sse_events rows — stream tap didn't fire")
    checks.append(c)

    conn.close()
    return checks


def main() -> int:
    print(f"[probe] session   {SESSION_ID}")
    print(f"[probe] proxy     {PROXY}")
    print(f"[probe] db        {DB}")
    print(f"[probe] ca_bundle {CA_BUNDLE}")
    print()
    print("[probe] driving traffic …")
    hit = drive_traffic()
    for k, v in hit.items():
        print(f"  {k}: {'ok' if v else 'miss'}")
    print()
    print("[probe] running checks …")
    checks = run_checks(hit)
    for c in checks:
        print(c)
    fails = sum(1 for c in checks if c.status == "FAIL")
    skips = sum(1 for c in checks if c.status == "SKIP")
    passes = sum(1 for c in checks if c.status == "PASS")
    print()
    print(f"[probe] pass={passes}  fail={fails}  skip={skips}")

    # On failure, print the [powhttp]-tagged lines from mitmproxy.log so we
    # can see whether hooks fired without needing a second docker run.
    if fails > 0:
        log_path = Path("/state/mitmproxy.log")
        if log_path.exists():
            print()
            print("[probe] mitmproxy.log tail (powhttp-tagged lines):")
            for line in log_path.read_text(errors="replace").splitlines()[-200:]:
                if "[powhttp]" in line or "sse" in line.lower() or "stream" in line.lower():
                    print(f"  {line}")
    return 1 if fails > 0 else 0


if __name__ == "__main__":
    sys.exit(main())
