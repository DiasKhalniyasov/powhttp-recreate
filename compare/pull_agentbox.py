#!/usr/bin/env python3
"""Dump our captures/flows.db to normalized JSONL.

Usage:
    python pull_agentbox.py <path/to/flows.db> <output.jsonl>
    python pull_agentbox.py <path/to/flows.db> <output.jsonl> --since-ms 1700000000000
    python pull_agentbox.py <path/to/flows.db> <output.jsonl> --bodies-dir <path>

If --bodies-dir is omitted, we look for a sibling `bodies/` directory next to
flows.db — that's where large bodies are content-addressed by the mitm addon.
"""

from __future__ import annotations

import argparse
import json
import pathlib
import sqlite3
import sys

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
from normalize import (
    NormFlow,
    clean_headers,
    decode_body,
    find_header,
    normalize_http_version,
    parse_url,
    sha256_or_none,
    write_jsonl,
)


def _resolve_body(inline: bytes | None, ref: str | None, bodies_dir: pathlib.Path) -> bytes | None:
    if inline is not None:
        return bytes(inline)
    if ref:
        # Our mitm addon layout: bodies/<first-2-of-sha>/<full-sha>
        p = bodies_dir / ref[:2] / ref
        if p.exists():
            return p.read_bytes()
    return None


def row_to_norm(row: sqlite3.Row, bodies_dir: pathlib.Path) -> NormFlow:
    url = row["url"]
    scheme, host, path = parse_url(url)

    req_headers = json.loads(row["req_headers"] or "[]")  # stored as [[k,v],...]
    resp_headers = json.loads(row["resp_headers"] or "[]")

    req_body = _resolve_body(row["req_body_inline"], row["req_body_ref"], bodies_dir)
    resp_body = _resolve_body(row["resp_body_inline"], row["resp_body_ref"], bodies_dir)

    # mitmproxy's raw_content is still gzipped / brotli'd / zstd'd. HAR stores
    # the decoded body, so decode here before sizing/hashing for a fair diff.
    # Request bodies are almost never compressed in practice, but handle both
    # sides symmetrically for completeness.
    req_enc = find_header(req_headers, "content-encoding")
    resp_enc = find_header(resp_headers, "content-encoding")
    req_body = decode_body(req_body, req_enc)
    resp_body = decode_body(resp_body, resp_enc)

    return NormFlow(
        source="agentbox",
        started_at_ms=row["started_at"],
        method=row["method"],
        url=url,
        scheme=row["scheme"] or scheme,
        host=row["remote_host"] or host,
        path=row["path"] or path,
        status=row["status"],
        http_version=normalize_http_version(row["http_version"]),
        content_type=row["content_type"],
        req_headers=clean_headers([(k, v) for k, v in req_headers]),
        resp_headers=clean_headers([(k, v) for k, v in resp_headers]),
        req_body_size=len(req_body) if req_body else (row["req_body_size"] or 0),
        resp_body_size=len(resp_body) if resp_body else (row["resp_body_size"] or 0),
        req_body_sha256=sha256_or_none(req_body),
        resp_body_sha256=sha256_or_none(resp_body),
    )


def dump(db_path: str, out_path: str, bodies_dir: pathlib.Path, since_ms: int | None) -> int:
    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row
    try:
        sql = "SELECT * FROM entries"
        params: list = []
        if since_ms is not None:
            sql += " WHERE started_at >= ?"
            params.append(since_ms)
        sql += " ORDER BY started_at ASC"
        rows = conn.execute(sql, params).fetchall()
    finally:
        conn.close()
    flows = [row_to_norm(r, bodies_dir) for r in rows]
    return write_jsonl(out_path, flows)


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("db_path")
    ap.add_argument("out_path")
    ap.add_argument("--bodies-dir", default=None)
    ap.add_argument("--since-ms", type=int, default=None)
    args = ap.parse_args()

    bodies_dir = pathlib.Path(args.bodies_dir) if args.bodies_dir else pathlib.Path(args.db_path).parent / "bodies"
    n = dump(args.db_path, args.out_path, bodies_dir, args.since_ms)
    print(f"[pull_agentbox] {n} entries -> {args.out_path}", file=sys.stderr)
    return 0


if __name__ == "__main__":
    sys.exit(main())
