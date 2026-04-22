#!/usr/bin/env python3
"""Turn a powhttp HAR export into normalized JSONL.

Usage:
    python parse_har.py <path/to/powhttp.har> <output.jsonl>

HAR 1.3 spec: https://www.softwareishard.com/blog/har-12-spec/
powhttp exports a standard-compliant HAR; we don't need to be lenient about
quirks. Request/response bodies are inline in `postData.text` / `content.text`,
base64-encoded when binary.
"""

from __future__ import annotations

import base64
import datetime as dt
import json
import pathlib
import sys

# Import path helper — works whether run as script or as module.
sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
from normalize import (
    NormFlow,
    clean_headers,
    normalize_http_version,
    parse_url,
    sha256_or_none,
    write_jsonl,
)


def _iso_to_ms(iso: str) -> int:
    """2026-04-22T23:59:41.893+05:00 → unix millis."""
    # Python 3.11+ handles ISO with timezone offset natively.
    return int(dt.datetime.fromisoformat(iso).timestamp() * 1000)


def _body_bytes(content: dict | None) -> bytes | None:
    """HAR represents bodies as either plain text or base64 (when `encoding` == 'base64')."""
    if not content:
        return None
    text = content.get("text")
    if not text:
        return None
    if content.get("encoding") == "base64":
        try:
            return base64.b64decode(text)
        except Exception:
            return None
    return text.encode("utf-8", errors="replace")


def _post_body_bytes(post_data: dict | None) -> bytes | None:
    if not post_data:
        return None
    text = post_data.get("text")
    if not text:
        return None
    if post_data.get("encoding") == "base64":
        try:
            return base64.b64decode(text)
        except Exception:
            return None
    return text.encode("utf-8", errors="replace")


def har_entry_to_norm(entry: dict) -> NormFlow:
    req = entry["request"]
    resp = entry.get("response") or {}

    url = req["url"]
    scheme, host, path = parse_url(url)

    req_headers = [(h["name"], h["value"]) for h in req.get("headers", [])]
    resp_headers = [(h["name"], h["value"]) for h in resp.get("headers", [])]

    req_body = _post_body_bytes(req.get("postData"))
    resp_body = _body_bytes(resp.get("content"))

    content_type = None
    for name, value in resp_headers:
        if name.lower() == "content-type":
            content_type = value
            break
    if content_type is None and resp.get("content", {}).get("mimeType"):
        content_type = resp["content"]["mimeType"]

    return NormFlow(
        source="powhttp",
        started_at_ms=_iso_to_ms(entry["startedDateTime"]),
        method=req["method"],
        url=url,
        scheme=scheme,
        host=host,
        path=path,
        status=resp.get("status") or None,
        http_version=normalize_http_version(resp.get("httpVersion") or req.get("httpVersion")),
        content_type=content_type,
        req_headers=clean_headers(req_headers),
        resp_headers=clean_headers(resp_headers),
        req_body_size=len(req_body) if req_body else 0,
        resp_body_size=len(resp_body) if resp_body else (resp.get("content", {}).get("size") or 0),
        req_body_sha256=sha256_or_none(req_body),
        resp_body_sha256=sha256_or_none(resp_body),
    )


def har_to_jsonl(har_path: str, out_path: str) -> int:
    har = json.loads(pathlib.Path(har_path).read_bytes())
    entries = har["log"]["entries"]
    flows = [har_entry_to_norm(e) for e in entries]
    return write_jsonl(out_path, flows)


def main() -> int:
    if len(sys.argv) != 3:
        print(__doc__, file=sys.stderr)
        return 2
    har_path, out_path = sys.argv[1], sys.argv[2]
    n = har_to_jsonl(har_path, out_path)
    print(f"[parse_har] {n} entries -> {out_path}", file=sys.stderr)
    return 0


if __name__ == "__main__":
    sys.exit(main())
