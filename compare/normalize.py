"""Shared normalized-flow schema.

Both sides (powhttp HAR and our agent-box SQLite) get boiled down to a common
JSON shape here so the diff tool only has to understand one thing.

Design notes:
- `match_key` is `(method, host, path)` — stable across proxies, ignores
  query strings (they often carry nonce/jitter that varies between runs).
- Body SHA256 is over the RAW bytes as the proxy saw them (gzipped stays
  gzipped). Matching compressed bodies on disk is fine for an A/B sanity
  check; decompression would be a separate tool.
- Pseudo-headers (`:method`, `:authority`, etc.) and cookies get filtered out
  of the header diff — pseudo-headers are transport-level and cookies differ
  between a real browser profile and our headless container by design.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import asdict, dataclass, field
from typing import Iterable, Iterator
from urllib.parse import urlparse

# Headers we never include in the normalized header list — they're either
# transport-plumbing or known to legitimately differ between a real Chrome
# profile and our ephemeral headless container.
_IGNORED_HEADER_PREFIXES = (":",)  # HTTP/2 pseudo-headers
_IGNORED_HEADER_NAMES = {
    "cookie", "set-cookie",
    "user-agent",          # headless vs real chrome always differs
    "sec-ch-ua", "sec-ch-ua-mobile", "sec-ch-ua-platform",
    "accept-language",     # OS locale leaks in
    "x-client-data",       # Chrome variants header, heavily profile-dependent
    "cf-ray", "cf-cache-status",  # Cloudflare edge node, race-condition noisy
    "date",                # always differs
    "age",                 # CDN-age, always differs
    "server-timing",       # CDN-telemetry, flaky
    "alt-svc",             # sometimes sent, sometimes not
    "report-to", "nel",    # reporting plumbing
    "x-powered-by",        # occasionally varies
}


@dataclass
class NormFlow:
    source: str               # "powhttp" | "agentbox"
    started_at_ms: int
    method: str
    url: str
    scheme: str
    host: str
    path: str
    status: int | None
    http_version: str | None
    content_type: str | None
    req_headers: list[list[str]] = field(default_factory=list)   # [[name, value], ...]
    resp_headers: list[list[str]] = field(default_factory=list)
    req_body_size: int = 0
    resp_body_size: int = 0
    req_body_sha256: str | None = None
    resp_body_sha256: str | None = None

    @property
    def match_key(self) -> tuple[str, str, str]:
        return (self.method.upper(), self.host.lower(), self.path or "/")

    def to_jsonl(self) -> str:
        return json.dumps(asdict(self), ensure_ascii=False)


def parse_url(url: str) -> tuple[str, str, str]:
    """Return (scheme, host, path)."""
    u = urlparse(url)
    return u.scheme, u.netloc.lower(), u.path or "/"


def clean_headers(headers: Iterable[tuple[str, str]]) -> list[list[str]]:
    """Drop pseudo-headers and known-noisy headers; lowercase names; sort for diff stability."""
    out: list[list[str]] = []
    for name, value in headers:
        n = name.strip().lower()
        if any(n.startswith(p) for p in _IGNORED_HEADER_PREFIXES):
            continue
        if n in _IGNORED_HEADER_NAMES:
            continue
        out.append([n, value])
    out.sort(key=lambda kv: (kv[0], kv[1]))
    return out


def sha256_or_none(data: bytes | None) -> str | None:
    if not data:
        return None
    return hashlib.sha256(data).hexdigest()


def normalize_http_version(v: str | None) -> str | None:
    """mitmproxy reports "HTTP/2.0", HAR reports "HTTP/2". Collapse to the shorter form."""
    if not v:
        return v
    if v == "HTTP/2.0":
        return "HTTP/2"
    if v == "HTTP/3.0":
        return "HTTP/3"
    return v


def find_header(headers: list, name: str) -> str | None:
    """Case-insensitive single lookup in a [[k,v], ...] list."""
    target = name.lower()
    for k, v in headers:
        if k.lower() == target:
            return v
    return None


def decode_body(blob: bytes | None, content_encoding: str | None) -> bytes | None:
    """Undo gzip / deflate / brotli / zstd so sizes & hashes match across proxies.

    powhttp's HAR stores the DECODED body (per HAR spec §4.5), but mitmproxy's
    `raw_content` is what came over the wire (still gzipped, brotli'd, etc.).
    For a fair comparison we need to decode on our side before sizing/hashing.

    Falls back to the raw bytes on any decode error or if the codec library
    isn't installed — the caller still gets a usable body, just with the
    original mismatch surfaced.
    """
    if not blob or not content_encoding:
        return blob
    enc = content_encoding.strip().lower()
    # content-encoding can be a stacked list like "gzip, gzip"; handle simple cases.
    enc = enc.split(",")[-1].strip()

    try:
        if enc in ("identity", ""):
            return blob
        if enc == "gzip":
            import gzip
            return gzip.decompress(blob)
        if enc == "deflate":
            import zlib
            # zlib.decompress handles both zlib-wrapped and raw deflate
            try:
                return zlib.decompress(blob)
            except zlib.error:
                return zlib.decompress(blob, -zlib.MAX_WBITS)
        if enc == "br":
            try:
                import brotli  # type: ignore
                return brotli.decompress(blob)
            except ImportError:
                return blob
        if enc == "zstd":
            try:
                import zstandard  # type: ignore
                return zstandard.ZstdDecompressor().decompress(blob)
            except ImportError:
                return blob
    except Exception:
        return blob
    return blob


def write_jsonl(path: str, flows: Iterable[NormFlow]) -> int:
    n = 0
    with open(path, "w", encoding="utf-8") as f:
        for flow in flows:
            f.write(flow.to_jsonl())
            f.write("\n")
            n += 1
    return n


def read_jsonl(path: str) -> Iterator[NormFlow]:
    with open(path, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            d = json.loads(line)
            yield NormFlow(**d)
