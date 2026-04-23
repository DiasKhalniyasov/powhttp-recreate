"""DoH upstream resolver for mitmproxy.

powhttp resolves all upstream DNS over HTTPS so the recording host's
/etc/resolv.conf can't influence what the proxy resolves to. We match that
by patching `socket.getaddrinfo` in the mitmproxy process to issue DoH
queries instead of hitting libc's resolver.

Controlled by env vars:
  POWHTTP_DOH                       — 'on' to enable (default off)
  POWHTTP_DOH_ENDPOINT              — comma-separated DoH URLs; defaults to
                                      Cloudflare + Quad9 (matches powhttp's
                                      1.12.12.12/9.9.9.11 choice)
  POWHTTP_DOH_FALLBACK              — 'system' (default) or 'fail'. On DoH
                                      error, either fall through to libc or
                                      raise.

Only A/AAAA lookups for non-numeric hosts go via DoH. Numeric literals,
IPv6 brackets, and localhost are always resolved locally.

Requires dnspython 2.4+ with DoH support (pip install 'dnspython[doh]').
"""

from __future__ import annotations

import logging
import os
import socket
import threading
from functools import lru_cache
from typing import Any

log = logging.getLogger("doh")

_DEFAULT_ENDPOINTS = (
    "https://cloudflare-dns.com/dns-query",
    "https://dns.quad9.net/dns-query",
    "https://dns.google/dns-query",
)

_orig_getaddrinfo = socket.getaddrinfo
_lock = threading.Lock()
_patched = False


def _is_numeric_host(host: str) -> bool:
    """True if host is already an IPv4/IPv6 literal or 'localhost'."""
    if not host:
        return True
    if host == "localhost" or host.endswith(".localhost"):
        return True
    try:
        socket.inet_pton(socket.AF_INET, host)
        return True
    except OSError:
        pass
    try:
        # Strip IPv6 brackets if any.
        h = host
        if h.startswith("[") and h.endswith("]"):
            h = h[1:-1]
        socket.inet_pton(socket.AF_INET6, h)
        return True
    except OSError:
        pass
    return False


def _doh_query(hostname: str, endpoints: tuple[str, ...]) -> list[str]:
    """Return a flat list of A + AAAA strings, empty on failure."""
    try:
        import dns.resolver
        import dns.rdatatype
        from dns.query import https as doh_https
        from dns.message import make_query
    except ImportError as e:
        log.warning("dnspython with DoH not available: %r", e)
        return []

    results: list[str] = []
    for endpoint in endpoints:
        try:
            for qtype in (dns.rdatatype.A, dns.rdatatype.AAAA):
                q = make_query(hostname, qtype)
                r = doh_https(q, endpoint, timeout=3.0)
                for ans in r.answer:
                    for item in ans:
                        s = item.to_text()
                        # .to_text() on A/AAAA is the bare address string.
                        if s and s not in results:
                            results.append(s)
            if results:
                return results
        except Exception as e:
            log.debug("DoH %s failed for %s: %r", endpoint, hostname, e)
            continue
    return results


@lru_cache(maxsize=4096)
def _cached_doh(hostname: str, endpoints: tuple[str, ...]) -> tuple[str, ...]:
    return tuple(_doh_query(hostname, endpoints))


def _patched_getaddrinfo(host, port, family=0, type=0, proto=0, flags=0):  # noqa: A002
    if not host or _is_numeric_host(host):
        return _orig_getaddrinfo(host, port, family, type, proto, flags)

    endpoints = tuple(
        e.strip() for e in os.environ.get("POWHTTP_DOH_ENDPOINT", "").split(",") if e.strip()
    ) or _DEFAULT_ENDPOINTS

    addrs = _cached_doh(host, endpoints)
    if not addrs:
        if os.environ.get("POWHTTP_DOH_FALLBACK", "system") == "system":
            return _orig_getaddrinfo(host, port, family, type, proto, flags)
        raise socket.gaierror(f"DoH resolution failed for {host!r}")

    port_int = 0 if port is None else (port if isinstance(port, int) else int(port))
    out: list[Any] = []
    for a in addrs:
        is_v6 = ":" in a
        fam = socket.AF_INET6 if is_v6 else socket.AF_INET
        if family and family not in (fam, socket.AF_UNSPEC):
            continue
        sockaddr = (a, port_int, 0, 0) if is_v6 else (a, port_int)
        out.append((fam, type or socket.SOCK_STREAM, proto or 0, "", sockaddr))
    if not out and os.environ.get("POWHTTP_DOH_FALLBACK", "system") == "system":
        return _orig_getaddrinfo(host, port, family, type, proto, flags)
    return out


def install() -> bool:
    """Patch socket.getaddrinfo if POWHTTP_DOH=on. Idempotent."""
    global _patched
    with _lock:
        if _patched:
            return True
        if os.environ.get("POWHTTP_DOH", "").lower() not in ("on", "1", "true", "yes"):
            log.info("DoH disabled (set POWHTTP_DOH=on to enable)")
            return False
        try:
            import dns.resolver  # noqa: F401
        except ImportError:
            log.warning("POWHTTP_DOH=on but dnspython not installed; DoH disabled")
            return False
        socket.getaddrinfo = _patched_getaddrinfo
        _patched = True
        log.info("DoH upstream resolver installed")
        return True
