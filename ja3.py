"""JA3 + JA4 computation from a parsed TLS ClientHello.

Input: mitmproxy's `tls.ClientHelloData.client_hello` — a parsed ClientHello
with `.cipher_suites`, `.extensions`, `.sni`, `.alpn_protocols`, plus the
raw underlying bytes (for the GREASE-stripped re-parse JA4 needs).

Output: the JA3 string (pre-hash), its MD5, and the JA4 fingerprint string.

References:
  - JA3:  https://github.com/salesforce/ja3
  - JA4:  https://github.com/FoxIO-LLC/ja4/blob/main/technical_details/JA4.md
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass
from typing import Iterable

# GREASE cipher/extension values (RFC 8701) — stripped from JA3/JA4 because
# browsers randomize them per-handshake.
_GREASE = frozenset(
    int.from_bytes(bytes([a, a]), "big")
    for a in (0x0A, 0x1A, 0x2A, 0x3A, 0x4A, 0x5A, 0x6A, 0x7A,
              0x8A, 0x9A, 0xAA, 0xBA, 0xCA, 0xDA, 0xEA, 0xFA)
)

# Extensions that carry "signalling" TLS state — included in JA4 cipher/ext
# counts but NOT in the JA4 sorted-ext hash (SNI=0x0000, ALPN=0x0010).
_JA4_EXCLUDED_FROM_HASH = frozenset({0x0000, 0x0010})


@dataclass
class TlsFingerprint:
    ja3: str          # Raw JA3 string (before MD5)
    ja3_hash: str     # MD5 of ja3
    ja4: str          # JA4 fingerprint (already in its final form)


def _strip_grease(values: Iterable[int]) -> list[int]:
    return [v for v in values if v not in _GREASE]


def _tls_version_for_ja3(client_hello_legacy_version: int, extensions: list) -> int:
    """JA3 uses the legacy_version from the record header, not the
    supported_versions extension. mitmproxy's ClientHello gives this directly."""
    return client_hello_legacy_version


def _tls_version_for_ja4(extensions: list) -> str:
    """JA4's version char: '13' for TLS1.3 if supported_versions contains 0x0304;
    else '12' for TLS1.2, '11' for TLS1.1, '10' for TLS1.0, 's3' for SSLv3, 'd0' for DTLS1.0, etc.
    We look in extension 43 (supported_versions) first; fall back to legacy."""
    for ext in extensions:
        # mitmproxy's Extension is a namedtuple: (type: int, data: bytes)
        ext_type = getattr(ext, "type", None) or (ext[0] if isinstance(ext, tuple) else None)
        ext_data = getattr(ext, "data", None) or (ext[1] if isinstance(ext, tuple) else b"")
        if ext_type == 0x002B and ext_data:  # supported_versions
            # Client form: 1-byte length, then list of 2-byte versions.
            if len(ext_data) >= 3:
                count = ext_data[0]
                versions = []
                for i in range(count // 2):
                    off = 1 + i * 2
                    if off + 2 <= len(ext_data):
                        v = int.from_bytes(ext_data[off : off + 2], "big")
                        if v not in _GREASE:
                            versions.append(v)
                if versions:
                    best = max(versions)
                    return _version_to_ja4(best)
    return "00"


def _version_to_ja4(v: int) -> str:
    return {
        0x0304: "13",
        0x0303: "12",
        0x0302: "11",
        0x0301: "10",
        0x0300: "s3",
        0xFEFF: "d1",  # DTLS 1.0
        0xFEFD: "d2",  # DTLS 1.2
        0xFEFC: "d3",  # DTLS 1.3
    }.get(v, "00")


def _ext_iter(extensions) -> list[tuple[int, bytes]]:
    out: list[tuple[int, bytes]] = []
    for ext in extensions or []:
        if hasattr(ext, "type"):
            out.append((int(ext.type), bytes(getattr(ext, "data", b"") or b"")))
        elif isinstance(ext, tuple) and len(ext) >= 2:
            out.append((int(ext[0]), bytes(ext[1] or b"")))
    return out


def _elliptic_curves(extensions: list[tuple[int, bytes]]) -> list[int]:
    """Extension 10 (supported_groups) — TLS 1.3 names; JA3 calls them 'curves'."""
    for t, data in extensions:
        if t == 0x000A and len(data) >= 2:
            length = int.from_bytes(data[0:2], "big")
            out = []
            for i in range(length // 2):
                off = 2 + i * 2
                if off + 2 <= len(data):
                    out.append(int.from_bytes(data[off : off + 2], "big"))
            return _strip_grease(out)
    return []


def _ec_point_formats(extensions: list[tuple[int, bytes]]) -> list[int]:
    """Extension 11 (ec_point_formats)."""
    for t, data in extensions:
        if t == 0x000B and len(data) >= 1:
            n = data[0]
            return list(data[1 : 1 + n])
    return []


def _alpn_first_last_chars(alpn_protocols) -> str:
    """JA4's ALPN component: first+last char of the first ALPN value.
    '00' if no ALPN. For h2 → 'h2', for http/1.1 → 'h1'."""
    if not alpn_protocols:
        return "00"
    first = alpn_protocols[0]
    if isinstance(first, (bytes, bytearray)):
        try:
            first = first.decode("ascii", errors="replace")
        except Exception:
            return "00"
    if not first:
        return "00"
    if len(first) == 1:
        return first + first
    return first[0] + first[-1]


def compute(client_hello, legacy_version: int | None = None) -> TlsFingerprint:
    """Compute JA3 + JA4 from a mitmproxy ClientHello.

    Args:
        client_hello: mitmproxy.tls.ClientHello (has cipher_suites, extensions,
                      sni, alpn_protocols, maybe legacy_version).
        legacy_version: record-layer legacy version (uint16); if None, tries
                        client_hello.legacy_version or defaults to TLS 1.2.
    """
    ciphers = _strip_grease(int(c) for c in getattr(client_hello, "cipher_suites", []) or [])
    extensions = _ext_iter(getattr(client_hello, "extensions", None) or [])
    # JA3 lists extension types in the ORDER THEY APPEAR, not sorted.
    ext_types_ordered = [t for t, _ in extensions if t not in _GREASE]
    curves = _elliptic_curves(extensions)
    pt_fmts = _ec_point_formats(extensions)

    ver_ja3 = legacy_version if legacy_version is not None else getattr(client_hello, "legacy_version", 0x0303)

    ja3_str = "{v},{c},{e},{cv},{pf}".format(
        v=ver_ja3,
        c="-".join(str(c) for c in ciphers),
        e="-".join(str(t) for t in ext_types_ordered),
        cv="-".join(str(c) for c in curves),
        pf="-".join(str(p) for p in pt_fmts),
    )
    ja3_hash = hashlib.md5(ja3_str.encode("ascii")).hexdigest()

    # --- JA4 ---
    sni = getattr(client_hello, "sni", None)
    alpn_protocols = getattr(client_hello, "alpn_protocols", None) or []
    tls_proto = "t"   # 't' = TCP TLS, 'q' = QUIC, 'd' = DTLS
    version_str = _tls_version_for_ja4(getattr(client_hello, "extensions", None) or [])
    if version_str == "00" and ver_ja3:
        version_str = _version_to_ja4(ver_ja3)
    sni_char = "d" if sni else "i"   # domain vs IP
    cipher_count = f"{min(len(ciphers), 99):02d}"
    ext_count = f"{min(len(ext_types_ordered), 99):02d}"
    alpn_chars = _alpn_first_last_chars(alpn_protocols)

    ja4_a = f"{tls_proto}{version_str}{sni_char}{cipher_count}{ext_count}{alpn_chars}"

    # JA4_b = sha256 of sorted hex ciphers, first 12 chars
    sorted_ciphers_hex = ",".join(f"{c:04x}" for c in sorted(ciphers))
    ja4_b = hashlib.sha256(sorted_ciphers_hex.encode("ascii")).hexdigest()[:12]

    # JA4_c = sha256 of sorted hex extensions (SNI + ALPN excluded), first 12 chars,
    # then "_" + signature_algorithms (ext 0x000D) values in ORIGINAL ORDER.
    ext_for_hash = sorted(
        t for t in ext_types_ordered if t not in _JA4_EXCLUDED_FROM_HASH
    )
    sig_algs: list[int] = []
    for t, data in extensions:
        if t == 0x000D and len(data) >= 2:  # signature_algorithms
            n = int.from_bytes(data[0:2], "big")
            for i in range(n // 2):
                off = 2 + i * 2
                if off + 2 <= len(data):
                    sig_algs.append(int.from_bytes(data[off : off + 2], "big"))
            break
    ja4_c_source = ",".join(f"{e:04x}" for e in ext_for_hash)
    if sig_algs:
        ja4_c_source += "_" + ",".join(f"{s:04x}" for s in sig_algs)
    ja4_c = hashlib.sha256(ja4_c_source.encode("ascii")).hexdigest()[:12]

    ja4 = f"{ja4_a}_{ja4_b}_{ja4_c}"

    return TlsFingerprint(ja3=ja3_str, ja3_hash=ja3_hash, ja4=ja4)


if __name__ == "__main__":
    # Smoke test with a synthetic minimal ClientHello-like object.
    class FakeExt:
        def __init__(self, t, d=b""):
            self.type, self.data = t, d

    class FakeCH:
        cipher_suites = [0x1301, 0x1302, 0x1303, 0xC02B, 0xC02F]
        extensions = [
            FakeExt(0x0000, b"\x00"),                   # SNI
            FakeExt(0x0010, b"\x00\x02\x02h2"),         # ALPN: h2
            FakeExt(0x002B, b"\x02\x03\x04\x03\x03"),   # supported_versions: 1.3,1.2
            FakeExt(0x000A, b"\x00\x04\x00\x17\x00\x18"),  # curves
            FakeExt(0x000B, b"\x01\x00"),               # point_formats
            FakeExt(0x000D, b"\x00\x04\x04\x03\x08\x04"),  # sig_algs
        ]
        sni = "example.com"
        alpn_protocols = [b"h2", b"http/1.1"]
        legacy_version = 0x0303

    fp = compute(FakeCH())
    print("JA3:     ", fp.ja3)
    print("JA3 hash:", fp.ja3_hash)
    print("JA4:     ", fp.ja4)
