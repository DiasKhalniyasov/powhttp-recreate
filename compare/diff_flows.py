#!/usr/bin/env python3
"""Diff two normalized JSONL flow files, emit a markdown report + JSONL diff.

Usage:
    python diff_flows.py <a.jsonl> <b.jsonl> <report.md> <diff.jsonl>

Matching:
    Both sides list flows by (method, host, path). We count occurrences on each
    side. If a key appears N times in A and M times in B, min(N,M) are treated
    as matched (paired in chronological order), |N-M| are "only in" the side
    that had more. For matched pairs we then diff headers, sizes, and body
    hashes.

Report sections:
    1. Summary counts
    2. Host-level coverage
    3. Only in A (powhttp)
    4. Only in B (agentbox)
    5. Matched-but-differ (headers / sizes / body hash)
    6. Top differing header keys
"""

from __future__ import annotations

import argparse
import collections
import json
import pathlib
import sys

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
from normalize import NormFlow, read_jsonl


# ---------------------------------------------------------------------------
# Matching
# ---------------------------------------------------------------------------

def _bucket(flows: list[NormFlow]) -> dict[tuple[str, str, str], list[NormFlow]]:
    b: dict[tuple[str, str, str], list[NormFlow]] = collections.defaultdict(list)
    for f in flows:
        b[f.match_key].append(f)
    # Sort each bucket chronologically so pairing is deterministic.
    for k in b:
        b[k].sort(key=lambda f: f.started_at_ms)
    return b


def match_flows(a: list[NormFlow], b: list[NormFlow]) -> tuple[list[tuple[NormFlow, NormFlow]], list[NormFlow], list[NormFlow]]:
    """Return (paired, only_in_a, only_in_b)."""
    ba, bb = _bucket(a), _bucket(b)
    keys = set(ba) | set(bb)

    paired: list[tuple[NormFlow, NormFlow]] = []
    only_a: list[NormFlow] = []
    only_b: list[NormFlow] = []

    for k in keys:
        xs, ys = ba.get(k, []), bb.get(k, [])
        n = min(len(xs), len(ys))
        for i in range(n):
            paired.append((xs[i], ys[i]))
        if len(xs) > n:
            only_a.extend(xs[n:])
        if len(ys) > n:
            only_b.extend(ys[n:])

    return paired, only_a, only_b


# ---------------------------------------------------------------------------
# Per-pair diff
# ---------------------------------------------------------------------------

def diff_pair(a: NormFlow, b: NormFlow) -> dict:
    """Return a dict describing differences, or empty dict if identical."""
    d: dict = {}

    if a.status != b.status:
        d["status"] = {"a": a.status, "b": b.status}
    if a.http_version != b.http_version:
        d["http_version"] = {"a": a.http_version, "b": b.http_version}
    if (a.content_type or "").split(";")[0] != (b.content_type or "").split(";")[0]:
        d["content_type"] = {"a": a.content_type, "b": b.content_type}

    # Sizes — allow a 5% tolerance since gzip nonce / minor protocol framing
    # differences can make byte-counts jitter.
    for field in ("req_body_size", "resp_body_size"):
        va, vb = getattr(a, field), getattr(b, field)
        if va == vb:
            continue
        m = max(va, vb, 1)
        if abs(va - vb) / m > 0.05:
            d[field] = {"a": va, "b": vb}

    # Body hashes — only flag if both sides have a hash and they differ.
    for field in ("req_body_sha256", "resp_body_sha256"):
        va, vb = getattr(a, field), getattr(b, field)
        if va and vb and va != vb:
            d[field] = {"a": va[:12] + "…", "b": vb[:12] + "…"}

    # Response header keys — symmetric difference on names only (values jitter).
    ka = {k for k, _ in a.resp_headers}
    kb = {k for k, _ in b.resp_headers}
    only_ka = sorted(ka - kb)
    only_kb = sorted(kb - ka)
    if only_ka or only_kb:
        d["resp_header_keys"] = {"only_a": only_ka, "only_b": only_kb}

    return d


# ---------------------------------------------------------------------------
# Report
# ---------------------------------------------------------------------------

def _host_coverage(a: list[NormFlow], b: list[NormFlow]) -> list[dict]:
    ca = collections.Counter(f.host for f in a)
    cb = collections.Counter(f.host for f in b)
    hosts = sorted(set(ca) | set(cb))
    out = []
    for h in hosts:
        out.append({"host": h, "a": ca.get(h, 0), "b": cb.get(h, 0)})
    out.sort(key=lambda r: -(r["a"] + r["b"]))
    return out


def _header_churn(differing_pairs: list[dict]) -> collections.Counter:
    c: collections.Counter = collections.Counter()
    for d in differing_pairs:
        rh = d.get("resp_header_keys") or {}
        for k in rh.get("only_a", []):
            c[("only_a", k)] += 1
        for k in rh.get("only_b", []):
            c[("only_b", k)] += 1
    return c


def write_report(
    a_name: str, b_name: str,
    a: list[NormFlow], b: list[NormFlow],
    paired: list[tuple[NormFlow, NormFlow]],
    only_a: list[NormFlow], only_b: list[NormFlow],
    diff_records: list[dict],
    out_md: str,
) -> None:
    lines: list[str] = []
    L = lines.append

    L(f"# Flow comparison: `{a_name}` vs `{b_name}`\n")
    L(f"- **{a_name}**: {len(a)} flows")
    L(f"- **{b_name}**: {len(b)} flows")
    L(f"- **Matched pairs** (by method+host+path): {len(paired)}")
    L(f"- **Only in {a_name}**: {len(only_a)}")
    L(f"- **Only in {b_name}**: {len(only_b)}")
    differing = [r for r in diff_records if r.get("differences")]
    L(f"- **Matched but differ**: {len(differing)} / {len(paired)}\n")

    # Host coverage
    L("## Host coverage\n")
    L(f"| Host | {a_name} | {b_name} |")
    L("|---|---:|---:|")
    for row in _host_coverage(a, b):
        L(f"| `{row['host']}` | {row['a']} | {row['b']} |")
    L("")

    # Only in A
    L(f"## Only in {a_name} ({len(only_a)})\n")
    if only_a:
        L("| Method | Host | Path | Status |")
        L("|---|---|---|---:|")
        for f in sorted(only_a, key=lambda f: (f.host, f.path)):
            L(f"| {f.method} | `{f.host}` | `{f.path}` | {f.status or '—'} |")
    else:
        L("_(none)_")
    L("")

    # Only in B
    L(f"## Only in {b_name} ({len(only_b)})\n")
    if only_b:
        L("| Method | Host | Path | Status |")
        L("|---|---|---|---:|")
        for f in sorted(only_b, key=lambda f: (f.host, f.path)):
            L(f"| {f.method} | `{f.host}` | `{f.path}` | {f.status or '—'} |")
    else:
        L("_(none)_")
    L("")

    # Differing pairs
    L(f"## Matched-but-differ ({len(differing)})\n")
    if differing:
        for r in differing[:50]:
            f = r["a_summary"]
            L(f"### `{f['method']} {f['host']}{f['path']}`")
            L("```json")
            L(json.dumps(r["differences"], indent=2, ensure_ascii=False))
            L("```")
        if len(differing) > 50:
            L(f"\n_(…{len(differing) - 50} more not shown; see diff.jsonl for full set)_")
    else:
        L("_(none — matched pairs are identical at the normalized-header level)_")
    L("")

    # Header churn
    churn = _header_churn(differing)
    if churn:
        L("## Top header keys that differ across matched pairs\n")
        L(f"| Side | Header | Count |")
        L("|---|---|---:|")
        for (side, name), n in churn.most_common(25):
            side_label = a_name if side == "only_a" else b_name
            L(f"| {side_label} | `{name}` | {n} |")
        L("")

    pathlib.Path(out_md).write_text("\n".join(lines), encoding="utf-8")


def write_diff_jsonl(
    out_path: str,
    paired: list[tuple[NormFlow, NormFlow]],
    only_a: list[NormFlow], only_b: list[NormFlow],
) -> list[dict]:
    """Write one JSON record per flow/pair; return the differing records (in memory)."""
    records: list[dict] = []
    with open(out_path, "w", encoding="utf-8") as f:
        for fa, fb in paired:
            diff = diff_pair(fa, fb)
            rec = {
                "type": "paired",
                "a_summary": {"method": fa.method, "host": fa.host, "path": fa.path, "status": fa.status},
                "b_summary": {"method": fb.method, "host": fb.host, "path": fb.path, "status": fb.status},
                "differences": diff,
            }
            records.append(rec)
            f.write(json.dumps(rec, ensure_ascii=False) + "\n")
        for fa in only_a:
            rec = {"type": "only_a", "flow": {"method": fa.method, "host": fa.host, "path": fa.path, "status": fa.status, "url": fa.url}}
            f.write(json.dumps(rec, ensure_ascii=False) + "\n")
        for fb in only_b:
            rec = {"type": "only_b", "flow": {"method": fb.method, "host": fb.host, "path": fb.path, "status": fb.status, "url": fb.url}}
            f.write(json.dumps(rec, ensure_ascii=False) + "\n")
    return records


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("a_jsonl")
    ap.add_argument("b_jsonl")
    ap.add_argument("report_md")
    ap.add_argument("diff_jsonl")
    ap.add_argument("--a-name", default=None, help="Override display name for side A (default: inferred from `source`)")
    ap.add_argument("--b-name", default=None, help="Override display name for side B")
    args = ap.parse_args()

    a = list(read_jsonl(args.a_jsonl))
    b = list(read_jsonl(args.b_jsonl))

    a_name = args.a_name or (a[0].source if a else "A")
    b_name = args.b_name or (b[0].source if b else "B")

    paired, only_a, only_b = match_flows(a, b)
    diff_records = write_diff_jsonl(args.diff_jsonl, paired, only_a, only_b)
    write_report(a_name, b_name, a, b, paired, only_a, only_b, diff_records, args.report_md)

    differing = sum(1 for r in diff_records if r.get("differences"))
    print(
        f"[diff] {a_name}={len(a)} {b_name}={len(b)} paired={len(paired)} "
        f"only_{a_name}={len(only_a)} only_{b_name}={len(only_b)} "
        f"differing={differing} -> {args.report_md} + {args.diff_jsonl}",
        file=sys.stderr,
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
