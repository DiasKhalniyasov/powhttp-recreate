"""HTTP/2 frame-level tap for mitmproxy.

mitmproxy consumes h2 frames through the `h2.connection.H2Connection` state
machine and then exposes only the synthesized HTTPFlow. We want powhttp's
frame-level view (DATA / HEADERS / WINDOW_UPDATE / RST_STREAM / PRIORITY /
PING / SETTINGS / GOAWAY / PUSH_PROMISE / CONTINUATION), so we patch the
state machine itself and record every frame as it flows through.

Design choices:
  - Defensive: the `h2` / `hyperframe` packages may version-skew; if a method
    we need isn't present, we log a warning and continue without the tap
    rather than crash mitmproxy.
  - Connection identity: we use `id(h2_connection_instance)` as a stable key
    and mint a connection_id the first time we see it. The addon correlates
    this to the TLS connection via a parallel weak-key map.
  - Thread safety: all writes go through a single sqlite connection in the
    addon; this module just emits events via a callback.
"""

from __future__ import annotations

import logging
import time
from dataclasses import dataclass
from typing import Any, Callable, Protocol

log = logging.getLogger("h2_tap")


class FrameSink(Protocol):
    """Callback the addon provides. Called once per frame in either direction."""
    def __call__(self, *, conn_key: int, direction: str, frame_type: str,
                 stream_id: int | None, flags: int, length: int,
                 payload: dict[str, Any]) -> None: ...


@dataclass
class _PatchResult:
    installed: bool
    reason: str = ""


def _frame_payload_summary(frame: Any) -> dict[str, Any]:
    """Extract a JSON-safe summary from a hyperframe Frame."""
    name = type(frame).__name__
    out: dict[str, Any] = {"frame": name}

    # Common attrs across frames
    for attr in ("flags", "stream_id", "length"):
        if hasattr(frame, attr):
            try:
                out[attr] = int(getattr(frame, attr) or 0)
            except Exception:
                pass

    if name == "HeadersFrame" or name == "ContinuationFrame" or name == "PushPromiseFrame":
        # `data` is the HPACK-encoded block. Don't include raw bytes — too noisy.
        data = getattr(frame, "data", b"") or b""
        out["hpack_size"] = len(data)
        if hasattr(frame, "depends_on"):
            out["depends_on"] = int(getattr(frame, "depends_on", 0) or 0)
        if hasattr(frame, "stream_weight"):
            out["weight"] = int(getattr(frame, "stream_weight", 0) or 0)
        if hasattr(frame, "promised_stream_id"):
            out["promised_stream_id"] = int(getattr(frame, "promised_stream_id", 0) or 0)
    elif name == "DataFrame":
        data = getattr(frame, "data", b"") or b""
        out["bytes"] = len(data)
        # Preview the first 128 bytes of payload when it looks text-ish; otherwise skip.
        try:
            if data and all(32 <= b < 127 or b in (9, 10, 13) for b in data[:64]):
                out["preview"] = data[:128].decode("utf-8", errors="replace")
        except Exception:
            pass
    elif name == "WindowUpdateFrame":
        out["window_increment"] = int(getattr(frame, "window_increment", 0) or 0)
    elif name == "RstStreamFrame":
        out["error_code"] = int(getattr(frame, "error_code", 0) or 0)
    elif name == "GoAwayFrame":
        out["error_code"] = int(getattr(frame, "error_code", 0) or 0)
        out["last_stream_id"] = int(getattr(frame, "last_stream_id", 0) or 0)
        ad = getattr(frame, "additional_data", b"") or b""
        if ad:
            out["additional_data_size"] = len(ad)
    elif name == "PingFrame":
        data = getattr(frame, "opaque_data", b"") or b""
        out["opaque_hex"] = data.hex()
    elif name == "SettingsFrame":
        settings = getattr(frame, "settings", {}) or {}
        out["settings"] = {int(k): int(v) for k, v in settings.items()}
        out["ack"] = bool("ACK" in getattr(frame, "flags", set()))
    elif name == "PriorityFrame":
        out["depends_on"] = int(getattr(frame, "depends_on", 0) or 0)
        out["weight"] = int(getattr(frame, "stream_weight", 0) or 0)
        out["exclusive"] = bool(getattr(frame, "exclusive", False))
    elif name == "AltSvcFrame":
        out["origin_size"] = len(getattr(frame, "origin", b"") or b"")
        out["field_size"] = len(getattr(frame, "field", b"") or b"")

    return out


def _frame_type_name(frame: Any) -> str:
    """Stable frame-type string. Drops the 'Frame' suffix from hyperframe classes."""
    n = type(frame).__name__
    return n[:-5].upper() if n.endswith("Frame") else n.upper()


def install(sink: FrameSink) -> _PatchResult:
    """Monkey-patch hyper-h2 so every frame hits `sink`.

    Returns a _PatchResult; `installed=False` means we fell back and no frames
    will flow. The caller (addon) should log this so the user knows h2 capture
    is degraded — request/response still works, just not frame-level detail.
    """
    try:
        import h2.connection as h2c
    except ImportError as e:
        return _PatchResult(False, f"h2 package not importable: {e!r}")

    H2C = getattr(h2c, "H2Connection", None)
    if H2C is None:
        return _PatchResult(False, "h2.connection.H2Connection not found")

    # We patch two methods:
    #   1. `_receive_frame(frame)` — called once per parsed incoming frame.
    #   2. `_prepare_for_sending(frame)` — called once per frame on the way out.
    # Both are internal to hyper-h2 but have been stable across 3.x / 4.x.
    recv_target = getattr(H2C, "_receive_frame", None)
    send_target = getattr(H2C, "_prepare_for_sending", None) or getattr(H2C, "_data_to_send", None)

    if recv_target is None:
        return _PatchResult(False, "H2Connection._receive_frame not found — h2 API changed?")

    if getattr(H2C, "_powhttp_patched", False):
        return _PatchResult(True, "already patched")

    _orig_recv = recv_target
    _orig_send = send_target

    def _tap(conn_self, frame, direction: str) -> None:
        try:
            summary = _frame_payload_summary(frame)
            sink(
                conn_key=id(conn_self),
                direction=direction,
                frame_type=_frame_type_name(frame),
                stream_id=summary.get("stream_id"),
                flags=summary.get("flags", 0),
                length=summary.get("length", 0) or summary.get("bytes", 0) or summary.get("hpack_size", 0),
                payload=summary,
            )
        except Exception as e:
            # Never let the tap break the proxy. Just log and move on.
            log.warning("h2_tap sink error: %r", e)

    def patched_receive_frame(self, frame, *args, **kwargs):
        # Defensive symmetry with patched_prepare — in practice `_receive_frame`
        # is per-frame in every h2 version we target, but guarding is cheap.
        try:
            if isinstance(frame, (list, tuple)):
                for f in frame:
                    _tap(self, f, "inbound")
            else:
                _tap(self, frame, "inbound")
        except Exception as e:
            log.warning("h2_tap inbound fan-out error: %r", e)
        return _orig_recv(self, frame, *args, **kwargs)

    H2C._receive_frame = patched_receive_frame

    if _orig_send is not None and _orig_send.__name__ == "_prepare_for_sending":
        # NB: In current hyper-h2 (4.x) `_prepare_for_sending` receives a *list*
        # of frames, not a single frame. Earlier versions passed one frame at a
        # time. Handle both so the tap reports proper per-frame type names
        # instead of lumping everything under the class name "list".
        def patched_prepare(self, frame_or_frames, *args, **kwargs):
            try:
                if isinstance(frame_or_frames, (list, tuple)):
                    for f in frame_or_frames:
                        _tap(self, f, "outbound")
                else:
                    _tap(self, frame_or_frames, "outbound")
            except Exception as e:
                log.warning("h2_tap outbound fan-out error: %r", e)
            return _orig_send(self, frame_or_frames, *args, **kwargs)
        H2C._prepare_for_sending = patched_prepare
    else:
        # Older hyper-h2: no _prepare_for_sending. Outbound frames are assembled
        # in `data_to_send` from per-method calls. We patch the individual sender
        # methods as a best-effort — this covers the common frame types.
        try:
            import hyperframe.frame as hf

            def _wrap_emit(method_name: str, frame_cls_name: str):
                method = getattr(H2C, method_name, None)
                if not method:
                    return

                def wrapper(self, *args, **kwargs):
                    result = method(self, *args, **kwargs)
                    try:
                        # Best-effort reconstruction of the frame just emitted.
                        cls = getattr(hf, frame_cls_name, None)
                        if cls:
                            # We don't have the exact frame, but we know the type.
                            stream_id = kwargs.get("stream_id") or (args[0] if args else None)
                            sink(
                                conn_key=id(self),
                                direction="outbound",
                                frame_type=frame_cls_name.replace("Frame", "").upper(),
                                stream_id=int(stream_id) if stream_id is not None else None,
                                flags=0,
                                length=0,
                                payload={"frame": frame_cls_name, "synthetic": True},
                            )
                    except Exception:
                        pass
                    return result

                setattr(H2C, method_name, wrapper)

            _wrap_emit("send_headers", "HeadersFrame")
            _wrap_emit("send_data", "DataFrame")
            _wrap_emit("reset_stream", "RstStreamFrame")
            _wrap_emit("ping", "PingFrame")
            _wrap_emit("increment_flow_control_window", "WindowUpdateFrame")
            _wrap_emit("close_connection", "GoAwayFrame")
        except Exception as e:
            log.warning("outbound h2 tap fallback failed: %r", e)

    H2C._powhttp_patched = True
    return _PatchResult(True, "patched h2.connection.H2Connection")
