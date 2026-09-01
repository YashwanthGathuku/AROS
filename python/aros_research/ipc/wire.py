"""Minimal protobuf wire codec for AROS Envelope Hello/HelloAck/ToolIntent/IntentResult.

Field numbers match proto/aros/v1/ipc.proto and the Rust prost types.
"""

from __future__ import annotations

from dataclasses import dataclass

from .framing import PROTOCOL_VERSION, encode_frame


def _uvarint(n: int) -> bytes:
    if n < 0:
        raise ValueError("varint must be non-negative")
    out = bytearray()
    while n > 0x7F:
        out.append((n & 0x7F) | 0x80)
        n >>= 7
    out.append(n)
    return bytes(out)


def _tag(field: int, wire: int) -> bytes:
    return _uvarint((field << 3) | wire)


def _ld(field: int, payload: bytes) -> bytes:
    return _tag(field, 2) + _uvarint(len(payload)) + payload


def _str(field: int, value: str) -> bytes:
    return _ld(field, value.encode("utf-8"))


def _var(field: int, value: int) -> bytes:
    return _tag(field, 0) + _uvarint(value)


def _read_varint(buf: bytes, i: int) -> tuple[int, int]:
    shift = 0
    result = 0
    while i < len(buf):
        b = buf[i]
        i += 1
        result |= (b & 0x7F) << shift
        if not (b & 0x80):
            return result, i
        shift += 7
        if shift > 63:
            raise ValueError("varint too long")
    raise ValueError("truncated varint")


def _parse_fields(buf: bytes) -> dict[int, list[bytes | int]]:
    """Parse a protobuf message into field_number -> list of values (bytes for LD, int for varint)."""
    fields: dict[int, list[bytes | int]] = {}
    i = 0
    while i < len(buf):
        key, i = _read_varint(buf, i)
        field = key >> 3
        wire = key & 7
        if wire == 0:
            val, i = _read_varint(buf, i)
            fields.setdefault(field, []).append(val)
        elif wire == 2:
            length, i = _read_varint(buf, i)
            payload = buf[i : i + length]
            i += length
            fields.setdefault(field, []).append(payload)
        else:
            raise ValueError(f"unsupported wire type {wire}")
    return fields


@dataclass(frozen=True)
class Hello:
    worker_kind: str
    python_version: str
    token: str = ""


@dataclass(frozen=True)
class IntentResult:
    decision: str
    reason: str
    exit_status: int | None = None
    stdout_digest: str | None = None
    request_id: str = ""


def encode_hello(hello: Hello, request_id: str = "hello") -> bytes:
    inner = _str(1, hello.worker_kind) + _str(2, hello.python_version)
    if hello.token:
        inner += _str(3, hello.token)
    env = _var(1, PROTOCOL_VERSION) + _str(2, request_id) + _ld(10, inner)
    return encode_frame(env)


def encode_tool_intent(
    capability: str,
    *,
    argv: list[str] | None = None,
    path: str | None = None,
    host: str | None = None,
    port: int | None = None,
    protocol: str | None = None,
    timeout_ms: int = 30_000,
    http_target: str | None = None,
    http_cookie: str | None = None,
    request_id: str = "intent",
) -> bytes:
    inner = _str(1, capability)
    for arg in argv or []:
        inner += _str(2, arg)
    if path:
        inner += _str(4, path)
    if host:
        inner += _str(5, host)
    if port is not None:
        inner += _var(6, port)
    if protocol:
        inner += _str(7, protocol)
    inner += _var(8, timeout_ms)
    if http_target:
        inner += _str(9, http_target)
    if http_cookie:
        inner += _str(10, http_cookie)
    env = _var(1, PROTOCOL_VERSION) + _str(2, request_id) + _ld(12, inner)
    return encode_frame(env)


def encode_error(code: str, message: str, request_id: str = "err") -> bytes:
    inner = _str(1, code) + _str(2, message)
    env = _var(1, PROTOCOL_VERSION) + _str(2, request_id) + _ld(15, inner)
    return encode_frame(env)


def decode_envelope_payload(payload: bytes) -> tuple[str, str, dict[int, list[bytes | int]]]:
    """Return (request_id, kind_tag_hint, fields of the oneof message)."""
    fields = _parse_fields(payload)
    request_id = ""
    if 2 in fields and fields[2]:
        raw = fields[2][0]
        if isinstance(raw, bytes):
            request_id = raw.decode("utf-8", errors="replace")
    # oneof tags: 10 Hello, 11 HelloAck, 12 ToolIntent, 13 IntentResult, ...
    for tag in (10, 11, 12, 13, 14, 15, 16):
        if tag in fields and fields[tag]:
            inner = fields[tag][0]
            if isinstance(inner, bytes):
                return request_id, str(tag), _parse_fields(inner)
    return request_id, "0", {}


def decode_intent_result(payload: bytes) -> IntentResult:
    request_id, tag, inner = decode_envelope_payload(payload)
    if tag != "13":
        raise ValueError(f"expected IntentResult (tag 13), got tag {tag}")

    def _s(field: int) -> str:
        vals = inner.get(field) or []
        if not vals:
            return ""
        v = vals[0]
        return v.decode("utf-8", errors="replace") if isinstance(v, bytes) else str(v)

    def _i(field: int) -> int | None:
        vals = inner.get(field) or []
        if not vals:
            return None
        v = vals[0]
        return int(v) if isinstance(v, int) else None

    return IntentResult(
        decision=_s(1),
        reason=_s(2),
        exit_status=_i(3),
        stdout_digest=_s(4) or None,
        request_id=request_id,
    )
