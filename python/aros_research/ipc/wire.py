"""Minimal protobuf wire codec for AROS Envelope Hello/HelloAck/Error.

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


@dataclass(frozen=True)
class Hello:
    worker_kind: str
    python_version: str


def encode_hello(hello: Hello, request_id: str = "hello") -> bytes:
    inner = _str(1, hello.worker_kind) + _str(2, hello.python_version)
    env = _var(1, PROTOCOL_VERSION) + _str(2, request_id) + _ld(10, inner)
    return encode_frame(env)


def encode_error(code: str, message: str, request_id: str = "err") -> bytes:
    inner = _str(1, code) + _str(2, message)
    env = _var(1, PROTOCOL_VERSION) + _str(2, request_id) + _ld(15, inner)
    return encode_frame(env)
