"""Length-prefixed Protobuf-compatible framing (u32 BE + payload)."""

from __future__ import annotations

MAX_FRAME = 4 * 1024 * 1024
PROTOCOL_VERSION = 1


class IpcError(Exception):
    pass


def encode_frame(payload: bytes, max_frame: int = MAX_FRAME) -> bytes:
    if len(payload) > max_frame:
        raise IpcError(f"frame too large: {len(payload)} > {max_frame}")
    return len(payload).to_bytes(4, "big") + payload


def decode_header(header: bytes, max_frame: int = MAX_FRAME) -> int:
    if len(header) != 4:
        raise IpcError("header must be 4 bytes")
    length = int.from_bytes(header, "big")
    if length > max_frame or length == 0:
        raise IpcError(f"invalid length {length}")
    return length
