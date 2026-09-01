from aros_research.ipc.framing import encode_frame
from aros_research.ipc.wire import (
    Hello,
    decode_intent_result,
    encode_hello,
    encode_tool_intent,
)


def test_hello_frame_has_length_prefix() -> None:
    framed = encode_hello(Hello(worker_kind="research", python_version="3.14.7"))
    length = int.from_bytes(framed[:4], "big")
    assert length == len(framed) - 4
    assert length > 0
    assert length < 4 * 1024 * 1024


def test_tool_intent_frame() -> None:
    framed = encode_tool_intent("read_file", path="/tmp/target/x")
    length = int.from_bytes(framed[:4], "big")
    assert length == len(framed) - 4
    assert b"read_file" in framed


def test_http_tool_intent_uses_typed_target() -> None:
    framed = encode_tool_intent(
        "http_request",
        host="127.0.0.1",
        port=18080,
        http_target="/files?path=../secret.txt",
        http_cookie="user=1",
    )
    assert b"http_request" in framed
    assert b"/files?path=../secret.txt" in framed
    assert b"user=1" in framed


def test_intent_result_decode() -> None:
    # Manually build a minimal IntentResult envelope matching Rust prost tags.
    # tag 13 = IntentResult; fields decision=1, reason=2
    def uvarint(n: int) -> bytes:
        out = bytearray()
        while n > 0x7F:
            out.append((n & 0x7F) | 0x80)
            n >>= 7
        out.append(n)
        return bytes(out)

    def ld(field: int, payload: bytes) -> bytes:
        return uvarint((field << 3) | 2) + uvarint(len(payload)) + payload

    def s(field: int, value: str) -> bytes:
        return ld(field, value.encode("utf-8"))

    inner = s(1, "DENY") + s(2, "capability not allowlisted")
    env = uvarint((1 << 3) | 0) + uvarint(1)  # protocol_version=1
    env += s(2, "req-42")
    env += ld(13, inner)
    framed = encode_frame(env)
    payload = framed[4:]
    result = decode_intent_result(payload)
    assert result.decision == "DENY"
    assert "allowlist" in result.reason
    assert result.request_id == "req-42"
