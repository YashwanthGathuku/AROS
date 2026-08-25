from aros_research.ipc.framing import IpcError, decode_header, encode_frame


def test_frame_roundtrip() -> None:
    payload = b"hello"
    framed = encode_frame(payload)
    length = decode_header(framed[:4])
    assert length == 5
    assert framed[4:] == payload


def test_reject_oversized() -> None:
    try:
        encode_frame(b"x" * 10, max_frame=4)
        raise AssertionError("should have failed")
    except IpcError:
        pass
