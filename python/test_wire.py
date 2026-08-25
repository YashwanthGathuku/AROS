from aros_research.ipc.wire import Hello, encode_hello, encode_tool_intent


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
