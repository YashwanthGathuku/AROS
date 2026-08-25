from aros_research.ipc.wire import Hello, encode_hello


def test_hello_frame_has_length_prefix() -> None:
    framed = encode_hello(Hello(worker_kind="research", python_version="3.14.7"))
    length = int.from_bytes(framed[:4], "big")
    assert length == len(framed) - 4
    assert length > 0
    assert length < 4 * 1024 * 1024
