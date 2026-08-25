# ADR-0002: Framed Protobuf over Unix domain sockets

- Status: Accepted
- Date: 2026-08-25
- Specs: `docs/TECH_STACK.md` §§12, 30, 33

## Decision

IPC is length-prefixed Protobuf (`u32` big-endian length + payload), max
frame 4 MiB, protocol version 1, over Unix domain sockets.

gRPC is not used in v0.1. Unstructured shell/text is not a protocol.

## Alternatives

1. gRPC — extra runtime and surface; complexity not justified.
2. JSONL over stdin — weaker typing/bounding; rejected for privileged ops.
3. Embed Python — rejected by ADR-0001.

## Windows tests

Production IPC is Linux/WSL UDS. If Windows AF_UNIX is unreliable, a
loopback TCP test transport with a daemon-issued HMAC token may be added;
it is not a production sandbox path.
