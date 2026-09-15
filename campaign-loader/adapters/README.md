# AROS target adapters

Per-project API glue lives here, not in the target tree.

A catalog id is a directory with `run.py`. The engine stages that directory
next to the pinned checkout and runs `generator.command` with `{harness}`.

`dycrpt-lib` path-depends on `voicechat_crypto` (the dycrpt crate name) and
calls `VoiceChatCryptoEngine::decrypt` (the receive/`open` path). It writes
nothing into dycrpt.
