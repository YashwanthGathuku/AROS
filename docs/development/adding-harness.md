# Adding a harness

`NativeHarness` is the default.

`GrokBuildHarness` is capability-detected (`grok` on PATH). If Grok cannot
be invoked in CI, keep the adapter, detection, a mock test, and these
enablement notes. The rest of AROS must not depend on Grok internals.
