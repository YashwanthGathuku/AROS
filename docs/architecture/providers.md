# Providers

- Sandbox: `FakeSandboxProvider` (tests, never containing) and
  `RootlessOciSandboxProvider` (fail-closed until containment is demonstrated).
- Model: OpenAI-compatible local adapter planned; `DeterministicMockProvider` for tests.
- Harness: `NativeHarness` default; `GrokBuildHarness` capability-detected.
- Evidence authority: `BuiltinEvidenceAuthority`; `TheustadAdapter` optional.
