# Adding a model provider

Implement a Python adapter that:

- talks OpenAI-compatible HTTP to a local `base_url`, or
- is `DeterministicMockProvider` for tests.

Never print API keys. Never put secrets in research containers.
Paid remote APIs are optional and not required for MVP.
