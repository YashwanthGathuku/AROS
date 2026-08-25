# Epistemic graph

Facts and beliefs are distinguished by `EpistemicState`.
LLM output may create `HYPOTHESIZED` / `CLAIMED` nodes only.
`VERIFIED` is produced by the verifier + evidence authority.

Storage: SQLite canonical + in-memory `petgraph` (`ActiveGraph`).
