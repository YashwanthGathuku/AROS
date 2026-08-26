# Product identity and future rename seam

AROS is the current product identity, but product naming is not a persistence or protocol invariant.

Runtime identity defaults are centralized in `crates/aros-types/src/branding.rs`. New user-visible product names, executable defaults, workspace names, database filenames, environment prefixes, and protocol namespace decisions should be introduced through that layer rather than scattered literals.

Cargo crate names and the Python package name remain stable compatibility APIs for v0.1. A future product rename should use aliases and migrations rather than rewriting stored evidence. Persisted evidence must rely on schema versions, UUIDs, hashes, and protocol versions, never the display product name.

The protocol namespace is intentionally separate from the display name so a product rename does not invalidate old manifests, evidence bundles, ledgers, or replay artifacts.
