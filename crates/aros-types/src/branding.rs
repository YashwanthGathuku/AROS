//! Centralized product identity and compatibility names.
//!
//! Keep user-facing/default names here so a future project rename is a small,
//! reviewable change. Cargo package/crate names and existing environment names
//! remain compatibility API for v0.1 and can be migrated separately.

pub const PRODUCT_NAME: &str = "AROS";
pub const PRODUCT_DESCRIPTION: &str = "Autonomous adversarial security research platform";
pub const BINARY_NAME: &str = "aros";
pub const DAEMON_NAME: &str = "arosd";
pub const VERIFIER_NAME: &str = "aros-verifier";
pub const WORKER_NAME: &str = "aros-research-worker";
pub const WORKSPACE_DIR: &str = ".aros";
pub const DATABASE_FILE: &str = "aros.db";
/// Current/legacy environment prefix. Preserve as an alias during any rename.
pub const ENV_PREFIX: &str = "AROS";

/// Stable machine/protocol identifier. Do not derive persistence/protocol
/// compatibility from the display name; renaming the product must not corrupt
/// existing evidence or make old manifests unreadable.
pub const PROTOCOL_NAMESPACE: &str = "aros.v1";

pub fn env_name(suffix: &str) -> String {
    format!("{ENV_PREFIX}_{suffix}")
}
