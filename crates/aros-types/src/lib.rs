//! Shared AROS domain types. No I/O, no policy decisions, no sandboxing.

#![forbid(unsafe_code)]

pub mod branding;
pub mod canonical;
pub mod domain;
pub mod enums;
pub mod error;
pub mod events;
pub mod ids;
pub mod manifest;
pub mod time;
pub mod tool;

pub use branding::{
    BINARY_NAME, DAEMON_NAME, DATABASE_FILE, ENV_PREFIX, PRODUCT_NAME, PROTOCOL_NAMESPACE,
    VERIFIER_NAME, WORKER_NAME, WORKSPACE_DIR,
};
pub use canonical::{blake3_hex, hash_canonical, sha256_hex, to_canonical_json, DigestPair};
pub use domain::*;
pub use enums::*;
pub use error::{Result, TypesError};
pub use events::{EventRecord, ResearchEvent};
pub use ids::*;
pub use manifest::{AllowedEndpoint, ArtifactPolicy, AuthorizationManifest, ResourceBudgets};
pub use time::unix_now_ms;
pub use tool::{ExecutionReceipt, NetworkIntent, ToolCapability, ToolIntent};
