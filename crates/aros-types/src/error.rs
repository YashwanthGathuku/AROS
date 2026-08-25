use thiserror::Error;

#[derive(Debug, Error)]
pub enum TypesError {
    #[error("json serialization failed: {0}")]
    Json(#[from] serde_json::Error),
    #[error("invalid identifier: {0}")]
    InvalidId(String),
    #[error("invalid network specification: {0}")]
    InvalidNetwork(String),
    #[error("canonicalization failed: {0}")]
    Canonical(String),
}

pub type Result<T> = std::result::Result<T, TypesError>;
