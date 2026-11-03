//! Content-addressed raw provider bytes.
//!
//! The digest records what was submitted. It is not an evidence level and it
//! does not verify a finding.

use aros_evidence::ContentAddressedStore;
use aros_store::Store;
use aros_types::CampaignId;
use serde_json::Value;
use thiserror::Error;

pub const PROVIDER_RAW_KIND: &str = "provider_raw";

#[derive(Debug, Error)]
pub enum ProviderRawError {
    #[error("{0}")]
    Rejected(String),
    #[error("store: {0}")]
    Store(#[from] aros_store::StoreError),
    #[error("json: {0}")]
    Json(#[from] serde_json::Error),
    #[error("cas: {0}")]
    Cas(#[from] aros_evidence::CasError),
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AddressedProvider {
    pub digest_blake3: String,
    pub digest_sha256: String,
    pub byte_len: u64,
}

pub fn require_correlation_id(raw: &str) -> Result<String, ProviderRawError> {
    let id = raw.trim();
    if id.is_empty() || id.len() > 64 {
        return Err(ProviderRawError::Rejected(
            "correlation id must be 1 to 64 characters".into(),
        ));
    }
    if !id
        .chars()
        .all(|ch| ch.is_ascii_alphanumeric() || matches!(ch, '.' | '_' | '-'))
    {
        return Err(ProviderRawError::Rejected(
            "correlation id must be ascii letters, digits, or . _ -".into(),
        ));
    }
    Ok(id.to_string())
}

/// A provider line may omit the id. A present id must equal the caller id.
pub fn provider_correlation_ok(payload: &Value, expected: &str) -> bool {
    for key in ["correlation_id", "run_id", "correlation"] {
        match payload.get(key) {
            None => {}
            Some(Value::String(text)) => {
                let trimmed = text.trim();
                if trimmed.is_empty() || trimmed != expected {
                    return false;
                }
            }
            Some(_) => return false,
        }
    }
    true
}

pub fn address_provider_bytes(
    store: &Store,
    cas: &ContentAddressedStore,
    provider: &str,
    campaign_id: CampaignId,
    correlation_id: &str,
    bytes: &[u8],
) -> Result<AddressedProvider, ProviderRawError> {
    let correlation_id = require_correlation_id(correlation_id)?;
    let artifact = cas.put(bytes, "application/x-ndjson")?;
    let record = serde_json::json!({
        "provider": provider,
        "campaign_id": campaign_id.to_string(),
        "correlation_id": correlation_id,
        "digest_blake3": artifact.digest_blake3,
        "digest_sha256": artifact.digest_sha256,
        "byte_len": artifact.byte_len,
        "media_type": artifact.media_type,
    });
    store.put_record(
        PROVIDER_RAW_KIND,
        &format!("{provider}:{}", artifact.digest_blake3),
        &record.to_string(),
    )?;
    Ok(AddressedProvider {
        digest_blake3: artifact.digest_blake3,
        digest_sha256: artifact.digest_sha256,
        byte_len: artifact.byte_len,
    })
}
