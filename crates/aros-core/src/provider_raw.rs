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

/// Store one returned provider stream. The bytes stay raw. This is not evidence.
pub fn address_provider_stream(
    store: &Store,
    cas: &ContentAddressedStore,
    provider: &str,
    campaign_id: CampaignId,
    correlation_id: &str,
    stream: &str,
    bytes: &[u8],
) -> Result<AddressedProvider, ProviderRawError> {
    if stream != "stdout" && stream != "stderr" {
        return Err(ProviderRawError::Rejected(
            "provider stream must be stdout or stderr".into(),
        ));
    }
    let provider = require_provider_label(provider)?;
    let correlation_id = require_correlation_id(correlation_id)?;
    let artifact = cas.put(bytes, "application/octet-stream")?;
    let record = serde_json::json!({
        "provider": provider,
        "campaign_id": campaign_id.to_string(),
        "correlation_id": correlation_id,
        "stream": stream,
        "digest_blake3": artifact.digest_blake3,
        "digest_sha256": artifact.digest_sha256,
        "byte_len": artifact.byte_len,
        "media_type": artifact.media_type,
    });
    store.put_record(
        PROVIDER_RAW_KIND,
        &format!("{provider}:{stream}:{}", artifact.digest_blake3),
        &record.to_string(),
    )?;
    Ok(AddressedProvider {
        digest_blake3: artifact.digest_blake3,
        digest_sha256: artifact.digest_sha256,
        byte_len: artifact.byte_len,
    })
}

pub fn require_provider_label(provider: &str) -> Result<String, ProviderRawError> {
    let provider = provider.trim();
    if provider.is_empty() || provider.len() > 64 {
        return Err(ProviderRawError::Rejected(
            "provider name must be 1 to 64 characters".into(),
        ));
    }
    if !provider
        .chars()
        .all(|ch| ch.is_ascii_alphanumeric() || matches!(ch, '.' | '_' | '-'))
    {
        return Err(ProviderRawError::Rejected(
            "provider name must be ascii letters, digits, or . _ -".into(),
        ));
    }
    Ok(provider.to_string())
}
