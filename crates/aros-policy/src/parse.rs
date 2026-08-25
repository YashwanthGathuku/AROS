use std::path::Path;

use aros_types::AuthorizationManifest;

use crate::error::{PolicyError, Result};

pub fn load_manifest_from_str(text: &str) -> Result<AuthorizationManifest> {
    let trimmed = text.trim_start();
    if trimmed.starts_with('{') {
        serde_json::from_str(trimmed).map_err(|e| PolicyError::Parse(e.to_string()))
    } else {
        serde_yaml::from_str(text).map_err(|e| PolicyError::Parse(e.to_string()))
    }
}

pub fn load_manifest_from_path(path: &Path) -> Result<AuthorizationManifest> {
    let text = std::fs::read_to_string(path)?;
    load_manifest_from_str(&text)
}
