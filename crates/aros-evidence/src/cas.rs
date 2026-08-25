use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};

use aros_types::{blake3_hex, sha256_hex, EvidenceArtifact};
use thiserror::Error;
use uuid::Uuid;

#[derive(Debug, Error)]
pub enum CasError {
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),
    #[error("artifact not found: {0}")]
    NotFound(String),
    #[error("digest mismatch")]
    DigestMismatch,
    #[error("artifact exceeds max size {0} bytes")]
    TooLarge(u64),
}

#[derive(Clone, Debug)]
pub struct ContentAddressedStore {
    root: PathBuf,
    max_bytes: u64,
}

impl ContentAddressedStore {
    pub fn open(root: impl Into<PathBuf>, max_bytes: u64) -> Result<Self, CasError> {
        let root = root.into();
        fs::create_dir_all(root.join("blake3"))?;
        Ok(Self { root, max_bytes })
    }

    fn blob_path(&self, digest: &str) -> PathBuf {
        let prefix = digest.get(0..2).unwrap_or("00");
        self.root.join("blake3").join(prefix).join(digest)
    }

    pub fn put(&self, bytes: &[u8], media_type: &str) -> Result<EvidenceArtifact, CasError> {
        if bytes.len() as u64 > self.max_bytes {
            return Err(CasError::TooLarge(self.max_bytes));
        }
        let digest = blake3_hex(bytes);
        let sha = sha256_hex(bytes);
        let path = self.blob_path(&digest);
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)?;
        }
        if !path.exists() {
            let tmp = path.with_extension(format!("tmp-{}", Uuid::new_v4()));
            {
                let mut file = fs::File::create(&tmp)?;
                file.write_all(bytes)?;
                file.sync_all()?;
            }
            fs::rename(tmp, &path)?;
        }
        Ok(EvidenceArtifact {
            id: aros_types::ArtifactId::new(),
            digest_blake3: digest,
            digest_sha256: sha,
            media_type: media_type.to_string(),
            byte_len: bytes.len() as u64,
        })
    }

    pub fn get(&self, digest: &str) -> Result<Vec<u8>, CasError> {
        let path = self.blob_path(digest);
        let bytes = fs::read(&path).map_err(|_| CasError::NotFound(digest.to_string()))?;
        let actual = blake3_hex(&bytes);
        if actual != digest {
            return Err(CasError::DigestMismatch);
        }
        Ok(bytes)
    }

    pub fn exists(&self, digest: &str) -> bool {
        self.blob_path(digest).is_file()
    }

    pub fn root(&self) -> &Path {
        &self.root
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn put_get_roundtrip_and_filename_is_not_identity() {
        let dir = tempfile::tempdir().unwrap();
        let cas = ContentAddressedStore::open(dir.path(), 1024 * 1024).unwrap();
        let art = cas.put(b"hello-aros", "text/plain").unwrap();
        assert_ne!(art.digest_blake3, "hello-aros");
        let got = cas.get(&art.digest_blake3).unwrap();
        assert_eq!(got, b"hello-aros");
    }

    #[test]
    fn rejects_oversized() {
        let dir = tempfile::tempdir().unwrap();
        let cas = ContentAddressedStore::open(dir.path(), 4).unwrap();
        let err = cas.put(b"too-big", "text/plain").unwrap_err();
        assert!(matches!(err, CasError::TooLarge(4)));
    }
}
