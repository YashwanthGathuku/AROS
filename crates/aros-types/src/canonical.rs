use serde::Serialize;
use serde_json::Value;
use sha2::{Digest, Sha256};

use crate::error::Result;

/// Recursively sort object keys so hashes are independent of field insertion order.
pub fn canonicalize_value(value: &Value) -> Value {
    match value {
        Value::Object(map) => {
            let mut keys: Vec<&String> = map.keys().collect();
            keys.sort_unstable();
            let mut out = serde_json::Map::with_capacity(keys.len());
            for key in keys {
                if let Some(v) = map.get(key) {
                    out.insert(key.clone(), canonicalize_value(v));
                }
            }
            Value::Object(out)
        }
        Value::Array(items) => Value::Array(items.iter().map(canonicalize_value).collect()),
        other => other.clone(),
    }
}

pub fn to_canonical_json<T: Serialize>(value: &T) -> Result<Vec<u8>> {
    let as_value = serde_json::to_value(value)?;
    let canonical = canonicalize_value(&as_value);
    Ok(serde_json::to_vec(&canonical)?)
}

pub fn blake3_hex(bytes: &[u8]) -> String {
    blake3::hash(bytes).to_hex().to_string()
}

pub fn sha256_hex(bytes: &[u8]) -> String {
    let digest = Sha256::digest(bytes);
    hex::encode(digest)
}

pub fn hash_canonical<T: Serialize>(value: &T) -> Result<DigestPair> {
    let bytes = to_canonical_json(value)?;
    Ok(DigestPair {
        blake3: blake3_hex(&bytes),
        sha256: sha256_hex(&bytes),
        canonical_len: bytes.len() as u64,
    })
}

#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct DigestPair {
    pub blake3: String,
    pub sha256: String,
    pub canonical_len: u64,
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use serde::Serialize;

    #[derive(Serialize)]
    struct Sample {
        b: u8,
        a: u8,
    }

    #[test]
    fn field_order_does_not_change_hash() {
        #[derive(Serialize)]
        struct Other {
            a: u8,
            b: u8,
        }
        let left = hash_canonical(&Sample { b: 2, a: 1 }).unwrap();
        let right = hash_canonical(&Other { a: 1, b: 2 }).unwrap();
        assert_eq!(left.blake3, right.blake3);
        assert_eq!(left.sha256, right.sha256);
    }

    #[test]
    fn canonical_json_sorts_nested_keys() {
        let v: Value = serde_json::from_str(r#"{"z":{"b":1,"a":2},"m":true}"#).unwrap();
        let canonical = canonicalize_value(&v);
        let s = serde_json::to_string(&canonical).unwrap();
        assert_eq!(s, r#"{"m":true,"z":{"a":2,"b":1}}"#);
    }
}
