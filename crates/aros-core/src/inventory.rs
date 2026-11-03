//! Bumblebee NDJSON ingestion into the campaign graph.
//!
//! This parses bytes the caller already captured. It does not execute Bumblebee
//! or walk the target tree. The raw bytes are content-addressed. A package,
//! component, or dependency becomes an observed Target Reality fact only when its
//! path is a safe relative path inside the caller-supplied snapshot set. An
//! exposure, finding, or lead stays a hypothesized research lead.

use std::collections::BTreeSet;

use aros_evidence::ContentAddressedStore;
use aros_store::Store;
use aros_types::{unix_now_ms, CampaignId, EpistemicState, GraphKind, GraphNode, NodeId};
use thiserror::Error;

use crate::provider_output::parse_ndjson;
use crate::provider_raw::{
    address_provider_bytes, provider_correlation_ok, require_correlation_id,
};

const MAX_FIELD: usize = 256;
const MAX_PATH: usize = 512;

#[derive(Debug, Error)]
pub enum InventoryError {
    #[error("{0}")]
    Rejected(String),
    #[error("store: {0}")]
    Store(#[from] aros_store::StoreError),
    #[error("json: {0}")]
    Json(#[from] serde_json::Error),
}

impl From<crate::provider_raw::ProviderRawError> for InventoryError {
    fn from(value: crate::provider_raw::ProviderRawError) -> Self {
        match value {
            crate::provider_raw::ProviderRawError::Rejected(message) => Self::Rejected(message),
            crate::provider_raw::ProviderRawError::Store(error) => Self::Store(error),
            crate::provider_raw::ProviderRawError::Json(error) => Self::Json(error),
            crate::provider_raw::ProviderRawError::Cas(error) => Self::Rejected(error.to_string()),
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct InventoryIngest {
    pub observed: usize,
    pub leads: usize,
    pub skipped: usize,
    pub rejected_lines: usize,
    pub truncated: bool,
    pub digest_blake3: String,
}

pub fn ingest_bumblebee_ndjson(
    store: &Store,
    cas: &ContentAddressedStore,
    campaign_id: CampaignId,
    correlation_id: &str,
    bytes: &[u8],
    snapshot_paths: &BTreeSet<String>,
) -> Result<InventoryIngest, InventoryError> {
    let correlation_id = require_correlation_id(correlation_id)?;
    let (records, summary) = parse_ndjson("bumblebee", bytes).map_err(InventoryError::Rejected)?;
    let addressed =
        address_provider_bytes(store, cas, "bumblebee", campaign_id, &correlation_id, bytes)?;
    let tied = normalized_snapshot(snapshot_paths);
    let mut observed = 0usize;
    let mut leads = 0usize;
    let mut skipped = 0usize;
    let created_unix_ms = unix_now_ms();
    for record in records {
        if !provider_correlation_ok(&record.payload, &correlation_id) {
            skipped += 1;
            continue;
        }
        let kind = record.record_type.trim();
        if matches!(kind, "component" | "package" | "dependency") {
            let Some(path) = record
                .payload
                .get("path")
                .or_else(|| record.payload.get("file"))
                .or_else(|| record.payload.get("location"))
                .and_then(|value| value.as_str())
                .and_then(safe_relative_path)
            else {
                skipped += 1;
                continue;
            };
            if !tied.contains(&path) {
                skipped += 1;
                continue;
            }
            store.put_graph_node(&inventory_node(
                campaign_id,
                kind,
                &path,
                &record.payload,
                &correlation_id,
                &addressed.digest_blake3,
                created_unix_ms,
            ))?;
            observed += 1;
        } else if matches!(kind, "finding" | "exposure" | "lead") {
            store.put_graph_node(&lead_node(
                campaign_id,
                kind,
                &record.payload,
                &correlation_id,
                &addressed.digest_blake3,
                created_unix_ms,
            ))?;
            leads += 1;
        } else {
            skipped += 1;
        }
    }
    Ok(InventoryIngest {
        observed,
        leads,
        skipped,
        rejected_lines: summary.rejected_lines,
        truncated: summary.truncated,
        digest_blake3: addressed.digest_blake3,
    })
}

fn inventory_node(
    campaign_id: CampaignId,
    kind: &str,
    path: &str,
    payload: &serde_json::Value,
    correlation_id: &str,
    digest: &str,
    created_unix_ms: u64,
) -> GraphNode {
    let name = text_field(payload, &["name"]);
    let version = provider_tool_version(payload);
    let label = name.clone().unwrap_or_else(|| path.to_string());
    GraphNode {
        id: NodeId::new(),
        campaign_id,
        graph: GraphKind::TargetReality,
        kind: kind.to_string(),
        label,
        epistemic: EpistemicState::Observed,
        payload: bounded_object(&[
            ("name", name),
            ("version", text_field(payload, &["version"])),
            ("ecosystem", text_field(payload, &["ecosystem"])),
            ("path", Some(path.to_string())),
            ("purl", text_field(payload, &["purl"])),
            ("provider", Some("bumblebee".into())),
            ("provider_version", version.clone()),
            ("correlation_id", Some(correlation_id.to_string())),
        ]),
        provenance: provenance(version.as_deref()),
        artifact_refs: vec![digest.to_string()],
        created_unix_ms,
    }
}

fn lead_node(
    campaign_id: CampaignId,
    record_type: &str,
    payload: &serde_json::Value,
    correlation_id: &str,
    digest: &str,
    created_unix_ms: u64,
) -> GraphNode {
    let title = text_field(payload, &["title", "name", "summary"]);
    let id = text_field(payload, &["id"]);
    let version = provider_tool_version(payload);
    let label = title
        .clone()
        .or_else(|| id.clone())
        .unwrap_or_else(|| "lead".into());
    GraphNode {
        id: NodeId::new(),
        campaign_id,
        graph: GraphKind::Research,
        kind: "lead".into(),
        label,
        epistemic: EpistemicState::Hypothesized,
        payload: bounded_object(&[
            ("record_type", Some(record_type.to_string())),
            ("id", id),
            ("title", title),
            ("provider", Some("bumblebee".into())),
            ("provider_version", version.clone()),
            ("correlation_id", Some(correlation_id.to_string())),
        ]),
        provenance: provenance(version.as_deref()),
        artifact_refs: vec![digest.to_string()],
        created_unix_ms,
    }
}

fn bounded_object(fields: &[(&str, Option<String>)]) -> serde_json::Value {
    let mut map = serde_json::Map::new();
    for (key, value) in fields {
        if let Some(text) = value {
            map.insert((*key).to_string(), serde_json::Value::String(text.clone()));
        }
    }
    serde_json::Value::Object(map)
}

fn text_field(payload: &serde_json::Value, keys: &[&str]) -> Option<String> {
    for key in keys {
        if let Some(text) = payload.get(*key).and_then(|value| value.as_str()) {
            let trimmed = text.trim();
            if trimmed.is_empty() {
                continue;
            }
            return Some(trimmed.chars().take(MAX_FIELD).collect());
        }
    }
    None
}

fn provider_tool_version(payload: &serde_json::Value) -> Option<String> {
    let raw = text_field(payload, &["tool_version", "scanner_version"])?;
    if raw.len() <= 64
        && raw
            .chars()
            .all(|ch| ch.is_ascii_alphanumeric() || matches!(ch, '.' | '-' | '+' | '_'))
    {
        Some(raw)
    } else {
        None
    }
}

fn provenance(version: Option<&str>) -> String {
    match version {
        Some(version) => format!("provider:bumblebee@{version}"),
        None => "provider:bumblebee".to_string(),
    }
}

fn normalized_snapshot(paths: &BTreeSet<String>) -> BTreeSet<String> {
    paths
        .iter()
        .filter_map(|path| safe_relative_path(path))
        .collect()
}

fn safe_relative_path(raw: &str) -> Option<String> {
    let trimmed = raw.trim();
    if trimmed.is_empty() || trimmed.len() > MAX_PATH {
        return None;
    }
    let slash = trimmed.replace('\\', "/");
    if slash.starts_with('/') {
        return None;
    }
    let bytes = slash.as_bytes();
    if bytes.len() >= 2 && bytes[0].is_ascii_alphabetic() && bytes[1] == b':' {
        return None;
    }
    let mut parts = Vec::new();
    for part in slash.split('/') {
        if part.is_empty() || part == "." {
            continue;
        }
        if part == ".." || part.contains(':') || part.contains('\0') {
            return None;
        }
        parts.push(part);
    }
    if parts.is_empty() {
        return None;
    }
    let path = parts.join("/");
    if path.len() > MAX_PATH {
        None
    } else {
        Some(path)
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;
    use crate::graph::ActiveGraph;

    #[test]
    fn tied_inventory_is_observed_and_exposure_stays_a_lead() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("aros.db");
        let campaign = CampaignId::new();
        let input = br#"{"record_type":"component","ecosystem":"pypi","name":"demo","version":"1.2.3","path":"src/./parse.py","purl":"pkg:pypi/demo@1.2.3","verified":true,"evidence_level":"E7","tool_version":"0.9.1","run_id":"run-1"}
{"type":"dependency","name":"left-pad","path":"vendor\\left-pad"}
{"record_type":"component","name":"outside","path":"../etc/passwd","verified":true}
{"record_type":"package","name":"loose","version":"9","path":"not/in/snapshot.py"}
{"record_type":"component","name":"drive","path":"C:\\Windows\\system32\\cmd.exe"}
{"record_type":"package","name":"foreign","path":"vendor/left-pad","run_id":"other"}
{"record_type":"finding","id":"lead-1","title":"maybe","verified":true,"evidence_level":"E7","path":"src/parse.py"}
{"record_type":"exposure","id":"lead-2","title":"catalog match"}
{"record_type":"note","text":"ignore"}
not-json
"#;
        let mut snapshot = BTreeSet::new();
        snapshot.insert("src\\parse.py".into());
        snapshot.insert("vendor/left-pad".into());
        snapshot.insert("C:/Windows/system32/cmd.exe".into());
        snapshot.insert("../etc/passwd".into());
        let summary = {
            let store = Store::open(&path).unwrap();
            let cas = ContentAddressedStore::open(dir.path().join("cas"), 8 * 1024 * 1024).unwrap();
            ingest_bumblebee_ndjson(&store, &cas, campaign, "run-1", input, &snapshot).unwrap()
        };
        assert_eq!(summary.observed, 2);
        assert_eq!(summary.leads, 2);
        assert_eq!(summary.skipped, 5);
        assert_eq!(summary.rejected_lines, 1);
        assert!(!summary.truncated);
        let store = Store::open(&path).unwrap();
        let nodes = store.load_graph_nodes(campaign).unwrap();
        assert_eq!(nodes.len(), 4);
        let component = nodes.iter().find(|node| node.kind == "component").unwrap();
        assert_eq!(component.graph, GraphKind::TargetReality);
        assert_eq!(component.epistemic, EpistemicState::Observed);
        assert!(component.epistemic.is_established_fact());
        assert_eq!(component.provenance, "provider:bumblebee@0.9.1");
        assert_eq!(component.payload["path"], "src/parse.py");
        assert_eq!(component.payload["name"], "demo");
        assert_eq!(component.payload["version"], "1.2.3");
        assert!(component.payload.get("verified").is_none());
        assert!(component.payload.get("evidence_level").is_none());
        assert_eq!(component.payload["correlation_id"], "run-1");
        assert_eq!(component.artifact_refs, vec![summary.digest_blake3.clone()]);
        let dependency = nodes.iter().find(|node| node.kind == "dependency").unwrap();
        assert_eq!(dependency.payload["path"], "vendor/left-pad");
        assert_eq!(dependency.epistemic, EpistemicState::Observed);
        let lead_nodes: Vec<_> = nodes.iter().filter(|node| node.kind == "lead").collect();
        assert_eq!(lead_nodes.len(), 2);
        for lead in lead_nodes {
            assert_eq!(lead.graph, GraphKind::Research);
            assert_eq!(lead.epistemic, EpistemicState::Hypothesized);
            assert!(!lead.epistemic.is_established_fact());
            assert!(lead.payload.get("verified").is_none());
            assert!(lead.payload.get("evidence_level").is_none());
        }
        let mut graph = ActiveGraph::new(campaign);
        for node in nodes {
            graph.add_node(node);
        }
        assert!(!graph.has_verified_finding());
        let cas = ContentAddressedStore::open(dir.path().join("cas"), 8 * 1024 * 1024).unwrap();
        assert_eq!(cas.get(&summary.digest_blake3).unwrap(), input);
        let raw = store
            .list_records(crate::provider_raw::PROVIDER_RAW_KIND)
            .unwrap();
        assert_eq!(raw.len(), 1);
        let record: serde_json::Value = serde_json::from_str(&raw[0].1).unwrap();
        assert_eq!(record["provider"], "bumblebee");
        assert_eq!(record["correlation_id"], "run-1");
        assert_eq!(record["digest_blake3"], summary.digest_blake3);
        assert!(record.get("verified").is_none());
        assert!(record.get("evidence_level").is_none());
        assert!(record.get("finding_id").is_none());
    }

    #[test]
    fn invalid_ndjson_writes_nothing() {
        let dir = tempfile::tempdir().unwrap();
        let store = Store::open(&dir.path().join("aros.db")).unwrap();
        let campaign = CampaignId::new();
        let cas = ContentAddressedStore::open(dir.path().join("cas"), 8 * 1024 * 1024).unwrap();
        let error =
            ingest_bumblebee_ndjson(&store, &cas, campaign, "run-1", b"\xff", &BTreeSet::new())
                .unwrap_err();
        assert!(error.to_string().contains("UTF-8"), "{error}");
        assert!(store.load_graph_nodes(campaign).unwrap().is_empty());
        assert!(store
            .list_records(crate::provider_raw::PROVIDER_RAW_KIND)
            .unwrap()
            .is_empty());
        let rejected = ingest_bumblebee_ndjson(
            &store,
            &cas,
            campaign,
            "../etc",
            br#"{"record_type":"note","text":"x"}"#,
            &BTreeSet::new(),
        )
        .unwrap_err();
        assert!(rejected.to_string().contains("correlation"), "{rejected}");
        let tiny = ContentAddressedStore::open(dir.path().join("tiny"), 4).unwrap();
        let oversized = ingest_bumblebee_ndjson(
            &store,
            &tiny,
            campaign,
            "run-1",
            br#"{"record_type":"note","text":"hello"}"#,
            &BTreeSet::new(),
        )
        .unwrap_err();
        assert!(oversized.to_string().contains("max size"), "{oversized}");
        assert!(store.load_graph_nodes(campaign).unwrap().is_empty());
    }
}
