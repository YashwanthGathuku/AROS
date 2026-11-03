//! Allowlisted campaign telemetry. A telemetry event is not evidence and not a verdict.
//!
//! The stream may drop events once it reaches [`MAX_TELEMETRY_EVENTS`]. Evidence
//! records are a different store kind and are not dropped here. Numbat-shaped
//! export is a record adapter. It does not start a collector and it does not enforce policy.

use std::fs::OpenOptions;
use std::io::Write;
use std::path::Path;

use aros_evidence::ContentAddressedStore;
use aros_store::Store;
use aros_types::{CampaignId, NodeId, TelemetryEvent};
use serde_json::Value;
use thiserror::Error;

use crate::provider_output::parse_ndjson;
use crate::provider_raw::{
    address_provider_bytes, provider_correlation_ok, require_correlation_id,
};

pub const TELEMETRY_KIND: &str = "telemetry";
const META_KIND: &str = "telemetry_meta";
const RETAINED_ID: &str = "retained";
const DROPPED_ID: &str = "dropped";

pub const MAX_TELEMETRY_EVENTS: usize = 4096;
const MAX_PAYLOAD: usize = 1024;

const PROVIDER_EVENT_NAMES: &[&str] = &[
    "AgentStarted",
    "AgentStopped",
    "ToolRequested",
    "ToolAllowed",
    "ToolDenied",
    "ProcessStarted",
    "ProcessFinished",
    "NetworkAttempted",
    "ObservationCreated",
    "AnomalyCreated",
    "PolicyViolationAttempt",
    "SandboxKilled",
];

const AUTHORITY_FIELDS: &[&str] = &[
    "authorize",
    "contained",
    "evidence_level",
    "finding",
    "may_authorize_actions",
    "may_verify_findings",
    "release_eligible",
    "verified",
];

const EVENT_NAMES: &[&str] = &[
    "CampaignStarted",
    "AgentStarted",
    "AgentStopped",
    "HypothesisCreated",
    "HypothesisRefuted",
    "ToolRequested",
    "ToolAllowed",
    "ToolDenied",
    "ProcessStarted",
    "ProcessFinished",
    "NetworkAttempted",
    "ObservationCreated",
    "AnomalyCreated",
    "EvidenceCreated",
    "ClaimCreated",
    "VerificationStarted",
    "VerificationSucceeded",
    "VerificationFailed",
    "PatchCreated",
    "ReattackStarted",
    "RegressionCreated",
    "PolicyViolationAttempt",
    "SandboxKilled",
];

#[derive(Debug, Error)]
pub enum TelemetryError {
    #[error("{0}")]
    Rejected(String),
    #[error("store: {0}")]
    Store(#[from] aros_store::StoreError),
    #[error("json: {0}")]
    Json(#[from] serde_json::Error),
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
}

impl From<crate::provider_raw::ProviderRawError> for TelemetryError {
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
pub struct NumbatIngest {
    pub stored: usize,
    pub dropped: usize,
    pub refused: usize,
    pub skipped: usize,
    pub rejected_lines: usize,
    pub truncated: bool,
    pub digest_blake3: String,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum EmitResult {
    Stored,
    Dropped { dropped: u64 },
}

pub fn emit_telemetry(
    store: &Store,
    work_root: Option<&Path>,
    event: &TelemetryEvent,
) -> Result<EmitResult, TelemetryError> {
    emit_limited(store, work_root, event, MAX_TELEMETRY_EVENTS)
}

pub(crate) fn emit_limited(
    store: &Store,
    work_root: Option<&Path>,
    event: &TelemetryEvent,
    limit: usize,
) -> Result<EmitResult, TelemetryError> {
    let stored = validate(event)?;
    let retained = read_counter(store, RETAINED_ID)?;
    if retained >= limit as u64 {
        let dropped = read_counter(store, DROPPED_ID)?.saturating_add(1);
        write_counter(store, DROPPED_ID, dropped)?;
        return Ok(EmitResult::Dropped { dropped });
    }
    let payload = serde_json::to_string(&stored)?;
    store.put_record(TELEMETRY_KIND, &NodeId::new().to_string(), &payload)?;
    write_counter(store, RETAINED_ID, retained.saturating_add(1))?;
    if let Some(work_root) = work_root {
        append_jsonl(work_root, &payload)?;
    }
    Ok(EmitResult::Stored)
}

pub fn load_telemetry(store: &Store) -> Result<Vec<TelemetryEvent>, TelemetryError> {
    let mut events = Vec::new();
    for (_id, payload) in store.list_records(TELEMETRY_KIND)? {
        events.push(serde_json::from_str(&payload)?);
    }
    Ok(events)
}

pub fn dropped_telemetry(store: &Store) -> Result<u64, TelemetryError> {
    read_counter(store, DROPPED_ID)
}

/// Numbat-shaped record. `enforcement` is always false. This does not start Numbat.
pub fn to_numbat_record(event: &TelemetryEvent) -> Result<serde_json::Value, TelemetryError> {
    let stored = validate(event)?;
    let mut record = serde_json::Map::new();
    record.insert("record_type".into(), serde_json::json!("event"));
    record.insert("schema".into(), serde_json::json!("aros-telemetry/1"));
    record.insert("enforcement".into(), serde_json::json!(false));
    record.insert("name".into(), serde_json::Value::String(stored.name));
    record.insert(
        "campaign_id".into(),
        match stored.campaign_id {
            Some(id) => serde_json::Value::String(id.to_string()),
            None => serde_json::Value::Null,
        },
    );
    record.insert("payload".into(), serde_json::Value::String(stored.payload));
    record.insert(
        "occurred_unix_ms".into(),
        serde_json::json!(stored.occurred_unix_ms),
    );
    Ok(serde_json::Value::Object(record))
}

/// Ingest Numbat NDJSON the caller already captured. This does not start Numbat.
///
/// Observational event names are stored as telemetry. Verdict names such as
/// `VerificationSucceeded` are refused. A finding line becomes `ObservationCreated`
/// and does not copy verdict fields.
pub fn ingest_numbat_ndjson(
    store: &Store,
    cas: &ContentAddressedStore,
    campaign_id: CampaignId,
    correlation_id: &str,
    bytes: &[u8],
    work_root: Option<&Path>,
) -> Result<NumbatIngest, TelemetryError> {
    let correlation_id = require_correlation_id(correlation_id)?;
    let (records, summary) = parse_ndjson("numbat", bytes).map_err(TelemetryError::Rejected)?;
    let addressed =
        address_provider_bytes(store, cas, "numbat", campaign_id, &correlation_id, bytes)?;
    let mut stored = 0usize;
    let mut dropped = 0usize;
    let mut refused = 0usize;
    let mut skipped = 0usize;
    for record in records {
        if !provider_correlation_ok(&record.payload, &correlation_id)
            || !campaign_matches(&record.payload, campaign_id)
        {
            refused += 1;
            continue;
        }
        let kind = record.record_type.trim();
        let event = if matches!(kind, "finding" | "detection" | "exposure") {
            if asks_to_enforce(&record.payload) {
                refused += 1;
                continue;
            }
            Some(provider_event(
                campaign_id,
                "ObservationCreated",
                &correlation_id,
                detection_message(&record.payload).as_deref(),
                occurred_ms(&record.payload),
            ))
        } else if kind == "event" {
            let name = record
                .payload
                .get("name")
                .and_then(|value| value.as_str())
                .unwrap_or("")
                .trim();
            if !PROVIDER_EVENT_NAMES.contains(&name) {
                if EVENT_NAMES.contains(&name) {
                    refused += 1;
                } else {
                    skipped += 1;
                }
                continue;
            }
            if asks_to_enforce(&record.payload) || carries_authority(&record.payload) {
                refused += 1;
                continue;
            }
            Some(provider_event(
                campaign_id,
                name,
                &correlation_id,
                text_message(&record.payload).as_deref(),
                occurred_ms(&record.payload),
            ))
        } else {
            skipped += 1;
            None
        };
        if let Some(event) = event {
            match emit_telemetry(store, work_root, &event)? {
                EmitResult::Stored => stored += 1,
                EmitResult::Dropped { .. } => dropped += 1,
            }
        }
    }
    Ok(NumbatIngest {
        stored,
        dropped,
        refused,
        skipped,
        rejected_lines: summary.rejected_lines,
        truncated: summary.truncated,
        digest_blake3: addressed.digest_blake3,
    })
}

fn provider_event(
    campaign_id: CampaignId,
    name: &str,
    correlation_id: &str,
    message: Option<&str>,
    occurred_unix_ms: u64,
) -> TelemetryEvent {
    TelemetryEvent {
        name: name.to_string(),
        campaign_id: Some(campaign_id),
        payload: provider_payload(correlation_id, message),
        occurred_unix_ms,
    }
}

fn provider_payload(correlation_id: &str, message: Option<&str>) -> String {
    let mut text = format!("correlation={correlation_id}");
    if let Some(message) = message {
        if !message.is_empty() {
            text.push(' ');
            text.push_str(message);
        }
    }
    text.chars().take(MAX_PAYLOAD).collect()
}

fn campaign_matches(payload: &Value, expected: CampaignId) -> bool {
    match payload.get("campaign_id") {
        None => true,
        Some(Value::String(text)) => text.trim() == expected.to_string(),
        Some(_) => false,
    }
}

fn asks_to_enforce(payload: &Value) -> bool {
    match payload.get("enforcement") {
        Some(Value::Bool(true)) => true,
        Some(Value::String(text)) if text.trim().eq_ignore_ascii_case("true") => true,
        _ => false,
    }
}

fn carries_authority(payload: &Value) -> bool {
    let Some(object) = payload.as_object() else {
        return true;
    };
    AUTHORITY_FIELDS.iter().any(|key| object.contains_key(*key))
}

fn occurred_ms(payload: &Value) -> u64 {
    for key in ["occurred_unix_ms", "timestamp_unix_ms"] {
        if let Some(value) = payload.get(key).and_then(|item| item.as_u64()) {
            return value;
        }
    }
    0
}

fn text_message(payload: &Value) -> Option<String> {
    for key in ["message", "summary", "detail"] {
        if let Some(text) = clip_field(payload, key, 256) {
            return Some(text);
        }
    }
    None
}

fn detection_message(payload: &Value) -> Option<String> {
    let id = clip_field(payload, "id", 128);
    let title = clip_field(payload, "title", 128).or_else(|| clip_field(payload, "summary", 128));
    Some(match (id, title) {
        (Some(id), Some(title)) => format!("numbat-detection id={id} {title}"),
        (Some(id), None) => format!("numbat-detection id={id}"),
        (None, Some(title)) => format!("numbat-detection {title}"),
        (None, None) => "numbat-detection".to_string(),
    })
}

fn clip_field(payload: &Value, key: &str, max: usize) -> Option<String> {
    let text = payload.get(key)?.as_str()?.trim();
    if text.is_empty() {
        return None;
    }
    Some(text.chars().take(max).collect())
}

fn validate(event: &TelemetryEvent) -> Result<TelemetryEvent, TelemetryError> {
    let name = event.name.trim();
    if !EVENT_NAMES.contains(&name) {
        return Err(TelemetryError::Rejected(
            "telemetry name is not in the spec allowlist".into(),
        ));
    }
    let payload = event.payload.trim();
    if payload.len() > MAX_PAYLOAD {
        return Err(TelemetryError::Rejected(format!(
            "telemetry payload must be at most {MAX_PAYLOAD} characters"
        )));
    }
    Ok(TelemetryEvent {
        name: name.to_string(),
        campaign_id: event.campaign_id,
        payload: payload.to_string(),
        occurred_unix_ms: event.occurred_unix_ms,
    })
}

fn read_counter(store: &Store, id: &str) -> Result<u64, TelemetryError> {
    match store.get_record(META_KIND, id) {
        Ok(text) => text
            .trim()
            .parse::<u64>()
            .map_err(|_| TelemetryError::Rejected("telemetry counter is not a number".into())),
        Err(aros_store::StoreError::NotFound(_)) => Ok(0),
        Err(error) => Err(error.into()),
    }
}

fn write_counter(store: &Store, id: &str, value: u64) -> Result<(), TelemetryError> {
    store.put_record(META_KIND, id, &value.to_string())?;
    Ok(())
}

fn append_jsonl(work_root: &Path, payload: &str) -> Result<(), TelemetryError> {
    let mut line = payload.to_string();
    line.push('\n');
    let mut file = OpenOptions::new()
        .create(true)
        .append(true)
        .open(work_root.join("telemetry.jsonl"))?;
    file.write_all(line.as_bytes())?;
    Ok(())
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;
    use aros_types::CampaignId;

    fn event(name: &str, payload: &str) -> TelemetryEvent {
        TelemetryEvent {
            name: name.into(),
            campaign_id: Some(CampaignId::new()),
            payload: payload.into(),
            occurred_unix_ms: 1_700_000_000_000,
        }
    }

    #[test]
    fn allowlisted_event_reloads_without_evidence_keys() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("aros.db");
        let sample = event("ObservationCreated", "stdout line");
        {
            let store = Store::open(&path).unwrap();
            let stored = emit_telemetry(&store, Some(dir.path()), &sample).unwrap();
            assert_eq!(stored, EmitResult::Stored);
        }
        let store = Store::open(&path).unwrap();
        let loaded = load_telemetry(&store).unwrap();
        assert_eq!(loaded.len(), 1);
        assert_eq!(loaded[0].name, "ObservationCreated");
        assert_eq!(loaded[0].payload, "stdout line");
        assert_eq!(loaded[0].campaign_id, sample.campaign_id);
        let rows = store.list_records(TELEMETRY_KIND).unwrap();
        let value: serde_json::Value = serde_json::from_str(&rows[0].1).unwrap();
        assert!(value.get("evidence_level").is_none());
        assert!(value.get("verified").is_none());
        assert!(value.get("finding_id").is_none());
        let lines = std::fs::read_to_string(dir.path().join("telemetry.jsonl")).unwrap();
        assert!(lines.contains("\"name\":\"ObservationCreated\""));
        assert!(!lines.contains("\"verified\""));
        let exported = to_numbat_record(&loaded[0]).unwrap();
        assert_eq!(exported["record_type"], "event");
        assert_eq!(exported["schema"], "aros-telemetry/1");
        assert_eq!(exported["enforcement"], false);
        assert!(exported.get("verified").is_none());
        assert!(exported.get("evidence_level").is_none());
        assert_eq!(EVENT_NAMES.len(), 23);
    }

    #[test]
    fn unknown_name_long_payload_and_cap_do_not_drop_evidence() {
        let dir = tempfile::tempdir().unwrap();
        let store = Store::open(&dir.path().join("aros.db")).unwrap();
        store
            .put_record("evidence", "kept", "{\"evidence_level\":\"E5\"}")
            .unwrap();
        let unknown = emit_telemetry(&store, Some(dir.path()), &event("CoverageCreated", "x"));
        assert!(unknown.unwrap_err().to_string().contains("allowlist"));
        let long = "a".repeat(1025);
        let rejected = emit_limited(&store, None, &event("EvidenceCreated", &long), 2);
        assert!(rejected.unwrap_err().to_string().contains("1024"));
        assert!(load_telemetry(&store).unwrap().is_empty());
        assert_eq!(
            emit_limited(&store, None, &event("EvidenceCreated", "one"), 2).unwrap(),
            EmitResult::Stored
        );
        assert_eq!(
            emit_limited(&store, None, &event("AnomalyCreated", "two"), 2).unwrap(),
            EmitResult::Stored
        );
        assert_eq!(
            emit_limited(&store, None, &event("ClaimCreated", "three"), 2).unwrap(),
            EmitResult::Dropped { dropped: 1 }
        );
        assert_eq!(load_telemetry(&store).unwrap().len(), 2);
        assert_eq!(dropped_telemetry(&store).unwrap(), 1);
        assert_eq!(
            store.get_record("evidence", "kept").unwrap(),
            "{\"evidence_level\":\"E5\"}"
        );
        assert!(!dir.path().join("telemetry.jsonl").exists());
        assert_eq!(MAX_TELEMETRY_EVENTS, 4096);
    }

    #[test]
    fn numbat_ndjson_stays_telemetry_and_refuses_verdicts() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("aros.db");
        let campaign = CampaignId::new();
        let input = format!(
            "{}\n{}\n{}\n{}\n{}\n{}\nnot-json\n",
            r#"{"record_type":"event","name":"ToolDenied","message":"port 80","run_id":"run-1","occurred_unix_ms":42}"#,
            r#"{"record_type":"event","name":"VerificationSucceeded","verified":true,"evidence_level":"E7","run_id":"run-1"}"#,
            r#"{"record_type":"event","name":"ProcessStarted","enforcement":true,"run_id":"run-1"}"#,
            r#"{"record_type":"finding","id":"n1","title":"suspicious call","verified":true,"evidence_level":"E7","run_id":"run-1"}"#,
            r#"{"record_type":"event","name":"NetworkAttempted","run_id":"other"}"#,
            r#"{"record_type":"event","name":"MadeUp","run_id":"run-1"}"#,
        );
        let input = input.into_bytes();
        let summary = {
            let store = Store::open(&path).unwrap();
            let cas = ContentAddressedStore::open(dir.path().join("cas"), 8 * 1024 * 1024).unwrap();
            ingest_numbat_ndjson(&store, &cas, campaign, "run-1", &input, Some(dir.path())).unwrap()
        };
        assert_eq!(summary.stored, 2);
        assert_eq!(summary.dropped, 0);
        assert_eq!(summary.refused, 3);
        assert_eq!(summary.skipped, 1);
        assert_eq!(summary.rejected_lines, 1);
        let store = Store::open(&path).unwrap();
        let loaded = load_telemetry(&store).unwrap();
        assert_eq!(loaded.len(), 2);
        let denied = loaded
            .iter()
            .find(|event| event.name == "ToolDenied")
            .unwrap();
        assert_eq!(denied.campaign_id, Some(campaign));
        assert_eq!(denied.occurred_unix_ms, 42);
        assert!(denied.payload.contains("correlation=run-1"));
        assert!(denied.payload.contains("port 80"));
        let detection = loaded
            .iter()
            .find(|event| event.name == "ObservationCreated")
            .unwrap();
        assert!(detection.payload.contains("suspicious call"));
        assert!(!detection.payload.contains("verified"));
        assert!(!detection.payload.contains("E7"));
        assert!(loaded
            .iter()
            .all(|event| event.name != "VerificationSucceeded"));
        assert!(loaded.iter().all(|event| event.name != "EvidenceCreated"));
        for event in &loaded {
            let value = serde_json::to_value(event).unwrap();
            assert!(value.get("verified").is_none());
            assert!(value.get("evidence_level").is_none());
        }
        let cas = ContentAddressedStore::open(dir.path().join("cas"), 8 * 1024 * 1024).unwrap();
        assert_eq!(cas.get(&summary.digest_blake3).unwrap(), input);
        let lines = std::fs::read_to_string(dir.path().join("telemetry.jsonl")).unwrap();
        assert!(lines.contains("\"name\":\"ToolDenied\""));
        assert!(!lines.contains("VerificationSucceeded"));
        let raw = store
            .list_records(crate::provider_raw::PROVIDER_RAW_KIND)
            .unwrap();
        let record: serde_json::Value = serde_json::from_str(&raw[0].1).unwrap();
        assert_eq!(record["provider"], "numbat");
        assert!(record.get("verified").is_none());
        assert!(store.load_graph_nodes(campaign).unwrap().is_empty());
    }

    #[test]
    fn bad_numbat_input_writes_nothing() {
        let dir = tempfile::tempdir().unwrap();
        let store = Store::open(&dir.path().join("aros.db")).unwrap();
        let cas = ContentAddressedStore::open(dir.path().join("cas"), 8 * 1024 * 1024).unwrap();
        let campaign = CampaignId::new();
        let bad_id = ingest_numbat_ndjson(
            &store,
            &cas,
            campaign,
            "../run",
            br#"{"record_type":"event","name":"ToolDenied"}"#,
            None,
        )
        .unwrap_err();
        assert!(bad_id.to_string().contains("correlation"), "{bad_id}");
        let bad_bytes =
            ingest_numbat_ndjson(&store, &cas, campaign, "run-1", b"\xff", None).unwrap_err();
        assert!(bad_bytes.to_string().contains("UTF-8"), "{bad_bytes}");
        assert!(load_telemetry(&store).unwrap().is_empty());
        assert!(store
            .list_records(crate::provider_raw::PROVIDER_RAW_KIND)
            .unwrap()
            .is_empty());
    }
}
