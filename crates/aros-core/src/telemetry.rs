//! Allowlisted campaign telemetry. A telemetry event is not evidence and not a verdict.
//!
//! The stream may drop events once it reaches [`MAX_TELEMETRY_EVENTS`]. Evidence
//! records are a different store kind and are not dropped here. Numbat-shaped
//! export is a record adapter. It does not start a collector and it does not enforce policy.

use std::fs::OpenOptions;
use std::io::Write;
use std::path::Path;

use aros_store::Store;
use aros_types::{NodeId, TelemetryEvent};
use thiserror::Error;

pub const TELEMETRY_KIND: &str = "telemetry";
const META_KIND: &str = "telemetry_meta";
const RETAINED_ID: &str = "retained";
const DROPPED_ID: &str = "dropped";

pub const MAX_TELEMETRY_EVENTS: usize = 4096;
const MAX_PAYLOAD: usize = 1024;

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
}
