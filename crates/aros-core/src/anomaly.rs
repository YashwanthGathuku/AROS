//! Persistent anomaly notebook. An anomaly is not a vulnerability.

use std::fs::OpenOptions;
use std::io::Write;
use std::path::Path;

use aros_evidence::EventLedger;
use aros_store::Store;
use aros_types::{Anomaly, CampaignId, NodeId, ResearchEvent};
use thiserror::Error;

pub const ANOMALY_KIND: &str = "anomaly";

const STATUSES: &[&str] = &["open", "revisited", "dismissed"];
const MAX_TEXT: usize = 1024;
const MAX_ITEMS: usize = 32;

#[derive(Debug, Error)]
pub enum AnomalyError {
    #[error("{0}")]
    Rejected(String),
    #[error("store: {0}")]
    Store(#[from] aros_store::StoreError),
    #[error("ledger: {0}")]
    Ledger(#[from] aros_evidence::LedgerError),
    #[error("json: {0}")]
    Json(#[from] serde_json::Error),
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
}

/// A mutational crash search ran without AFL++ or libFuzzer. That fact is not a finding.
pub fn coverage_engine_gap(campaign_id: CampaignId) -> Anomaly {
    Anomaly {
        id: NodeId::new(),
        campaign_id,
        observation: "COVERAGE_ENGINE absent".into(),
        baseline: "a coverage-guided engine was not executed".into(),
        components: vec!["coverage-engine".into()],
        possible_explanations: vec!["AFL++ or libFuzzer was not available for this entry".into()],
        related_hypotheses: vec![],
        related_historical_patterns: vec!["COVERAGE_ENGINE absent".into()],
        status: "open".into(),
    }
}

pub fn persist_anomaly(
    store: &Store,
    ledger: &mut EventLedger,
    anomaly: &Anomaly,
) -> Result<(), AnomalyError> {
    let stored = validate(anomaly)?;
    let payload = serde_json::to_string(&stored)?;
    store.put_record(ANOMALY_KIND, &stored.id.to_string(), &payload)?;
    ledger.append(
        ResearchEvent::AnomalyRecorded {
            campaign_id: stored.campaign_id,
            summary: stored.observation.clone(),
        },
        vec![],
    )?;
    Ok(())
}

pub fn load_anomalies(store: &Store) -> Result<Vec<Anomaly>, AnomalyError> {
    let mut notes = Vec::new();
    for (_id, payload) in store.list_records(ANOMALY_KIND)? {
        notes.push(serde_json::from_str(&payload)?);
    }
    Ok(notes)
}

pub fn append_anomaly_jsonl(work_root: &Path, anomaly: &Anomaly) -> Result<(), AnomalyError> {
    let stored = validate(anomaly)?;
    let mut line = serde_json::to_string(&stored)?;
    line.push('\n');
    let mut file = OpenOptions::new()
        .create(true)
        .append(true)
        .open(work_root.join("anomalies.jsonl"))?;
    file.write_all(line.as_bytes())?;
    Ok(())
}

fn validate(anomaly: &Anomaly) -> Result<Anomaly, AnomalyError> {
    let mut stored = anomaly.clone();
    stored.observation = clean_text("observation", &stored.observation)?;
    stored.baseline = clean_text("baseline", &stored.baseline)?;
    stored.status = stored.status.trim().to_string();
    if !STATUSES.contains(&stored.status.as_str()) {
        return Err(AnomalyError::Rejected(
            "anomaly status must be open, revisited, or dismissed".into(),
        ));
    }
    stored.components = clean_list("component", &stored.components)?;
    stored.possible_explanations = clean_list("explanation", &stored.possible_explanations)?;
    stored.related_historical_patterns =
        clean_list("pattern", &stored.related_historical_patterns)?;
    if stored.related_hypotheses.len() > MAX_ITEMS {
        return Err(AnomalyError::Rejected(
            "anomaly related_hypotheses exceeds 32".into(),
        ));
    }
    Ok(stored)
}

fn clean_text(label: &str, raw: &str) -> Result<String, AnomalyError> {
    let text = raw.trim();
    if text.is_empty() || text.len() > MAX_TEXT {
        return Err(AnomalyError::Rejected(format!(
            "anomaly {label} must be 1 to {MAX_TEXT} characters"
        )));
    }
    Ok(text.to_string())
}

impl From<AnomalyError> for crate::engine::EngineError {
    fn from(value: AnomalyError) -> Self {
        match value {
            AnomalyError::Store(err) => Self::Store(err),
            AnomalyError::Ledger(err) => Self::Ledger(err),
            AnomalyError::Json(err) => Self::Json(err),
            AnomalyError::Io(err) => Self::Io(err),
            AnomalyError::Rejected(message) => Self::FailClosed(message),
        }
    }
}

fn clean_list(label: &str, raw: &[String]) -> Result<Vec<String>, AnomalyError> {
    if raw.len() > MAX_ITEMS {
        return Err(AnomalyError::Rejected(format!(
            "anomaly {label} list exceeds {MAX_ITEMS}"
        )));
    }
    let mut out = Vec::with_capacity(raw.len());
    for item in raw {
        out.push(clean_text(label, item)?);
    }
    Ok(out)
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    #[test]
    fn notebook_reloads_and_is_not_a_finding() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("aros.db");
        let campaign = CampaignId::new();
        let note = coverage_engine_gap(campaign);
        {
            let store = Store::open(&path).unwrap();
            let mut ledger = EventLedger::new();
            persist_anomaly(&store, &mut ledger, &note).unwrap();
            store.persist_ledger_for(campaign, &ledger).unwrap();
            append_anomaly_jsonl(dir.path(), &note).unwrap();
        }
        let store = Store::open(&path).unwrap();
        let loaded = load_anomalies(&store).unwrap();
        assert_eq!(loaded.len(), 1);
        assert_eq!(loaded[0].id, note.id);
        assert_eq!(loaded[0].observation, "COVERAGE_ENGINE absent");
        assert_eq!(loaded[0].status, "open");
        assert_eq!(loaded[0].components, vec!["coverage-engine".to_string()]);
        let payload = store.list_records(ANOMALY_KIND).unwrap();
        let value: serde_json::Value = serde_json::from_str(&payload[0].1).unwrap();
        assert!(value.get("evidence_level").is_none());
        assert!(value.get("verified").is_none());
        assert!(value.get("finding_id").is_none());
        let ledger = store.load_ledger_for(campaign).unwrap();
        assert!(ledger.entries().iter().any(|entry| {
            matches!(
                &entry.record.event,
                ResearchEvent::AnomalyRecorded { summary, .. } if summary == "COVERAGE_ENGINE absent"
            )
        }));
        let lines = std::fs::read_to_string(dir.path().join("anomalies.jsonl")).unwrap();
        assert!(lines.contains("\"status\":\"open\""));
    }

    #[test]
    fn verdict_status_and_empty_observation_are_rejected() {
        let dir = tempfile::tempdir().unwrap();
        let store = Store::open(&dir.path().join("aros.db")).unwrap();
        let mut ledger = EventLedger::new();
        let mut note = coverage_engine_gap(CampaignId::new());
        note.status = "verified".into();
        let err = persist_anomaly(&store, &mut ledger, &note).unwrap_err();
        assert!(err.to_string().contains("status"), "{err}");
        note.status = "open".into();
        note.observation = "  ".into();
        let err = persist_anomaly(&store, &mut ledger, &note).unwrap_err();
        assert!(err.to_string().contains("observation"), "{err}");
        assert!(store.list_records(ANOMALY_KIND).unwrap().is_empty());
    }
}
