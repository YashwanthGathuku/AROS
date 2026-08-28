use aros_types::{blake3_hex, to_canonical_json, CampaignId, EventRecord, ResearchEvent};
use serde::{Deserialize, Serialize};
use thiserror::Error;

const GENESIS: &str = "0000000000000000000000000000000000000000000000000000000000000000";

#[derive(Debug, Error)]
pub enum LedgerError {
    #[error("json: {0}")]
    Json(#[from] aros_types::TypesError),
    #[error("broken hash chain at index {index}")]
    BrokenChain { index: usize },
    #[error("tampered payload at index {index}")]
    Tampered { index: usize },
    #[error("non-contiguous ledger index: expected {expected}, got {actual}")]
    NonContiguous { expected: u64, actual: u64 },
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct LedgerEntry {
    pub index: u64,
    pub previous_hash: String,
    pub event_hash: String,
    pub campaign_id: Option<CampaignId>,
    pub payload_digest: String,
    pub artifact_digests: Vec<String>,
    pub record: EventRecord,
}

#[derive(Serialize)]
struct ChainMaterial<'a> {
    previous_hash: &'a str,
    record: &'a EventRecord,
    artifact_digests: &'a [String],
}

fn entry_hash(
    previous_hash: &str,
    record: &EventRecord,
    artifact_digests: &[String],
) -> Result<(String, String), LedgerError> {
    let payload_bytes = to_canonical_json(record)?;
    let payload_digest = blake3_hex(&payload_bytes);
    let material = ChainMaterial {
        previous_hash,
        record,
        artifact_digests,
    };
    let chain_bytes = to_canonical_json(&material)?;
    Ok((payload_digest, blake3_hex(&chain_bytes)))
}

#[derive(Clone, Debug, Default)]
pub struct EventLedger {
    entries: Vec<LedgerEntry>,
}

impl EventLedger {
    pub fn new() -> Self {
        Self {
            entries: Vec::new(),
        }
    }

    /// Construct a ledger from persisted entries without rewriting any hash or
    /// digest field. Verification is performed before the ledger is returned.
    pub fn from_stored_entries(entries: Vec<LedgerEntry>) -> Result<Self, LedgerError> {
        let ledger = Self { entries };
        ledger.verify()?;
        Ok(ledger)
    }

    pub fn len(&self) -> usize {
        self.entries.len()
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    pub fn entries(&self) -> &[LedgerEntry] {
        &self.entries
    }

    pub fn append(
        &mut self,
        event: ResearchEvent,
        artifact_digests: Vec<String>,
    ) -> Result<LedgerEntry, LedgerError> {
        let record = event.stamped_payload();
        let previous_hash = self
            .entries
            .last()
            .map(|entry| entry.event_hash.clone())
            .unwrap_or_else(|| GENESIS.to_string());
        let (payload_digest, event_hash) = entry_hash(&previous_hash, &record, &artifact_digests)?;
        let entry = LedgerEntry {
            index: self.entries.len() as u64,
            previous_hash,
            event_hash,
            campaign_id: record.event.campaign_id(),
            payload_digest,
            artifact_digests,
            record,
        };
        self.entries.push(entry.clone());
        Ok(entry)
    }

    pub fn verify(&self) -> Result<(), LedgerError> {
        let mut expected_prev = GENESIS.to_string();
        for (index, entry) in self.entries.iter().enumerate() {
            if entry.index != index as u64 {
                return Err(LedgerError::NonContiguous {
                    expected: index as u64,
                    actual: entry.index,
                });
            }
            if entry.previous_hash != expected_prev {
                return Err(LedgerError::BrokenChain { index });
            }
            let (payload_digest, recomputed) =
                entry_hash(&entry.previous_hash, &entry.record, &entry.artifact_digests)?;
            if payload_digest != entry.payload_digest || recomputed != entry.event_hash {
                return Err(LedgerError::Tampered { index });
            }
            expected_prev = entry.event_hash.clone();
        }
        Ok(())
    }

    /// Mutate a stored payload as an attacker would. Used by tamper tests.
    pub fn tamper_payload_for_test(&mut self, index: usize, summary: &str) {
        if let Some(entry) = self.entries.get_mut(index) {
            if let ResearchEvent::AnomalyRecorded {
                summary: existing, ..
            } = &mut entry.record.event
            {
                *existing = summary.to_string();
            }
        }
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use aros_types::{CampaignId, TargetId};

    #[test]
    fn verify_accepts_untampered_chain() {
        let mut ledger = EventLedger::new();
        let campaign = CampaignId::new();
        ledger
            .append(
                ResearchEvent::CampaignStarted {
                    campaign_id: campaign,
                    manifest_hash: "abc".into(),
                },
                vec![],
            )
            .unwrap();
        ledger
            .append(
                ResearchEvent::TargetRegistered {
                    target_id: TargetId::new(),
                    name: "fx".into(),
                },
                vec![],
            )
            .unwrap();
        ledger.verify().unwrap();
    }

    #[test]
    fn verify_detects_payload_tamper() {
        let mut ledger = EventLedger::new();
        let campaign = CampaignId::new();
        ledger
            .append(
                ResearchEvent::AnomalyRecorded {
                    campaign_id: campaign,
                    summary: "orig".into(),
                },
                vec![],
            )
            .unwrap();
        ledger.tamper_payload_for_test(0, "evil");
        assert!(ledger.verify().is_err());
    }

    #[test]
    fn stored_entry_tamper_is_not_rehashed_away() {
        let mut ledger = EventLedger::new();
        let campaign = CampaignId::new();
        ledger
            .append(
                ResearchEvent::AnomalyRecorded {
                    campaign_id: campaign,
                    summary: "orig".into(),
                },
                vec!["artifact".into()],
            )
            .unwrap();
        let mut stored = ledger.entries().to_vec();
        if let ResearchEvent::AnomalyRecorded { summary, .. } = &mut stored[0].record.event {
            *summary = "tampered".into();
        }
        assert!(EventLedger::from_stored_entries(stored).is_err());
    }
}
