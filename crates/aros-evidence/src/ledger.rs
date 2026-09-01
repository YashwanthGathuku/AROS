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
    use proptest::prelude::*;

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

    proptest! {
        #[test]
        fn arbitrary_event_chain_verifies_when_untouched(
            summaries in prop::collection::vec("[a-zA-Z0-9 _.-]{0,48}", 1..24),
            artifacts in prop::collection::vec("[a-f0-9]{0,64}", 0..8),
        ) {
            let campaign = CampaignId::new();
            let mut ledger = EventLedger::new();
            for summary in summaries {
                ledger.append(
                    ResearchEvent::AnomalyRecorded {
                        campaign_id: campaign,
                        summary,
                    },
                    artifacts.clone(),
                ).unwrap();
            }
            prop_assert!(ledger.verify().is_ok());
            let stored = ledger.entries().to_vec();
            prop_assert!(EventLedger::from_stored_entries(stored).is_ok());
        }

        #[test]
        fn arbitrary_artifact_digest_mutation_is_detected(
            original in "[a-f0-9]{1,64}",
            replacement in "[a-f0-9]{1,64}",
        ) {
            prop_assume!(original != replacement);
            let campaign = CampaignId::new();
            let mut ledger = EventLedger::new();
            ledger.append(
                ResearchEvent::AnomalyRecorded {
                    campaign_id: campaign,
                    summary: "artifact-bound".into(),
                },
                vec![original],
            ).unwrap();
            let mut stored = ledger.entries().to_vec();
            stored[0].artifact_digests[0] = replacement;
            prop_assert!(EventLedger::from_stored_entries(stored).is_err());
        }

        #[test]
        fn arbitrary_index_mutation_is_detected(offset in 1_u64..1000) {
            let campaign = CampaignId::new();
            let mut ledger = EventLedger::new();
            ledger.append(
                ResearchEvent::CampaignStarted {
                    campaign_id: campaign,
                    manifest_hash: "manifest".into(),
                },
                vec![],
            ).unwrap();
            let mut stored = ledger.entries().to_vec();
            stored[0].index = offset;
            let outcome = EventLedger::from_stored_entries(stored);
            let non_contiguous = matches!(outcome, Err(LedgerError::NonContiguous { .. }));
            prop_assert!(non_contiguous);
        }
    }
}
