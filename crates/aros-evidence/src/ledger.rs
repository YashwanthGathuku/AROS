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
        let payload_bytes = to_canonical_json(&record)?;
        let payload_digest = blake3_hex(&payload_bytes);
        let previous_hash = self
            .entries
            .last()
            .map(|e| e.event_hash.clone())
            .unwrap_or_else(|| GENESIS.to_string());
        let mut chain_input = previous_hash.clone().into_bytes();
        chain_input.extend_from_slice(&payload_bytes);
        for d in &artifact_digests {
            chain_input.extend_from_slice(d.as_bytes());
        }
        let event_hash = blake3_hex(&chain_input);
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
            if entry.previous_hash != expected_prev {
                return Err(LedgerError::BrokenChain { index });
            }
            let payload_bytes = to_canonical_json(&entry.record)?;
            let payload_digest = blake3_hex(&payload_bytes);
            if payload_digest != entry.payload_digest {
                return Err(LedgerError::Tampered { index });
            }
            let mut chain_input = entry.previous_hash.clone().into_bytes();
            chain_input.extend_from_slice(&payload_bytes);
            for d in &entry.artifact_digests {
                chain_input.extend_from_slice(d.as_bytes());
            }
            let recomputed = blake3_hex(&chain_input);
            if recomputed != entry.event_hash {
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
}
