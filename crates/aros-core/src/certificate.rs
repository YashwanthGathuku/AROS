//! Offline evidence certificate. The digest covers the claims. Verification
//! re-reads the ledger and any named artifacts. It does not re-run the attack
//! and it does not treat a waived host run as a contained release.

use std::fs;
use std::path::{Path, PathBuf};

use aros_evidence::EventLedger;
use aros_store::Store;
use aros_types::{blake3_hex, to_canonical_json, CampaignId, ResearchEvent, DATABASE_FILE};
use serde::{Deserialize, Serialize};

use crate::engine::{CampaignOutcome, EngineError};

pub const CERTIFICATE_FILE: &str = "certificate.json";
const SCHEMA: &str = "aros-certificate/1";

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct EvidenceCertificate {
    pub schema: String,
    pub campaign_id: String,
    pub spec_id: String,
    pub state: String,
    pub evidence_level: String,
    pub verified_finding: bool,
    pub original_digest: String,
    pub original_digest_after: String,
    pub original_unmodified: bool,
    pub harness_digest: Option<String>,
    pub independent_reproduced: bool,
    pub twin_holds: bool,
    pub variant_holds: bool,
    pub regression_relpath: Option<String>,
    pub regression_digest: Option<String>,
    pub minimized_relpath: Option<String>,
    pub minimized_digest: Option<String>,
    pub contained: bool,
    pub required_evidence_met: bool,
    pub ledger_head: String,
    pub ledger_events: u64,
    pub release_eligible: bool,
    pub limits: Vec<String>,
    /// BLAKE3 of the canonical JSON with this field removed.
    pub digest: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct CertificateCheck {
    pub statement_ok: bool,
    pub release_eligible: bool,
    pub evidence_level: String,
    pub campaign_id: String,
    pub limits: Vec<String>,
    pub failures: Vec<String>,
}

pub fn write_certificate(
    work_root: &Path,
    spec_id: &str,
    outcome: &CampaignOutcome,
    ledger: &EventLedger,
) -> Result<PathBuf, EngineError> {
    let head = ledger
        .entries()
        .last()
        .map(|entry| entry.event_hash.clone())
        .unwrap_or_default();
    let level = outcome
        .evidence_level
        .map(|level| format!("{level:?}"))
        .unwrap_or_else(|| "none".into());
    let original_unmodified = outcome.original_digest == outcome.original_digest_after;
    let mut limits = Vec::new();
    if !outcome.declared.contained {
        limits.push("containment not demonstrated".into());
    }
    if !original_unmodified {
        limits.push("original target digest changed".into());
    }
    if !outcome.declared.required_evidence_met {
        limits.push("required evidence not met".into());
    }
    if !outcome.declared.ledger_verified {
        limits.push("ledger failed at issue".into());
    }
    if !claims_match_level(
        &level,
        outcome.declared.independent_reproduced,
        outcome.declared.twin_holds,
        outcome.declared.variant_holds,
        outcome.declared.regression_digest.is_some(),
    ) {
        return Err(EngineError::FailClosed(
            "certificate refused: evidence level does not match the recorded measurements".into(),
        ));
    }
    let release_eligible = limits.is_empty();
    let mut certificate = EvidenceCertificate {
        schema: SCHEMA.into(),
        campaign_id: outcome.campaign.id.to_string(),
        spec_id: spec_id.to_string(),
        state: format!("{:?}", outcome.campaign.state),
        evidence_level: level,
        verified_finding: outcome
            .finding
            .as_ref()
            .is_some_and(|finding| finding.verified),
        original_digest: outcome.original_digest.clone(),
        original_digest_after: outcome.original_digest_after.clone(),
        original_unmodified,
        harness_digest: outcome.declared.harness_digest.clone(),
        independent_reproduced: outcome.declared.independent_reproduced,
        twin_holds: outcome.declared.twin_holds,
        variant_holds: outcome.declared.variant_holds,
        regression_relpath: outcome
            .declared
            .regression_digest
            .as_ref()
            .map(|_| "e7-regression/regression_test.py".to_string()),
        regression_digest: outcome.declared.regression_digest.clone(),
        minimized_relpath: outcome
            .declared
            .minimized_digest
            .as_ref()
            .map(|_| "minimized.bin".to_string()),
        minimized_digest: outcome.declared.minimized_digest.clone(),
        contained: outcome.declared.contained,
        required_evidence_met: outcome.declared.required_evidence_met,
        ledger_head: head,
        ledger_events: ledger.len() as u64,
        release_eligible,
        limits,
        digest: String::new(),
    };
    certificate.digest = certificate_digest(&certificate)?;
    let path = work_root.join(CERTIFICATE_FILE);
    fs::write(&path, serde_json::to_vec_pretty(&certificate)?)?;
    Ok(path)
}

pub fn verify_certificate(work_root: &Path) -> Result<CertificateCheck, EngineError> {
    let path = work_root.join(CERTIFICATE_FILE);
    let raw = fs::read(&path)?;
    let certificate: EvidenceCertificate = serde_json::from_slice(&raw)?;
    let mut failures = Vec::new();
    match certificate_digest(&certificate) {
        Ok(digest) if digest == certificate.digest => {}
        Ok(_) => failures.push("certificate digest does not match the claims".into()),
        Err(error) => failures.push(error.to_string()),
    }
    if certificate.schema != SCHEMA {
        failures.push(format!("unknown certificate schema {}", certificate.schema));
    }
    if certificate.original_unmodified
        != (certificate.original_digest == certificate.original_digest_after)
    {
        failures.push("original_unmodified disagrees with the two digests".into());
    }
    if !claims_match_level(
        &certificate.evidence_level,
        certificate.independent_reproduced,
        certificate.twin_holds,
        certificate.variant_holds,
        certificate.regression_digest.is_some(),
    ) {
        failures.push("evidence level does not match the recorded measurements".into());
    }
    let recomputed_release = certificate.limits.is_empty()
        && certificate.contained
        && certificate.original_unmodified
        && certificate.required_evidence_met
        && claims_match_level(
            &certificate.evidence_level,
            certificate.independent_reproduced,
            certificate.twin_holds,
            certificate.variant_holds,
            certificate.regression_digest.is_some(),
        );
    if certificate.release_eligible != recomputed_release {
        failures.push("release_eligible disagrees with the recorded limits".into());
    }
    if certificate.release_eligible && !certificate.contained {
        failures.push("release_eligible cannot be set without containment".into());
    }
    match check_ledger(work_root, &certificate) {
        Ok(()) => {}
        Err(error) => failures.push(error),
    }
    if let (Some(rel), Some(digest)) = (
        certificate.regression_relpath.as_deref(),
        certificate.regression_digest.as_deref(),
    ) {
        match hash_work_file(work_root, rel) {
            Ok(actual) if actual == digest => {}
            Ok(_) => failures.push("regression file digest does not match".into()),
            Err(error) => failures.push(error),
        }
    }
    if let (Some(rel), Some(digest)) = (
        certificate.minimized_relpath.as_deref(),
        certificate.minimized_digest.as_deref(),
    ) {
        match hash_work_file(work_root, rel) {
            Ok(actual) if actual == digest => {}
            Ok(_) => failures.push("minimized payload digest does not match".into()),
            Err(error) => failures.push(error),
        }
    }
    Ok(CertificateCheck {
        statement_ok: failures.is_empty(),
        release_eligible: certificate.release_eligible && failures.is_empty(),
        evidence_level: certificate.evidence_level,
        campaign_id: certificate.campaign_id,
        limits: certificate.limits,
        failures,
    })
}

fn claims_match_level(
    level: &str,
    independent: bool,
    twin_holds: bool,
    variant_holds: bool,
    regression: bool,
) -> bool {
    if level.contains("E7") {
        return variant_holds && twin_holds && independent && regression;
    }
    if level.contains("E6") {
        return twin_holds && independent && !variant_holds;
    }
    if level.contains("E5") {
        return !variant_holds && !twin_holds;
    }
    if level.contains("E4") {
        return independent && !variant_holds && !twin_holds;
    }
    if level.contains("E3") || level.contains("E2") || level.contains("E1") || level.contains("E0")
    {
        return !variant_holds && !twin_holds;
    }
    false
}

fn certificate_digest(certificate: &EvidenceCertificate) -> Result<String, EngineError> {
    let mut value = serde_json::to_value(certificate)?;
    if let Some(object) = value.as_object_mut() {
        object.remove("digest");
    }
    let bytes = to_canonical_json(&value)?;
    Ok(blake3_hex(&bytes))
}

fn check_ledger(work_root: &Path, certificate: &EvidenceCertificate) -> Result<(), String> {
    let campaign_id: CampaignId = certificate
        .campaign_id
        .parse()
        .map_err(|error: aros_types::TypesError| error.to_string())?;
    let store = Store::open(&work_root.join(DATABASE_FILE)).map_err(|error| error.to_string())?;
    let ledger = store
        .load_ledger_for(campaign_id)
        .map_err(|error| error.to_string())?;
    ledger.verify().map_err(|error| error.to_string())?;
    let head = ledger
        .entries()
        .last()
        .map(|entry| entry.event_hash.as_str())
        .unwrap_or("");
    if head != certificate.ledger_head {
        return Err("ledger head does not match the certificate".into());
    }
    if ledger.len() as u64 != certificate.ledger_events {
        return Err("ledger length does not match the certificate".into());
    }
    if let Some(harness) = certificate.harness_digest.as_deref() {
        let present = ledger.entries().iter().any(|entry| {
            entry
                .artifact_digests
                .iter()
                .any(|digest| digest == harness)
        });
        if !present {
            return Err("harness digest is not in the ledger".into());
        }
    }
    let issued = ledger.entries().iter().rev().find_map(|entry| {
        if let ResearchEvent::CertificateIssued {
            contained,
            original_unmodified,
            ..
        } = &entry.record.event
        {
            Some((*contained, *original_unmodified))
        } else {
            None
        }
    });
    match issued {
        Some((contained, original_unmodified))
            if contained == certificate.contained
                && original_unmodified == certificate.original_unmodified => {}
        Some(_) => {
            return Err("certificate containment flags disagree with the ledger".into());
        }
        None => return Err("ledger has no CertificateIssued event".into()),
    }
    Ok(())
}

fn hash_work_file(work_root: &Path, rel: &str) -> Result<String, String> {
    let path = rel
        .split('/')
        .filter(|part| !part.is_empty() && *part != "." && *part != "..")
        .fold(work_root.to_path_buf(), |acc, part| acc.join(part));
    let bytes = fs::read(&path).map_err(|error| format!("{}: {error}", path.display()))?;
    Ok(blake3_hex(&bytes))
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn digest_changes_when_a_claim_changes() {
        let mut certificate = EvidenceCertificate {
            schema: SCHEMA.into(),
            campaign_id: "00000000-0000-4000-8000-000000000001".into(),
            spec_id: "http-idor".into(),
            state: "Verified".into(),
            evidence_level: "E4IndependentReproduction".into(),
            verified_finding: true,
            original_digest: "abc".into(),
            original_digest_after: "abc".into(),
            original_unmodified: true,
            harness_digest: None,
            independent_reproduced: true,
            twin_holds: false,
            variant_holds: false,
            regression_relpath: None,
            regression_digest: None,
            minimized_relpath: None,
            minimized_digest: None,
            contained: false,
            required_evidence_met: true,
            ledger_head: "head".into(),
            ledger_events: 1,
            release_eligible: false,
            limits: vec!["containment not demonstrated".into()],
            digest: String::new(),
        };
        certificate.digest = certificate_digest(&certificate).unwrap();
        let first = certificate.digest.clone();
        certificate.contained = true;
        let second = certificate_digest(&certificate).unwrap();
        assert_ne!(first, second);
    }
}
