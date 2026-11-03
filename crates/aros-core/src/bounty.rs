//! Program scope and a bounty report draft.
//!
//! The scope file is the program brief. It is not authorization to touch the
//! public internet, and it does not grant safe harbor. The draft is eligible
//! only after a verified, independently reproduced result at E4 or higher.
//! `submitted` stays false. AROS does not send the draft.

use aros_types::EvidenceLevel;
use serde::Serialize;
use serde_json::Value;
use thiserror::Error;

use crate::engine::CampaignOutcome;

const HAZARDOUS: &[&str] = &[
    "denial_of_service",
    "social_engineering",
    "physical_access",
    "production_modification",
    "excessive_data_access",
];

const SCOPE_FIELDS: &[&str] = &[
    "program_id",
    "organization",
    "disclosure",
    "program_claims_safe_harbor",
    "minimum_evidence",
    "in_scope",
    "out_of_scope",
];

#[derive(Debug, Error)]
pub enum BountyError {
    #[error("{0}")]
    Rejected(String),
    #[error("json: {0}")]
    Json(#[from] serde_json::Error),
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ScopeAsset {
    pub kind: String,
    pub value: String,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ProgramScope {
    pub program_id: String,
    pub organization: String,
    pub disclosure: String,
    pub program_claims_safe_harbor: String,
    pub minimum_evidence: EvidenceLevel,
    pub in_scope: Vec<ScopeAsset>,
    pub out_of_scope: Vec<ScopeAsset>,
    pub forbidden: Vec<String>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BountyEvidence {
    pub campaign_id: String,
    pub spec_id: String,
    pub invariant: String,
    pub location: String,
    pub evidence_level: EvidenceLevel,
    pub verified: bool,
    pub independent_reproduced: bool,
    pub minimized_digest: Option<String>,
    pub certificate_digest: Option<String>,
    pub contained: bool,
    pub release_eligible: bool,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct BountyReport {
    pub schema: String,
    pub submitted: bool,
    pub eligible: bool,
    pub refusal: Option<String>,
    pub program_id: String,
    pub title: String,
    pub target: String,
    pub location: String,
    pub summary: String,
    pub evidence_level: String,
    pub reproduction: Vec<String>,
    pub impact: String,
    pub mitigation: String,
    pub disclosure: String,
    pub program_claims_safe_harbor: String,
    pub safe_harbor_granted_by_aros: bool,
    pub campaign_id: String,
    pub spec_id: String,
    pub minimized_digest: Option<String>,
    pub certificate_digest: Option<String>,
    pub contained: bool,
    pub release_eligible: bool,
    pub forbidden: Vec<String>,
}

pub fn parse_program_scope(bytes: &[u8]) -> Result<ProgramScope, BountyError> {
    if bytes.len() > 64 * 1024 {
        return Err(BountyError::Rejected(
            "program scope exceeds 65536 bytes".into(),
        ));
    }
    let value: Value = serde_json::from_slice(bytes)?;
    let object = value
        .as_object()
        .ok_or_else(|| BountyError::Rejected("program scope must be an object".into()))?;
    for key in object.keys() {
        if !SCOPE_FIELDS.contains(&key.as_str()) {
            return Err(BountyError::Rejected(format!(
                "program scope field `{key}` is not accepted"
            )));
        }
    }
    let program_id = token_field(object.get("program_id"), "program_id")?;
    let organization = text_field(object.get("organization"), "organization", 128)?;
    let disclosure = one_of(
        object.get("disclosure"),
        "disclosure",
        &["nondisclosure", "coordinated", "discretionary"],
    )?;
    let program_claims_safe_harbor = one_of(
        object.get("program_claims_safe_harbor"),
        "program_claims_safe_harbor",
        &["none", "partial", "full"],
    )?;
    let minimum_evidence = parse_minimum(object.get("minimum_evidence"))?;
    let in_scope = assets(object.get("in_scope"), "in_scope", true)?;
    let out_of_scope = assets(object.get("out_of_scope"), "out_of_scope", false)?;
    Ok(ProgramScope {
        program_id,
        organization,
        disclosure,
        program_claims_safe_harbor,
        minimum_evidence,
        in_scope,
        out_of_scope,
        forbidden: HAZARDOUS.iter().map(|item| (*item).to_string()).collect(),
    })
}

pub fn bounty_evidence_from_outcome(
    outcome: &CampaignOutcome,
    spec_id: &str,
    invariant: &str,
    location: &str,
    certificate_digest: Option<&str>,
) -> BountyEvidence {
    let (verified, level) = match &outcome.finding {
        Some(finding) => (finding.verified, finding.evidence_level),
        None => (false, EvidenceLevel::E0HypothesisOnly),
    };
    let evidence_level = outcome.evidence_level.unwrap_or(level);
    BountyEvidence {
        campaign_id: outcome.campaign.id.to_string(),
        spec_id: clip(spec_id, 128),
        invariant: clip(invariant, 1024),
        location: clip(location, 512),
        evidence_level,
        verified,
        independent_reproduced: outcome.declared.independent_reproduced,
        minimized_digest: outcome.declared.minimized_digest.clone(),
        certificate_digest: certificate_digest.map(|digest| clip(digest, 128)),
        contained: outcome.declared.contained,
        release_eligible: false,
    }
}

pub fn write_bounty_report(
    scope: &ProgramScope,
    evidence: &BountyEvidence,
) -> Result<BountyReport, BountyError> {
    let location = normalize_location(&evidence.location)?;
    let mut refusal = None;
    if scope
        .out_of_scope
        .iter()
        .any(|asset| asset.value == location)
    {
        refusal = Some("target is out of scope".into());
    } else if !scope.in_scope.iter().any(|asset| asset.value == location) {
        refusal = Some("target is not in scope".into());
    } else if !evidence.verified {
        refusal = Some("finding is not verified".into());
    } else if !evidence.independent_reproduced
        || evidence.evidence_level < EvidenceLevel::E4IndependentReproduction
    {
        refusal = Some("independent reproduction at E4 or higher is required".into());
    } else if evidence.evidence_level < scope.minimum_evidence {
        refusal = Some("evidence is below the program minimum".into());
    }
    let eligible = refusal.is_none();
    let title = if eligible {
        format!("{} at {location}", evidence.spec_id)
    } else {
        format!("not eligible: {} at {location}", evidence.spec_id)
    };
    Ok(BountyReport {
        schema: "aros-bounty-report/1".into(),
        submitted: false,
        eligible,
        refusal,
        program_id: scope.program_id.clone(),
        title,
        target: location.clone(),
        location: location.clone(),
        summary: evidence.invariant.clone(),
        evidence_level: level_label(evidence.evidence_level).into(),
        reproduction: reproduction(evidence, &location),
        impact: evidence.invariant.clone(),
        mitigation: "Restore the behavior the invariant names, then re-run the same campaign."
            .into(),
        disclosure: scope.disclosure.clone(),
        program_claims_safe_harbor: scope.program_claims_safe_harbor.clone(),
        safe_harbor_granted_by_aros: false,
        campaign_id: evidence.campaign_id.clone(),
        spec_id: evidence.spec_id.clone(),
        minimized_digest: evidence.minimized_digest.clone(),
        certificate_digest: evidence.certificate_digest.clone(),
        contained: evidence.contained,
        release_eligible: evidence.release_eligible,
        forbidden: scope.forbidden.clone(),
    })
}

pub fn render_bounty_report(report: &BountyReport) -> String {
    let mut lines = Vec::new();
    lines.push(format!("# {}", report.title));
    lines.push(String::new());
    lines.push(format!("Program: {}", report.program_id));
    lines.push(format!("Target: {}", report.target));
    lines.push(format!("Evidence: {}", report.evidence_level));
    lines.push("Submitted: false".into());
    lines.push(format!(
        "Program claims safe harbor: {}. AROS does not grant safe harbor.",
        report.program_claims_safe_harbor
    ));
    lines.push(format!("Disclosure: {}", report.disclosure));
    if let Some(reason) = &report.refusal {
        lines.push(format!("Not eligible: {reason}"));
    }
    lines.push(String::new());
    lines.push("## Summary".into());
    lines.push(report.summary.clone());
    lines.push(String::new());
    lines.push("## Reproduction".into());
    for (index, step) in report.reproduction.iter().enumerate() {
        lines.push(format!("{}. {step}", index + 1));
    }
    lines.push(String::new());
    lines.push("## Impact".into());
    lines.push(report.impact.clone());
    lines.push(String::new());
    lines.push("## Mitigation".into());
    lines.push(report.mitigation.clone());
    if let Some(digest) = &report.minimized_digest {
        lines.push(String::new());
        lines.push(format!("Minimized digest: {digest}"));
    }
    if let Some(digest) = &report.certificate_digest {
        lines.push(format!("Certificate digest: {digest}"));
    }
    lines.push(format!(
        "Contained: {}. Release eligible: {}.",
        report.contained, report.release_eligible
    ));
    lines.join("\n")
}

fn reproduction(evidence: &BountyEvidence, location: &str) -> Vec<String> {
    let mut steps = vec![
        format!("Use the in-scope target `{location}`."),
        format!(
            "Run campaign `{}` ({}) and require an independent reproduction.",
            evidence.spec_id, evidence.campaign_id
        ),
    ];
    if let Some(digest) = &evidence.minimized_digest {
        steps.push(format!("Replay the minimized input. BLAKE3 {digest}."));
    }
    if let Some(digest) = &evidence.certificate_digest {
        steps.push(format!("Check certificate digest {digest}."));
    }
    if !evidence.contained {
        steps.push(
            "This draft records a run whose containment flag is false. It is not a contained release."
                .into(),
        );
    }
    steps
}

fn normalize_location(raw: &str) -> Result<String, BountyError> {
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return Err(BountyError::Rejected("target location is empty".into()));
    }
    if trimmed.contains("://") || looks_public_host(trimmed) {
        return Err(BountyError::Rejected(
            "public targets are outside AROS v0.1".into(),
        ));
    }
    let slash = trimmed.replace('\\', "/");
    if slash.split('/').any(|part| part == "..") {
        return Err(BountyError::Rejected(
            "target location must not contain ..".into(),
        ));
    }
    if is_loopback(&slash) {
        return normalize_loopback(&slash);
    }
    if slash.starts_with('/') || slash.contains('/') || has_drive_prefix(&slash) {
        return Ok(slash);
    }
    Err(BountyError::Rejected(
        "target location must be a local tree or a loopback endpoint".into(),
    ))
}

fn assets(
    value: Option<&Value>,
    field: &str,
    required: bool,
) -> Result<Vec<ScopeAsset>, BountyError> {
    let Some(value) = value else {
        if required {
            return Err(BountyError::Rejected(format!("{field} is required")));
        }
        return Ok(Vec::new());
    };
    let list = value
        .as_array()
        .ok_or_else(|| BountyError::Rejected(format!("{field} must be a list")))?;
    if required && list.is_empty() {
        return Err(BountyError::Rejected(format!("{field} must not be empty")));
    }
    if list.len() > 64 {
        return Err(BountyError::Rejected(format!("{field} exceeds 64 assets")));
    }
    let mut assets = Vec::new();
    for item in list {
        let object = item
            .as_object()
            .ok_or_else(|| BountyError::Rejected(format!("{field} entries must be objects")))?;
        for key in object.keys() {
            if key != "kind" && key != "value" {
                return Err(BountyError::Rejected(format!(
                    "{field} entry field `{key}` is not accepted"
                )));
            }
        }
        let kind = object
            .get("kind")
            .and_then(|item| item.as_str())
            .unwrap_or("");
        let raw = object
            .get("value")
            .and_then(|item| item.as_str())
            .unwrap_or("");
        let value = normalize_location(raw)?;
        let kind = match kind {
            "local_tree" if !is_loopback(&value) => "local_tree",
            "loopback" if is_loopback(&value) => "loopback",
            _ => {
                return Err(BountyError::Rejected(format!(
                    "{field} kind `{kind}` does not match the asset"
                )))
            }
        };
        assets.push(ScopeAsset {
            kind: kind.into(),
            value,
        });
    }
    Ok(assets)
}

fn looks_public_host(raw: &str) -> bool {
    let host = raw.split('/').next().unwrap_or(raw);
    let host = host.split(':').next().unwrap_or(host);
    if host.eq_ignore_ascii_case("localhost") {
        return false;
    }
    if host.parse::<std::net::IpAddr>().is_ok() {
        return !is_loopback_host(host);
    }
    host.contains('.') && !host.contains('/') && !has_drive_prefix(raw)
}

fn is_loopback(value: &str) -> bool {
    let Some((host, port)) = value.rsplit_once(':') else {
        return false;
    };
    is_loopback_host(host) && port.parse::<u16>().ok().filter(|port| *port > 0).is_some()
}

fn is_loopback_host(host: &str) -> bool {
    host.eq_ignore_ascii_case("localhost")
        || host == "127.0.0.1"
        || host == "::1"
        || host == "[::1]"
}

fn normalize_loopback(value: &str) -> Result<String, BountyError> {
    let Some((host, port)) = value.rsplit_once(':') else {
        return Err(BountyError::Rejected(
            "loopback asset requires a port".into(),
        ));
    };
    let port: u16 = port
        .parse()
        .map_err(|_| BountyError::Rejected("loopback port is not valid".into()))?;
    if port == 0 {
        return Err(BountyError::Rejected(
            "loopback port must be non-zero".into(),
        ));
    }
    let host = if host.eq_ignore_ascii_case("localhost") {
        "localhost"
    } else if host == "[::1]" || host == "::1" {
        "[::1]"
    } else if host == "127.0.0.1" {
        "127.0.0.1"
    } else {
        return Err(BountyError::Rejected(
            "public targets are outside AROS v0.1".into(),
        ));
    };
    Ok(format!("{host}:{port}"))
}

fn has_drive_prefix(value: &str) -> bool {
    let bytes = value.as_bytes();
    bytes.len() >= 3
        && bytes[0].is_ascii_alphabetic()
        && bytes[1] == b':'
        && (bytes[2] == b'/' || bytes[2] == b'\\')
}

fn parse_minimum(value: Option<&Value>) -> Result<EvidenceLevel, BountyError> {
    let raw = value
        .and_then(|item| item.as_str())
        .ok_or_else(|| BountyError::Rejected("minimum_evidence is required".into()))?;
    let level = match raw.trim() {
        "E4" | "E4_INDEPENDENT_REPRODUCTION" => EvidenceLevel::E4IndependentReproduction,
        "E5" | "E5_MINIMIZED_REPRODUCTION" => EvidenceLevel::E5MinimizedReproduction,
        "E6" | "E6_COUNTERFACTUAL_DIFFERENTIAL" => EvidenceLevel::E6CounterfactualDifferential,
        "E7" | "E7_VARIANT_REATTACK_AND_REGRESSION" => {
            EvidenceLevel::E7VariantReattackAndRegression
        }
        _ => {
            return Err(BountyError::Rejected(
                "minimum_evidence must be E4 or higher".into(),
            ))
        }
    };
    Ok(level)
}

fn token_field(value: Option<&Value>, field: &str) -> Result<String, BountyError> {
    let text = text_field(value, field, 64)?;
    if text
        .chars()
        .all(|ch| ch.is_ascii_alphanumeric() || matches!(ch, '.' | '_' | '-'))
    {
        Ok(text)
    } else {
        Err(BountyError::Rejected(format!(
            "{field} must be ascii letters, digits, or . _ -"
        )))
    }
}

fn text_field(value: Option<&Value>, field: &str, max: usize) -> Result<String, BountyError> {
    let raw = value
        .and_then(|item| item.as_str())
        .ok_or_else(|| BountyError::Rejected(format!("{field} is required")))?;
    let trimmed = raw.trim();
    if trimmed.is_empty()
        || trimmed.chars().count() > max
        || trimmed.chars().any(|ch| ch.is_control())
    {
        return Err(BountyError::Rejected(format!(
            "{field} must be 1 to {max} characters"
        )));
    }
    Ok(trimmed.to_string())
}

fn one_of(value: Option<&Value>, field: &str, allowed: &[&str]) -> Result<String, BountyError> {
    let text = text_field(value, field, 32)?;
    if allowed.contains(&text.as_str()) {
        Ok(text)
    } else {
        Err(BountyError::Rejected(format!(
            "{field} must be one of {}",
            allowed.join(", ")
        )))
    }
}

fn level_label(level: EvidenceLevel) -> &'static str {
    match level {
        EvidenceLevel::E0HypothesisOnly => "E0",
        EvidenceLevel::E1StaticSupport => "E1",
        EvidenceLevel::E2DynamicAnomaly => "E2",
        EvidenceLevel::E3InvariantViolation => "E3",
        EvidenceLevel::E4IndependentReproduction => "E4",
        EvidenceLevel::E5MinimizedReproduction => "E5",
        EvidenceLevel::E6CounterfactualDifferential => "E6",
        EvidenceLevel::E7VariantReattackAndRegression => "E7",
    }
}

fn clip(raw: &str, max: usize) -> String {
    raw.trim().chars().take(max).collect()
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    fn scope_json(extra: &str) -> String {
        format!(
            r#"{{
                "program_id": "lab-authz",
                "organization": "AROS lab",
                "disclosure": "nondisclosure",
                "program_claims_safe_harbor": "full",
                "minimum_evidence": "E4",
                "in_scope": [{{"kind": "local_tree", "value": "fixtures/vulnerable/authz"}}],
                "out_of_scope": [{{"kind": "local_tree", "value": "fixtures/patched/authz"}}]
                {extra}
            }}"#
        )
    }

    fn proven() -> BountyEvidence {
        BountyEvidence {
            campaign_id: "campaign-1".into(),
            spec_id: "http-idor".into(),
            invariant: "authenticated as user=1 must not read bob-secret".into(),
            location: "fixtures/vulnerable/authz".into(),
            evidence_level: EvidenceLevel::E5MinimizedReproduction,
            verified: true,
            independent_reproduced: true,
            minimized_digest: Some("abc123".into()),
            certificate_digest: Some("def456".into()),
            contained: false,
            release_eligible: false,
        }
    }

    #[test]
    fn eligible_draft_keeps_the_invariant_and_is_not_submitted() {
        let scope = parse_program_scope(scope_json("").as_bytes()).unwrap();
        assert_eq!(scope.forbidden.len(), 5);
        assert!(scope
            .forbidden
            .iter()
            .any(|item| item == "denial_of_service"));
        let report = write_bounty_report(&scope, &proven()).unwrap();
        assert!(report.eligible);
        assert!(!report.submitted);
        assert!(!report.safe_harbor_granted_by_aros);
        assert_eq!(report.evidence_level, "E5");
        assert_eq!(report.summary, proven().invariant);
        assert!(!report.release_eligible);
        let markdown = render_bounty_report(&report);
        assert!(markdown.contains("authenticated as user=1 must not read bob-secret"));
        assert!(markdown.contains("BLAKE3 abc123"));
        assert!(markdown.contains("Submitted: false"));
        assert!(markdown.contains("AROS does not grant safe harbor"));
        let json = serde_json::to_value(&report).unwrap();
        assert_eq!(json["submitted"], false);
        assert!(json.get("verified").is_none());
    }

    #[test]
    fn public_assets_unknown_fields_and_weak_evidence_are_refused() {
        let public_scope =
            scope_json("").replace("fixtures/vulnerable/authz", "https://example.com");
        let error = parse_program_scope(public_scope.as_bytes()).unwrap_err();
        assert!(error.to_string().contains("public"), "{error}");
        let address = scope_json("").replace("fixtures/vulnerable/authz", "8.8.8.8:443");
        assert!(parse_program_scope(address.as_bytes())
            .unwrap_err()
            .to_string()
            .contains("public"));
        let wildcard = scope_json("").replace("fixtures/vulnerable/authz", "*.example.com");
        assert!(parse_program_scope(wildcard.as_bytes()).is_err());
        let extra = scope_json(r#", "may_authorize_actions": true"#);
        let error = parse_program_scope(extra.as_bytes()).unwrap_err();
        assert!(error.to_string().contains("not accepted"), "{error}");
        let low = scope_json("").replace("E4", "E2");
        assert!(parse_program_scope(low.as_bytes())
            .unwrap_err()
            .to_string()
            .contains("E4"));

        let scope = parse_program_scope(scope_json("").as_bytes()).unwrap();
        let mut weak = proven();
        weak.evidence_level = EvidenceLevel::E3InvariantViolation;
        weak.independent_reproduced = false;
        let report = write_bounty_report(&scope, &weak).unwrap();
        assert!(!report.eligible);
        assert!(report.refusal.unwrap().contains("E4"));
        assert!(!report.submitted);

        let mut outside = proven();
        outside.location = "fixtures/patched/authz".into();
        let report = write_bounty_report(&scope, &outside).unwrap();
        assert_eq!(report.refusal.as_deref(), Some("target is out of scope"));

        let mut missing = proven();
        missing.location = "fixtures/other".into();
        let report = write_bounty_report(&scope, &missing).unwrap();
        assert_eq!(report.refusal.as_deref(), Some("target is not in scope"));

        let loopback = r#"{
            "program_id": "lab-loop",
            "organization": "AROS lab",
            "disclosure": "coordinated",
            "program_claims_safe_harbor": "none",
            "minimum_evidence": "E4",
            "in_scope": [{"kind": "loopback", "value": "127.0.0.1:8080"}]
        }"#;
        let scope = parse_program_scope(loopback.as_bytes()).unwrap();
        assert_eq!(scope.in_scope[0].value, "127.0.0.1:8080");
    }
}
