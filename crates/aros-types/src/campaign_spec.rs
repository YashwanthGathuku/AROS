//! Declarative RedLab campaign contract. No I/O, no execution.

use serde::{Deserialize, Serialize};

use crate::error::{Result, TypesError};

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CampaignSpec {
    pub id: String,
    #[serde(default)]
    pub schema_version: Option<String>,
    #[serde(default)]
    pub target: Option<CampaignTarget>,
    pub security_class: SecurityClass,
    pub historical_pattern: HistoricalPattern,
    pub surface: CampaignSurface,
    pub invariant: String,
    pub attacker_capabilities: Vec<String>,
    #[serde(default)]
    pub prerequisites: Vec<String>,
    pub resource_limits: ResourceLimits,
    #[serde(default)]
    pub assigned_roles: Vec<String>,
    pub generator: CampaignGenerator,
    pub oracle: CampaignOracle,
    pub expected_outcome: ExpectedOutcome,
    pub required_evidence: Vec<String>,
    pub severity_rationale: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CampaignTarget {
    pub project: String,
    #[serde(default)]
    pub repo: Option<String>,
    pub revision_pin: String,
    #[serde(default)]
    pub language: Option<String>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum SecurityClass {
    Confidentiality,
    Integrity,
    Authenticity,
    ForwardSecrecy,
    Availability,
    MemorySafety,
    SupplyChain,
    SideChannel,
    Authorization,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HistoricalPattern {
    pub summary: String,
    #[serde(default)]
    pub references: Vec<String>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CampaignSurface {
    pub entrypoints: Vec<String>,
    #[serde(default)]
    pub files: Vec<String>,
    #[serde(default)]
    pub notes: Option<String>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ResourceLimits {
    pub wall_clock_seconds: u32,
    pub memory_mb: u32,
    #[serde(default)]
    pub max_iterations: Option<u32>,
    #[serde(default)]
    pub network: CampaignNetwork,
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub enum CampaignNetwork {
    #[default]
    #[serde(rename = "none")]
    None,
    #[serde(rename = "loopback-only")]
    LoopbackOnly,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CampaignGenerator {
    pub kind: GeneratorKind,
    pub command: String,
    #[serde(default)]
    pub corpus: Option<String>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum GeneratorKind {
    #[serde(rename = "harness")]
    Harness,
    #[serde(rename = "fuzzer")]
    Fuzzer,
    #[serde(rename = "differential")]
    Differential,
    #[serde(rename = "formal-check")]
    FormalCheck,
    #[serde(rename = "property-test")]
    PropertyTest,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CampaignOracle {
    pub decides: OracleDecides,
    pub success_means: String,
    #[serde(default)]
    pub r#match: Option<String>,
    #[serde(default)]
    pub negative_control: Option<String>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum OracleDecides {
    ExitCode,
    StdoutContains,
    StdoutNotContains,
    JsonField,
    DifferentialMismatch,
    CounterexampleFound,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ExpectedOutcome {
    InvariantHolds,
    InvariantBroken,
}

impl CampaignSpec {
    pub fn from_json_str(raw: &str) -> Result<Self> {
        let spec: Self = serde_json::from_str(raw)?;
        spec.validate()?;
        Ok(spec)
    }

    pub fn validate(&self) -> Result<()> {
        if self.id.is_empty() || !id_is_slug(&self.id) {
            return Err(TypesError::InvalidCampaign(format!(
                "id {:?} is not a slug [a-z0-9]+(-[a-z0-9]+)*",
                self.id
            )));
        }
        if let Some(version) = &self.schema_version {
            if version != "0.1" {
                return Err(TypesError::InvalidCampaign(format!(
                    "unsupported schema_version {version}"
                )));
            }
        }
        if self.invariant.trim().is_empty() {
            return Err(TypesError::InvalidCampaign(
                "invariant must be a falsifiable claim".into(),
            ));
        }
        if self.attacker_capabilities.is_empty() {
            return Err(TypesError::InvalidCampaign(
                "attacker_capabilities must not be empty".into(),
            ));
        }
        if self.surface.entrypoints.is_empty() {
            return Err(TypesError::InvalidCampaign(
                "surface.entrypoints must not be empty".into(),
            ));
        }
        if self.resource_limits.wall_clock_seconds < 1 || self.resource_limits.memory_mb < 1 {
            return Err(TypesError::InvalidCampaign(
                "resource_limits must bound wall clock and memory".into(),
            ));
        }
        if self.generator.command.trim().is_empty() {
            return Err(TypesError::InvalidCampaign(
                "generator.command must not be empty".into(),
            ));
        }
        if self.required_evidence.is_empty() {
            return Err(TypesError::InvalidCampaign(
                "required_evidence must not be empty".into(),
            ));
        }
        for level in &self.required_evidence {
            if !matches!(
                level.as_str(),
                "E0" | "E1" | "E2" | "E3" | "E4" | "E5" | "E6" | "E7"
            ) {
                return Err(TypesError::InvalidCampaign(format!(
                    "unknown evidence level {level}"
                )));
            }
        }
        if self.oracle.decides == OracleDecides::StdoutContains && self.oracle.r#match.is_none() {
            return Err(TypesError::InvalidCampaign(
                "stdout_contains oracle requires match".into(),
            ));
        }
        Ok(())
    }
}

fn id_is_slug(id: &str) -> bool {
    let mut chars = id.chars().peekable();
    if chars.peek().is_none() {
        return false;
    }
    let mut prev_hyphen = true;
    for c in chars {
        if c == '-' {
            if prev_hyphen {
                return false;
            }
            prev_hyphen = true;
            continue;
        }
        if !c.is_ascii_lowercase() && !c.is_ascii_digit() {
            return false;
        }
        prev_hyphen = false;
    }
    !prev_hyphen
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    const REPLAY: &str =
        include_str!("../../../campaign-loader/dycrpt-replay-resistance.campaign.json");
    const MAXSKIP: &str =
        include_str!("../../../campaign-loader/dycrpt-skipped-key-dos.campaign.json");

    #[test]
    fn shipped_replay_campaign_parses() {
        let spec = CampaignSpec::from_json_str(REPLAY).unwrap();
        assert_eq!(spec.id, "dycrpt-replay-resistance");
        assert_eq!(spec.security_class, SecurityClass::Integrity);
        assert_eq!(spec.expected_outcome, ExpectedOutcome::InvariantHolds);
        assert_eq!(spec.oracle.r#match.as_deref(), Some("REPLAY_ACCEPTED"));
        assert_eq!(
            spec.target.as_ref().unwrap().revision_pin,
            "e4e200ad71bda9ef81ea0bfa4c6e427dc9d7d82c"
        );
    }

    #[test]
    fn shipped_maxskip_campaign_parses() {
        let spec = CampaignSpec::from_json_str(MAXSKIP).unwrap();
        assert_eq!(spec.id, "dycrpt-skipped-key-dos");
        assert_eq!(spec.security_class, SecurityClass::Availability);
        assert_eq!(spec.oracle.r#match.as_deref(), Some("UNBOUNDED_DERIVATION"));
    }

    #[test]
    fn extra_field_is_rejected() {
        let err = CampaignSpec::from_json_str("{\"id\":\"x\",\"bonus\":1}").unwrap_err();
        let msg = err.to_string();
        assert!(
            msg.contains("unknown field") || msg.contains("invalid campaign"),
            "{msg}"
        );
    }

    #[test]
    fn missing_invariant_is_rejected() {
        let mut value: serde_json::Value = serde_json::from_str(REPLAY).unwrap();
        value.as_object_mut().unwrap().remove("invariant");
        assert!(CampaignSpec::from_json_str(&value.to_string()).is_err());
    }

    #[test]
    fn uppercase_id_is_rejected() {
        let mut spec = CampaignSpec::from_json_str(REPLAY).unwrap();
        spec.id = "DycrptReplay".into();
        assert!(spec.validate().is_err());
    }
}
