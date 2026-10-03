//! Replaceable external integrations.
//!
//! AROS owns authorization, policy, evidence and verification. External tools
//! may contribute research proposals, passive inventory, or observability.
//! Their output is untrusted input and can never promote evidence levels.

use std::path::Path;

use serde::{Deserialize, Serialize};

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum IntegrationRole {
    ResearchHarness,
    PassiveInventory,
    Observability,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct IntegrationInvocation {
    pub provider: String,
    pub role: IntegrationRole,
    pub executable: String,
    pub argv: Vec<String>,
    pub cwd: Option<String>,
    pub read_only: bool,
    pub may_authorize_actions: bool,
    pub may_verify_findings: bool,
    pub output_semantics: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ForeignProjectIntegrations {
    pub grok_build: IntegrationInvocation,
    pub bumblebee: IntegrationInvocation,
    pub numbat: IntegrationInvocation,
}

/// Build provider-neutral invocation contracts. These are plans, not process
/// execution. The broker/runner must separately admit any invocation.
pub fn foreign_project_integrations(root: &Path) -> ForeignProjectIntegrations {
    let root = root.display().to_string();

    ForeignProjectIntegrations {
        grok_build: IntegrationInvocation {
            provider: "grok-build".into(),
            role: IntegrationRole::ResearchHarness,
            executable: "grok".into(),
            argv: vec![
                "--cwd".into(),
                root.clone(),
                "--output-format".into(),
                "json".into(),
                "--no-auto-update".into(),
                "--max-turns".into(),
                "8".into(),
                "--prompt-file".into(),
                "AROS_GENERATED_RESEARCH_PROMPT".into(),
            ],
            cwd: Some(root.clone()),
            read_only: false,
            may_authorize_actions: false,
            may_verify_findings: false,
            output_semantics:
                "untrusted research proposals/observations; never authorization or evidence promotion"
                    .into(),
        },
        bumblebee: IntegrationInvocation {
            provider: "bumblebee".into(),
            role: IntegrationRole::PassiveInventory,
            executable: "bumblebee".into(),
            argv: vec![
                "scan".into(),
                "--profile".into(),
                "project".into(),
                "--root".into(),
                root.clone(),
            ],
            cwd: None,
            read_only: true,
            may_authorize_actions: false,
            may_verify_findings: false,
            output_semantics:
                "read-only NDJSON inventory facts; exposure matches are leads, not vulnerability proof"
                    .into(),
        },
        numbat: IntegrationInvocation {
            provider: "numbat".into(),
            role: IntegrationRole::Observability,
            executable: "numbat".into(),
            argv: vec![
                "collect".into(),
                "--addr".into(),
                "127.0.0.1:4318".into(),
            ],
            cwd: None,
            read_only: true,
            may_authorize_actions: false,
            may_verify_findings: false,
            output_semantics:
                "monitor-only normalized activity telemetry; never AROS policy enforcement".into(),
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn external_integrations_never_gain_aros_authority() {
        let integrations = foreign_project_integrations(Path::new("/tmp/foreign"));
        for integration in [
            &integrations.grok_build,
            &integrations.bumblebee,
            &integrations.numbat,
        ] {
            assert!(!integration.may_authorize_actions);
            assert!(!integration.may_verify_findings);
        }
        assert!(integrations.bumblebee.read_only);
        assert!(integrations.numbat.read_only);
        assert_eq!(
            integrations.grok_build.role,
            IntegrationRole::ResearchHarness
        );
    }

    #[test]
    fn bumblebee_is_scoped_to_the_immutable_project_root() {
        let integrations = foreign_project_integrations(Path::new("/snapshots/t1"));
        assert_eq!(
            integrations.bumblebee.argv,
            vec![
                "scan",
                "--profile",
                "project",
                "--root",
                "/snapshots/t1"
            ]
        );
    }

    #[test]
    fn numbat_is_monitor_only_on_loopback() {
        let integrations = foreign_project_integrations(Path::new("/snapshots/t1"));
        assert!(integrations
            .numbat
            .argv
            .windows(2)
            .any(|v| v == ["--addr", "127.0.0.1:4318"]));
        assert!(integrations.numbat.output_semantics.contains("monitor-only"));
    }
}
