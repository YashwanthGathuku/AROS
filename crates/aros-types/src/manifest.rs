use std::collections::BTreeSet;

use ipnet::IpNet;
use serde::{Deserialize, Serialize};

use crate::canonical::{hash_canonical, DigestPair};
use crate::enums::{DestructivePolicy, ProtocolKind, VisibilityMode};
use crate::error::Result;
use crate::ids::{CampaignId, TargetId};
use crate::tool::ToolCapability;

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ResourceBudgets {
    pub cpu_millis: u64,
    pub memory_bytes: u64,
    pub pid_limit: u32,
    pub disk_bytes: u64,
    pub wall_time_ms: u64,
    pub model_requests: u64,
    pub model_tokens: u64,
    pub max_concurrent_experiments: u32,
    pub max_sandbox_instances: u32,
    pub max_research_cells: u32,
}

impl Default for ResourceBudgets {
    fn default() -> Self {
        Self {
            cpu_millis: 60_000,
            memory_bytes: 512 * 1024 * 1024,
            pid_limit: 128,
            disk_bytes: 256 * 1024 * 1024,
            wall_time_ms: 10 * 60_000,
            model_requests: 100,
            model_tokens: 200_000,
            max_concurrent_experiments: 4,
            max_sandbox_instances: 4,
            max_research_cells: 2,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct AllowedEndpoint {
    pub cidr: IpNet,
    pub ports: BTreeSet<u16>,
    pub protocols: BTreeSet<ProtocolKind>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ArtifactPolicy {
    pub retain_raw_evidence: bool,
    pub max_artifact_bytes: u64,
}

impl Default for ArtifactPolicy {
    fn default() -> Self {
        Self {
            retain_raw_evidence: true,
            max_artifact_bytes: 32 * 1024 * 1024,
        }
    }
}

/// Frozen campaign authorization. Hashed canonically; the hash is copied onto
/// experiments, tool executions, observations, evidence, and verifier runs.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct AuthorizationManifest {
    pub campaign_id: CampaignId,
    pub target_id: TargetId,
    pub visibility: VisibilityMode,
    pub allowed_filesystem_roots: Vec<String>,
    pub allowed_service_names: BTreeSet<String>,
    pub allowed_endpoints: Vec<AllowedEndpoint>,
    pub allowed_credential_refs: BTreeSet<String>,
    pub permitted_modalities: BTreeSet<String>,
    pub destructive: DestructivePolicy,
    pub tool_allowlist: BTreeSet<ToolCapability>,
    pub budgets: ResourceBudgets,
    pub artifacts: ArtifactPolicy,
    pub data_classification: String,
    pub require_containment: bool,
}

impl AuthorizationManifest {
    pub fn digest(&self) -> Result<DigestPair> {
        hash_canonical(self)
    }

    pub fn manifest_hash(&self) -> Result<String> {
        Ok(self.digest()?.blake3)
    }

    pub fn default_deny_local(campaign_id: CampaignId, target_id: TargetId, root: String) -> Self {
        let mut tools = BTreeSet::new();
        tools.insert(ToolCapability::ReadFile);
        tools.insert(ToolCapability::ListTree);
        tools.insert(ToolCapability::SearchText);
        tools.insert(ToolCapability::GitInspect);
        // Deny-by-default means exactly that: network and execution
        // capabilities are opted into by the caller that authorizes an
        // endpoint, never granted implicitly by the constructor's name.
        tools.insert(ToolCapability::CollectFile);
        tools.insert(ToolCapability::CollectLogs);
        Self {
            campaign_id,
            target_id,
            visibility: VisibilityMode::WhiteBox,
            allowed_filesystem_roots: vec![root],
            allowed_service_names: BTreeSet::from(["fixture-target".to_string()]),
            allowed_endpoints: Vec::new(),
            allowed_credential_refs: BTreeSet::new(),
            permitted_modalities: BTreeSet::from([
                "static".to_string(),
                "http".to_string(),
                "source".to_string(),
            ]),
            destructive: DestructivePolicy::Forbid,
            tool_allowlist: tools,
            budgets: ResourceBudgets::default(),
            artifacts: ArtifactPolicy::default(),
            data_classification: "local-fixture".to_string(),
            require_containment: true,
        }
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn manifest_hash_is_stable_across_set_iteration() {
        let c = CampaignId::new();
        let t = TargetId::new();
        let a = AuthorizationManifest::default_deny_local(c, t, "/tmp/target".into());
        let b = a.clone();
        assert_eq!(a.manifest_hash().unwrap(), b.manifest_hash().unwrap());
        assert_eq!(a.manifest_hash().unwrap().len(), 64);
    }
}
