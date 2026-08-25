//! Lab-mode policy + broker execution shared by the daemon HTTP surface and tests.

use std::path::{Path, PathBuf};
use std::str::FromStr;

use aros_core::{BrokerError, ToolBroker};
use aros_evidence::{ContentAddressedStore, EventLedger};
use aros_policy::SandboxIdentity;
use aros_types::{
    AllowedEndpoint, AuthorizationManifest, CampaignId, PolicyDecision, ProtocolKind, SandboxId,
    TargetId, ToolCapability, ToolIntent,
};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ToolIntentRequest {
    pub capability: String,
    #[serde(default)]
    pub argv: Vec<String>,
    pub path: Option<String>,
    pub host: Option<String>,
    pub port: Option<u32>,
    pub protocol: Option<String>,
    #[serde(default = "default_timeout")]
    pub timeout_ms: u64,
}

fn default_timeout() -> u64 {
    30_000
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ToolIntentResponse {
    pub decision: String,
    pub reason: String,
    pub exit_status: Option<i32>,
    pub stdout_digest: Option<String>,
}

pub fn canonicalize_lab_root(raw: &str) -> String {
    let path = Path::new(raw);
    path.canonicalize()
        .unwrap_or_else(|_| {
            if path.is_absolute() {
                path.to_path_buf()
            } else {
                std::env::current_dir()
                    .unwrap_or_else(|_| PathBuf::from("."))
                    .join(path)
            }
        })
        .to_string_lossy()
        .into_owned()
}

pub fn lab_manifest() -> AuthorizationManifest {
    let raw = std::env::var("AROS_LAB_ROOT").unwrap_or_else(|_| {
        std::env::current_dir()
            .map(|p| p.to_string_lossy().into_owned())
            .unwrap_or_else(|_| ".".into())
    });
    let root = canonicalize_lab_root(&raw);
    let mut m = AuthorizationManifest::default_deny_local(
        CampaignId::new(),
        TargetId::new(),
        root,
    );
    m.require_containment = std::env::var("AROS_REQUIRE_CONTAINMENT")
        .map(|v| v == "1" || v.eq_ignore_ascii_case("true"))
        .unwrap_or(false);
    m.tool_allowlist.insert(ToolCapability::ListTree);
    m.tool_allowlist.insert(ToolCapability::ReadFile);
    m.tool_allowlist.insert(ToolCapability::SearchText);
    m.tool_allowlist.insert(ToolCapability::GitInspect);
    m.tool_allowlist.insert(ToolCapability::HttpRequest);
    if let Ok(cidr) = IpNet::from_str("127.0.0.1/32") {
        m.allowed_endpoints.push(AllowedEndpoint {
            cidr,
            ports: (1..=65535).collect(),
            protocols: [ProtocolKind::Http, ProtocolKind::Tcp]
                .into_iter()
                .collect(),
        });
    }
    m.allowed_service_names.insert("localhost".into());
    m.allowed_service_names.insert("127.0.0.1".into());
    m
}

use ipnet::IpNet;

pub fn capability_from_str(s: &str) -> Option<ToolCapability> {
    match s {
        "read_file" => Some(ToolCapability::ReadFile),
        "list_tree" => Some(ToolCapability::ListTree),
        "search_text" => Some(ToolCapability::SearchText),
        "git_inspect" => Some(ToolCapability::GitInspect),
        "run_tests" => Some(ToolCapability::RunTests),
        "run_language_tool" => Some(ToolCapability::RunLanguageTool),
        "http_request" => Some(ToolCapability::HttpRequest),
        "browser_request" => Some(ToolCapability::BrowserRequest),
        "execute_allowlisted_binary" => Some(ToolCapability::ExecuteAllowlistedBinary),
        "collect_logs" => Some(ToolCapability::CollectLogs),
        "collect_file" => Some(ToolCapability::CollectFile),
        "collect_process_state" => Some(ToolCapability::CollectProcessState),
        "fuzz_adapter" => Some(ToolCapability::FuzzAdapter),
        "sanitizer_adapter" => Some(ToolCapability::SanitizerAdapter),
        "static_analysis_adapter" => Some(ToolCapability::StaticAnalysisAdapter),
        _ => None,
    }
}

pub fn intent_from_request(req: &ToolIntentRequest) -> Result<ToolIntent, String> {
    let capability = capability_from_str(&req.capability)
        .ok_or_else(|| format!("unknown capability {:?}", req.capability))?;
    let mut intent = ToolIntent::new(capability);
    intent.argv = req.argv.clone();
    intent.path = req.path.clone();
    intent.timeout_ms = if req.timeout_ms == 0 {
        30_000
    } else {
        req.timeout_ms
    };
    if let (Some(host), Some(port)) = (&req.host, req.port) {
        let protocol = match req.protocol.as_deref() {
            Some("tcp") => ProtocolKind::Tcp,
            Some("udp") => ProtocolKind::Udp,
            _ => ProtocolKind::Http,
        };
        let port_u16 = u16::try_from(port).map_err(|_| "port out of range".to_string())?;
        intent.network = Some(aros_types::NetworkIntent {
            host: host.clone(),
            port: port_u16,
            protocol,
        });
    }
    Ok(intent)
}

pub fn decision_str(d: PolicyDecision) -> &'static str {
    match d {
        PolicyDecision::Allow => "ALLOW",
        PolicyDecision::Deny => "DENY",
        PolicyDecision::RequiresHuman => "REQUIRES_HUMAN",
    }
}

pub struct LabRuntime {
    pub manifest: AuthorizationManifest,
    pub manifest_hash: String,
    pub sandbox: SandboxIdentity,
    pub cas: ContentAddressedStore,
    pub ledger: EventLedger,
}

impl LabRuntime {
    pub fn open(data_root: impl AsRef<Path>) -> Result<Self, String> {
        let data_root = data_root.as_ref();
        std::fs::create_dir_all(data_root).map_err(|e| e.to_string())?;
        let cas = ContentAddressedStore::open(data_root.join("cas"), 32 * 1024 * 1024)
            .map_err(|e| e.to_string())?;
        let manifest = lab_manifest();
        let manifest_hash = manifest.manifest_hash().map_err(|e| e.to_string())?;
        let sandbox = SandboxIdentity {
            id: SandboxId::new(),
            containment_demonstrated: !manifest.require_containment,
        };
        Ok(Self {
            manifest,
            manifest_hash,
            sandbox,
            cas,
            ledger: EventLedger::new(),
        })
    }

    pub fn execute(&mut self, intent: ToolIntent) -> ToolIntentResponse {
        let mut broker = ToolBroker {
            campaign_id: self.manifest.campaign_id,
            manifest: &self.manifest,
            manifest_hash: self.manifest_hash.clone(),
            snapshot: None,
            sandbox: &self.sandbox,
            cas: &self.cas,
            ledger: &mut self.ledger,
            cli_human_override: false,
        };
        match broker.execute(intent) {
            Ok(receipt) => ToolIntentResponse {
                decision: decision_str(receipt.decision).into(),
                reason: "allowlist match; executed by trusted broker".into(),
                exit_status: receipt.exit_status,
                stdout_digest: receipt.stdout_digest,
            },
            Err(BrokerError::Denied(reason)) => ToolIntentResponse {
                decision: "DENY".into(),
                reason,
                exit_status: None,
                stdout_digest: None,
            },
            Err(other) => ToolIntentResponse {
                decision: "DENY".into(),
                reason: format!("execution failed: {other}"),
                exit_status: None,
                stdout_digest: None,
            },
        }
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    #[test]
    fn list_tree_via_lab_runtime_returns_cas_digest() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("marker.txt"), "aros-lab").unwrap();
        std::env::set_var("AROS_LAB_ROOT", dir.path());
        std::env::set_var("AROS_REQUIRE_CONTAINMENT", "0");

        let data = tempfile::tempdir().unwrap();
        let mut rt = LabRuntime::open(data.path()).unwrap();

        let req = ToolIntentRequest {
            capability: "list_tree".into(),
            argv: vec![],
            path: Some(dir.path().to_string_lossy().into_owned()),
            host: None,
            port: None,
            protocol: None,
            timeout_ms: 30_000,
        };
        let intent = intent_from_request(&req).unwrap();
        let resp = rt.execute(intent);
        assert_eq!(resp.decision, "ALLOW", "reason={}", resp.reason);
        assert_eq!(resp.exit_status, Some(0));
        let digest = resp.stdout_digest.expect("digest");
        let bytes = rt.cas.get(&digest).unwrap();
        let listing = String::from_utf8(bytes).unwrap();
        assert!(listing.contains("marker.txt"), "listing={listing}");
    }

    #[test]
    fn forbidden_capability_is_denied() {
        let dir = tempfile::tempdir().unwrap();
        std::env::set_var("AROS_LAB_ROOT", dir.path());
        std::env::set_var("AROS_REQUIRE_CONTAINMENT", "0");
        let data = tempfile::tempdir().unwrap();
        let mut rt = LabRuntime::open(data.path()).unwrap();
        let req = ToolIntentRequest {
            capability: "fuzz_adapter".into(),
            argv: vec![],
            path: None,
            host: None,
            port: None,
            protocol: None,
            timeout_ms: 1_000,
        };
        let intent = intent_from_request(&req).unwrap();
        let resp = rt.execute(intent);
        assert_eq!(resp.decision, "DENY");
        assert!(resp.stdout_digest.is_none());
    }
}
