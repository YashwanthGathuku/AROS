//! Lab-mode policy + broker execution shared by the daemon HTTP surface and tests.

use std::path::Path;
use std::str::FromStr;

use aros_core::{BrokerError, ToolBroker};
use aros_evidence::{ContentAddressedStore, EventLedger};
use aros_policy::SandboxIdentity;
use aros_types::{
    env_name, AllowedEndpoint, AuthorizationManifest, CampaignId, PolicyDecision, ProtocolKind,
    SandboxId, TargetId, ToolCapability, ToolIntent,
};
use ipnet::IpNet;
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
    pub http_target: Option<String>,
    pub http_cookie: Option<String>,
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

pub fn canonicalize_lab_root(raw: &str) -> Result<String, String> {
    let path = Path::new(raw);
    let canonical = path
        .canonicalize()
        .map_err(|error| format!("lab root must exist and be canonicalizable: {error}"))?;
    let value = canonical.to_string_lossy().into_owned();
    Ok(value
        .strip_prefix(r"\\?\")
        .or_else(|| value.strip_prefix("//?/"))
        .unwrap_or(&value)
        .to_string())
}

pub fn lab_manifest_from_root(
    raw: &str,
    require_containment: bool,
) -> Result<AuthorizationManifest, String> {
    lab_manifest_from_root_with_ports(raw, require_containment, &[])
}

pub fn lab_manifest_from_root_with_ports(
    raw: &str,
    require_containment: bool,
    allowed_ports: &[u16],
) -> Result<AuthorizationManifest, String> {
    let root = canonicalize_lab_root(raw)?;
    let mut manifest =
        AuthorizationManifest::default_deny_local(CampaignId::new(), TargetId::new(), root);
    manifest.require_containment = require_containment;
    manifest.tool_allowlist.insert(ToolCapability::ListTree);
    manifest.tool_allowlist.insert(ToolCapability::ReadFile);
    manifest.tool_allowlist.insert(ToolCapability::SearchText);
    manifest.tool_allowlist.insert(ToolCapability::GitInspect);
    if !allowed_ports.is_empty() {
        manifest.tool_allowlist.insert(ToolCapability::HttpRequest);
        if let Ok(cidr) = IpNet::from_str("127.0.0.1/32") {
            manifest.allowed_endpoints.push(AllowedEndpoint {
                cidr,
                ports: allowed_ports.iter().copied().collect(),
                protocols: [ProtocolKind::Http, ProtocolKind::Tcp]
                    .into_iter()
                    .collect(),
            });
        }
        manifest.allowed_service_names.insert("localhost".into());
        manifest.allowed_service_names.insert("127.0.0.1".into());
    }
    Ok(manifest)
}

fn parse_ports(raw: &str) -> Result<Vec<u16>, String> {
    if raw.trim().is_empty() {
        return Ok(Vec::new());
    }
    raw.split(',')
        .map(|part| {
            part.trim()
                .parse::<u16>()
                .map_err(|_| format!("invalid lab port {part:?}"))
        })
        .collect()
}

pub fn lab_manifest() -> Result<AuthorizationManifest, String> {
    let root = std::env::var(env_name("LAB_ROOT")).map_err(|_| {
        "explicit lab root is required; daemon will not use cwd implicitly".to_string()
    })?;
    let require_containment = std::env::var(env_name("REQUIRE_CONTAINMENT"))
        .map(|value| !(value == "0" || value.eq_ignore_ascii_case("false")))
        .unwrap_or(true);
    let ports = std::env::var(env_name("LAB_PORTS"))
        .ok()
        .map(|value| parse_ports(&value))
        .transpose()?
        .unwrap_or_default();
    lab_manifest_from_root_with_ports(&root, require_containment, &ports)
}

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
    intent.http_target = req.http_target.clone();
    intent.http_cookie = req.http_cookie.clone();
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

pub fn decision_str(decision: PolicyDecision) -> &'static str {
    match decision {
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
        Self::open_with_manifest(data_root, lab_manifest()?)
    }

    pub fn open_with_manifest(
        data_root: impl AsRef<Path>,
        manifest: AuthorizationManifest,
    ) -> Result<Self, String> {
        let data_root = data_root.as_ref();
        std::fs::create_dir_all(data_root).map_err(|error| error.to_string())?;
        let cas = ContentAddressedStore::open(data_root.join("cas"), 32 * 1024 * 1024)
            .map_err(|error| error.to_string())?;
        let manifest_hash = manifest
            .manifest_hash()
            .map_err(|error| error.to_string())?;
        let sandbox = SandboxIdentity {
            id: SandboxId::new(),
            containment_demonstrated: false,
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
    fn default_manifest_requires_explicit_root() {
        std::env::remove_var(env_name("LAB_ROOT"));
        assert!(lab_manifest().is_err());
    }

    #[test]
    fn explicit_manifest_has_no_network_by_default() {
        let dir = tempfile::tempdir().unwrap();
        let manifest = lab_manifest_from_root(&dir.path().to_string_lossy(), true).unwrap();
        assert!(manifest.require_containment);
        assert!(manifest.allowed_endpoints.is_empty());
        assert!(!manifest
            .tool_allowlist
            .contains(&ToolCapability::HttpRequest));
    }

    #[test]
    fn list_tree_via_explicit_waiver_manifest_returns_cas_digest() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("marker.txt"), "aros-lab").unwrap();
        let data = tempfile::tempdir().unwrap();
        let manifest = lab_manifest_from_root(&dir.path().to_string_lossy(), false).unwrap();
        let mut runtime = LabRuntime::open_with_manifest(data.path(), manifest).unwrap();
        runtime.manifest.require_containment = false;

        let req = ToolIntentRequest {
            capability: "list_tree".into(),
            argv: vec![],
            path: Some(dir.path().to_string_lossy().into_owned()),
            host: None,
            port: None,
            protocol: None,
            http_target: None,
            http_cookie: None,
            timeout_ms: 30_000,
        };
        let resp = runtime.execute(intent_from_request(&req).unwrap());
        assert_eq!(resp.decision, "ALLOW", "reason={}", resp.reason);
        let bytes = runtime
            .cas
            .get(&resp.stdout_digest.expect("digest"))
            .unwrap();
        assert!(String::from_utf8(bytes).unwrap().contains("marker.txt"));
    }
}
