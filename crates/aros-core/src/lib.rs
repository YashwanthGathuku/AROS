#![forbid(unsafe_code)]

pub mod adapters;
pub mod broker;
pub mod budget;
pub mod engine;
pub mod graph;
pub mod http_lab;
pub mod scheduler;
pub mod snapshot;
pub mod verifier;

pub use broker::{BrokerError, ToolBroker};
pub use engine::{CampaignEngine, CampaignOutcome, EngineError, FixtureKind};
pub use http_lab::{http_exchange, http_get, http_post_json, HttpError, HttpResponse};
pub use verifier::{
    adjudicate_from_input, reduced_input, verifier_bin_present, verify_in_subprocess,
    verify_input_independently, VerifierInput, VerifierProcessResult, VerifierReplaySpec,
};

use aros_types::{
    AllowedEndpoint, AuthorizationManifest, CampaignId, ProtocolKind, TargetId, ToolCapability,
};
use ipnet::IpNet;
use std::str::FromStr;

/// Lab manifest for repository fixtures. Containment is still required unless
/// the caller sets `require_containment = false` after an explicit operator waiver.
pub fn fixture_manifest(
    root: &str,
    host: &str,
    port: u16,
    require_containment: bool,
) -> AuthorizationManifest {
    let mut m = AuthorizationManifest::default_deny_local(
        CampaignId::new(),
        TargetId::new(),
        root.to_string(),
    );
    m.require_containment = require_containment;
    m.tool_allowlist.insert(ToolCapability::ListTree);
    m.tool_allowlist.insert(ToolCapability::ReadFile);
    m.tool_allowlist.insert(ToolCapability::SearchText);
    m.tool_allowlist.insert(ToolCapability::HttpRequest);
    if let Ok(net) = IpNet::from_str("127.0.0.0/8") {
        m.allowed_cidrs.insert(net);
    }
    m.allowed_endpoints.push(AllowedEndpoint {
        host: host.to_string(),
        port,
        protocol: ProtocolKind::Http,
    });
    m
}
