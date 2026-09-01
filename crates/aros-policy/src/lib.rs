//! Deterministic policy decision point. No LLM authority.

#![forbid(unsafe_code)]

pub mod engine;
pub mod error;
pub mod network_scope;
pub mod parse;
pub mod path_scope;
pub mod shell;

pub use engine::{evaluate, v0_1_effective_allow, PolicyVerdict, SandboxIdentity};
pub use error::{PolicyError, Result};
pub use parse::{load_manifest_from_path, load_manifest_from_str};
pub use path_scope::{is_forbidden_host_resource, normalize_path, path_allowed};

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use aros_types::{
        AuthorizationManifest, CampaignId, PolicyDecision, ProtocolKind, SandboxId, TargetId,
        ToolCapability, ToolIntent,
    };
    use ipnet::IpNet;
    use std::str::FromStr;

    use super::*;

    fn contained() -> SandboxIdentity {
        SandboxIdentity {
            id: SandboxId::new(),
            containment_demonstrated: true,
        }
    }

    fn uncontained() -> SandboxIdentity {
        SandboxIdentity {
            id: SandboxId::new(),
            containment_demonstrated: false,
        }
    }

    fn manifest_with_loopback() -> AuthorizationManifest {
        let mut m = AuthorizationManifest::default_deny_local(
            CampaignId::new(),
            TargetId::new(),
            "/tmp/target".into(),
        );
        m.require_containment = true;
        // Network capability is now an explicit opt-in, granted by whoever
        // authorizes the endpoint.
        m.tool_allowlist
            .insert(aros_types::ToolCapability::HttpRequest);
        m.allowed_endpoints.push(aros_types::AllowedEndpoint {
            cidr: IpNet::from_str("127.0.0.1/32").unwrap(),
            ports: [8080].into_iter().collect(),
            protocols: [ProtocolKind::Http, ProtocolKind::Tcp]
                .into_iter()
                .collect(),
        });
        m
    }

    #[test]
    fn fail_closed_without_containment() {
        let m = manifest_with_loopback();
        let mut intent = ToolIntent::new(ToolCapability::ReadFile);
        intent.path = Some("/tmp/target/README.md".into());
        let v = evaluate(&m, None, &uncontained(), &intent);
        assert_eq!(v.decision, PolicyDecision::Deny);
        assert!(v.reason.contains("containment"));
    }

    #[test]
    fn unauthorized_capability_denied() {
        let m = manifest_with_loopback();
        let intent = ToolIntent::new(ToolCapability::FuzzAdapter);
        let v = evaluate(&m, None, &contained(), &intent);
        assert_eq!(v.decision, PolicyDecision::Deny);
    }

    #[test]
    fn public_internet_denied() {
        let m = manifest_with_loopback();
        let mut intent = ToolIntent::new(ToolCapability::HttpRequest);
        intent.network = Some(aros_types::NetworkIntent {
            host: "8.8.8.8".into(),
            port: 53,
            protocol: ProtocolKind::Udp,
        });
        let v = evaluate(&m, None, &contained(), &intent);
        assert_eq!(v.decision, PolicyDecision::Deny);
    }

    #[test]
    fn authorized_loopback_http_allowed() {
        let m = manifest_with_loopback();
        let mut intent = ToolIntent::new(ToolCapability::HttpRequest);
        intent.network = Some(aros_types::NetworkIntent {
            host: "127.0.0.1".into(),
            port: 8080,
            protocol: ProtocolKind::Http,
        });
        let v = evaluate(&m, None, &contained(), &intent);
        assert_eq!(v.decision, PolicyDecision::Allow);
    }

    #[test]
    fn docker_socket_and_ssh_key_denied() {
        let m = manifest_with_loopback();
        for p in [
            "/var/run/docker.sock",
            "/home/user/.ssh/id_rsa",
            "/mnt/c/Windows",
        ] {
            let mut intent = ToolIntent::new(ToolCapability::ReadFile);
            intent.path = Some(p.into());
            let v = evaluate(&m, None, &contained(), &intent);
            assert_eq!(v.decision, PolicyDecision::Deny, "{p}");
        }
    }

    #[test]
    fn manifest_hash_changes_when_allowlist_grows() {
        let mut m = manifest_with_loopback();
        let a = m.manifest_hash().unwrap();
        m.tool_allowlist.insert(ToolCapability::FuzzAdapter);
        let b = m.manifest_hash().unwrap();
        assert_ne!(a, b);
    }

    #[test]
    fn requires_human_not_auto_promoted() {
        let verdict = PolicyVerdict {
            decision: PolicyDecision::RequiresHuman,
            reason: "test".into(),
        };
        assert!(!v0_1_effective_allow(&verdict, false));
        assert!(v0_1_effective_allow(&verdict, true));
    }
}
