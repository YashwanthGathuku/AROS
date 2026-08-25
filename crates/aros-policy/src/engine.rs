use aros_types::{
    AuthorizationManifest, DestructivePolicy, PolicyDecision, SandboxId, TargetSnapshot,
    ToolCapability, ToolIntent,
};

use crate::network_scope::{network_allowed, parse_host_ip};
use crate::path_scope::path_allowed;
use crate::shell::{argv_contains_shell_metacharacters, executable_is_shell};

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SandboxIdentity {
    pub id: SandboxId,
    pub containment_demonstrated: bool,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PolicyVerdict {
    pub decision: PolicyDecision,
    pub reason: String,
}

impl PolicyVerdict {
    fn allow(reason: impl Into<String>) -> Self {
        Self {
            decision: PolicyDecision::Allow,
            reason: reason.into(),
        }
    }

    fn deny(reason: impl Into<String>) -> Self {
        Self {
            decision: PolicyDecision::Deny,
            reason: reason.into(),
        }
    }

    fn human(reason: impl Into<String>) -> Self {
        Self {
            decision: PolicyDecision::RequiresHuman,
            reason: reason.into(),
        }
    }

    pub fn is_allow(&self) -> bool {
        self.decision == PolicyDecision::Allow
    }
}

/// Deterministic policy decision point. The LLM cannot override this result.
pub fn evaluate(
    manifest: &AuthorizationManifest,
    _snapshot: Option<&TargetSnapshot>,
    sandbox: &SandboxIdentity,
    intent: &ToolIntent,
) -> PolicyVerdict {
    if manifest.require_containment && !sandbox.containment_demonstrated {
        return PolicyVerdict::deny(
            "containment not demonstrated; campaign fails closed (ADR-0004)",
        );
    }

    if !manifest.tool_allowlist.contains(&intent.capability) {
        return PolicyVerdict::deny(format!(
            "capability {} is not on the tool allowlist",
            intent.capability.as_str()
        ));
    }

    if argv_contains_shell_metacharacters(&intent.argv) {
        return PolicyVerdict::deny("argv contains shell metacharacters");
    }

    if intent
        .argv
        .first()
        .is_some_and(|exe| executable_is_shell(exe))
    {
        return PolicyVerdict::deny("shell executables are not a tool capability");
    }

    if let Some(path) = &intent.path {
        if crate::path_scope::is_forbidden_host_resource(path) {
            return PolicyVerdict::deny("host secret or container socket path is forbidden");
        }
        if !path_allowed(path, &manifest.allowed_filesystem_roots) {
            return PolicyVerdict::deny("path is outside allowed filesystem roots");
        }
    }

    if let Some(cwd) = &intent.cwd {
        if !path_allowed(cwd, &manifest.allowed_filesystem_roots) {
            return PolicyVerdict::deny("cwd is outside allowed filesystem roots");
        }
    }

    if let Some(net) = &intent.network {
        let ip_ok =
            parse_host_ip(&net.host).is_some() && network_allowed(net, &manifest.allowed_endpoints);
        let name_ok = manifest.allowed_service_names.contains(&net.host)
            && network_allowed(
                &aros_types::NetworkIntent {
                    host: "127.0.0.1".into(),
                    port: net.port,
                    protocol: net.protocol,
                },
                &manifest.allowed_endpoints,
            );
        // Service names may only be used when a loopback (or otherwise listed)
        // endpoint on that port/protocol is also authorized. This prevents
        // DNS-as-egress via an allowed name pointing at the public Internet.
        if !ip_ok && !name_ok {
            return PolicyVerdict::deny("network destination is not in the allowlist");
        }
        if parse_host_ip(&net.host).is_none() && !manifest.allowed_service_names.contains(&net.host)
        {
            return PolicyVerdict::deny("hostname is not an allowed service name");
        }
        if parse_host_ip(&net.host).is_some() && !network_allowed(net, &manifest.allowed_endpoints)
        {
            return PolicyVerdict::deny("ip/port/protocol is not in the allowlist");
        }
    }

    if matches!(
        intent.capability,
        ToolCapability::HttpRequest | ToolCapability::BrowserRequest
    ) && intent.network.is_none()
    {
        return PolicyVerdict::deny("network capability requires a network intent");
    }
    if matches!(
        intent.capability,
        ToolCapability::ReadFile | ToolCapability::CollectFile | ToolCapability::SearchText
    ) && intent.path.is_none()
    {
        return PolicyVerdict::deny("filesystem capability requires a path");
    }

    match manifest.destructive {
        DestructivePolicy::Forbid => {}
        DestructivePolicy::RequireHuman => {
            if matches!(
                intent.capability,
                ToolCapability::ExecuteAllowlistedBinary | ToolCapability::FuzzAdapter
            ) {
                return PolicyVerdict::human(
                    "destructive policy requires an explicit CLI invocation",
                );
            }
        }
        DestructivePolicy::AllowInSandbox => {}
    }

    PolicyVerdict::allow("allowlist match")
}

/// v0.1: REQUIRES_HUMAN is treated as blocked unless the caller is the CLI
/// with an explicit override flag. The engine itself never auto-promotes.
pub fn v0_1_effective_allow(verdict: &PolicyVerdict, cli_human_override: bool) -> bool {
    match verdict.decision {
        PolicyDecision::Allow => true,
        PolicyDecision::Deny => false,
        PolicyDecision::RequiresHuman => cli_human_override,
    }
}
