use aros_types::{AuthorityResult, EvidenceBundle, EvidenceLevel, VerifierMode, VerifierRun};

pub trait EvidenceAuthority {
    fn name(&self) -> &'static str;
    fn adjudicate(&self, bundle: &EvidenceBundle, verifier: &VerifierRun) -> AuthorityResult;
}

/// Built-in authority used when THEUSTAD is not installed.
pub struct BuiltinEvidenceAuthority;

impl EvidenceAuthority for BuiltinEvidenceAuthority {
    fn name(&self) -> &'static str {
        "builtin"
    }

    fn adjudicate(&self, bundle: &EvidenceBundle, verifier: &VerifierRun) -> AuthorityResult {
        if bundle.artifact_digests.is_empty() {
            return AuthorityResult::InsufficientEvidence;
        }
        match verifier.result {
            AuthorityResult::Verified
                if bundle.level >= EvidenceLevel::E4IndependentReproduction
                    && matches!(
                        verifier.mode,
                        VerifierMode::ReproduceCandidate | VerifierMode::Blindish
                    ) =>
            {
                AuthorityResult::Verified
            }
            other => other,
        }
    }
}

/// Optional external adapter. Standalone MVP works without THEUSTAD.
pub struct TheustadAdapter {
    pub endpoint: Option<String>,
}

impl TheustadAdapter {
    pub fn unavailable() -> Self {
        Self { endpoint: None }
    }

    pub fn is_available(&self) -> bool {
        self.endpoint.is_some()
    }
}

impl EvidenceAuthority for TheustadAdapter {
    fn name(&self) -> &'static str {
        "theustad"
    }

    fn adjudicate(&self, bundle: &EvidenceBundle, verifier: &VerifierRun) -> AuthorityResult {
        if !self.is_available() {
            return BuiltinEvidenceAuthority.adjudicate(bundle, verifier);
        }
        // Optional process/HTTP integration is capability-detected later.
        BuiltinEvidenceAuthority.adjudicate(bundle, verifier)
    }
}
