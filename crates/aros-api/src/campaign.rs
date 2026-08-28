//! Lab fixture campaign entry points for arosd.

use std::net::TcpListener;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::thread;
use std::time::{Duration, Instant};

use aros_core::{fixture_manifest, http_get, CampaignEngine, CampaignOutcome, EngineError, FixtureKind};
use aros_types::env_name;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FixtureKindParam {
    Authz,
    Path,
    Deceptive,
}

impl From<FixtureKindParam> for FixtureKind {
    fn from(value: FixtureKindParam) -> Self {
        match value {
            FixtureKindParam::Authz => FixtureKind::Authz,
            FixtureKindParam::Path => FixtureKind::Path,
            FixtureKindParam::Deceptive => FixtureKind::Deceptive,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FixtureCampaignRequest {
    /// Absolute path to a real runnable fixture tree containing server.py.
    pub fixture_root: String,
    /// Working directory for CAS, twin and sqlite.
    pub work_root: String,
    pub kind: FixtureKindParam,
    /// Explicit lab/development waiver. Defaults false: no silent downgrade.
    #[serde(default)]
    pub waive_containment: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FixtureCampaignResponse {
    pub campaign_id: String,
    pub state: String,
    pub verified: bool,
    pub deceptive_rejected: bool,
    pub evidence_level: Option<String>,
    pub original_digest: String,
    pub original_digest_after: String,
    pub original_unmodified: bool,
    pub claim: Option<String>,
    pub live_reattack_confirmed: bool,
    pub research_card_id: Option<String>,
    pub verifier_isolated: bool,
}

impl From<CampaignOutcome> for FixtureCampaignResponse {
    fn from(out: CampaignOutcome) -> Self {
        let verified = out.finding.as_ref().is_some_and(|finding| finding.verified);
        let claim = out.finding.as_ref().map(|finding| finding.claim.clone());
        let evidence_level = out.evidence_level.map(|level| format!("{level:?}"));
        let state = format!("{:?}", out.campaign.state);
        let original_unmodified = out.original_digest == out.original_digest_after;
        Self {
            campaign_id: out.campaign.id.to_string(),
            state,
            verified,
            deceptive_rejected: out.deceptive_rejected,
            evidence_level,
            original_digest: out.original_digest,
            original_digest_after: out.original_digest_after,
            original_unmodified,
            claim,
            live_reattack_confirmed: out.live_reattack_confirmed,
            research_card_id: out.research_card_id,
            verifier_isolated: out.verifier_isolated,
        }
    }
}

struct ActualFixture {
    child: Child,
    port: u16,
}

impl ActualFixture {
    fn start(root: &Path) -> Result<Self, String> {
        if !root.join("server.py").is_file() {
            return Err("fixture must contain runnable server.py".into());
        }
        let python = resolve_python().ok_or_else(|| "python interpreter unavailable".to_string())?;
        let listener = TcpListener::bind("127.0.0.1:0").map_err(|error| error.to_string())?;
        let port = listener.local_addr().map_err(|error| error.to_string())?.port();
        drop(listener);
        let child = Command::new(python)
            .arg("server.py")
            .current_dir(root)
            .env("AROS_FIXTURE_PORT", port.to_string())
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .map_err(|error| format!("launch real fixture: {error}"))?;
        let mut fixture = Self { child, port };
        let deadline = Instant::now() + Duration::from_secs(4);
        while Instant::now() < deadline {
            if fixture
                .child
                .try_wait()
                .map_err(|error| error.to_string())?
                .is_some()
            {
                fixture.stop();
                return Err("fixture exited before readiness".into());
            }
            if http_get("127.0.0.1", port, "/health", None).is_ok() {
                return Ok(fixture);
            }
            thread::sleep(Duration::from_millis(50));
        }
        fixture.stop();
        Err("fixture readiness deadline exceeded".into())
    }

    fn stop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

impl Drop for ActualFixture {
    fn drop(&mut self) {
        self.stop();
    }
}

fn resolve_python() -> Option<String> {
    if let Ok(explicit) = std::env::var(env_name("PYTHON")) {
        if !explicit.trim().is_empty() {
            return Some(explicit);
        }
    }
    ["python3", "python"].into_iter().find_map(|candidate| {
        Command::new(candidate)
            .arg("--version")
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()
            .ok()
            .filter(|status| status.success())
            .map(|_| candidate.to_string())
    })
}

pub fn run_fixture_campaign(
    request: &FixtureCampaignRequest,
) -> Result<FixtureCampaignResponse, String> {
    let fixture_root = PathBuf::from(&request.fixture_root);
    let work_root = PathBuf::from(&request.work_root);
    if !fixture_root.is_dir() {
        return Err(format!(
            "fixture_root is not a directory: {}",
            request.fixture_root
        ));
    }
    std::fs::create_dir_all(&work_root).map_err(|error| error.to_string())?;

    let kind = FixtureKind::from(request.kind.clone());
    let mut fixture = ActualFixture::start(&fixture_root)?;
    let engine = CampaignEngine::new(request.waive_containment);
    let manifest = fixture_manifest(
        &fixture_root.to_string_lossy(),
        "127.0.0.1",
        fixture.port,
        !request.waive_containment,
    );
    let result = engine.run_fixture_campaign(
        &fixture_root,
        &work_root,
        "127.0.0.1",
        fixture.port,
        None,
        kind,
        manifest,
    );
    fixture.stop();
    match result {
        Ok(outcome) => Ok(FixtureCampaignResponse::from(outcome)),
        Err(EngineError::FailClosed(message)) => Err(message),
        Err(other) => Err(other.to_string()),
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    fn fixture_path(parts: &[&str]) -> PathBuf {
        let mut path = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        path.push("../..");
        for part in parts {
            path.push(part);
        }
        path.canonicalize().unwrap()
    }

    #[test]
    fn authz_campaign_uses_real_fixture_and_real_twin() {
        let fixture = fixture_path(&["fixtures", "vulnerable", "authz"]);
        let work = tempfile::tempdir().unwrap();
        let response = run_fixture_campaign(&FixtureCampaignRequest {
            fixture_root: fixture.to_string_lossy().into_owned(),
            work_root: work.path().to_string_lossy().into_owned(),
            kind: FixtureKindParam::Authz,
            waive_containment: true,
        })
        .unwrap();
        assert!(response.verified, "claim={:?}", response.claim);
        assert!(response.original_unmodified);
        assert!(response.live_reattack_confirmed);
        assert_eq!(response.evidence_level.as_deref(), Some("E7VariantReattackAndRegression"));
    }

    #[test]
    fn path_campaign_uses_real_fixture_and_real_twin() {
        let fixture = fixture_path(&["fixtures", "vulnerable", "path"]);
        let work = tempfile::tempdir().unwrap();
        let response = run_fixture_campaign(&FixtureCampaignRequest {
            fixture_root: fixture.to_string_lossy().into_owned(),
            work_root: work.path().to_string_lossy().into_owned(),
            kind: FixtureKindParam::Path,
            waive_containment: true,
        })
        .unwrap();
        assert!(response.verified);
        assert!(response.live_reattack_confirmed);
        assert_eq!(response.evidence_level.as_deref(), Some("E7VariantReattackAndRegression"));
    }

    #[test]
    fn deceptive_negative_control_is_rejected_by_invariant_not_label_shortcut() {
        let fixture = fixture_path(&["fixtures", "deceptive"]);
        let work = tempfile::tempdir().unwrap();
        let response = run_fixture_campaign(&FixtureCampaignRequest {
            fixture_root: fixture.to_string_lossy().into_owned(),
            work_root: work.path().to_string_lossy().into_owned(),
            kind: FixtureKindParam::Deceptive,
            waive_containment: true,
        })
        .unwrap();
        assert!(response.deceptive_rejected);
        assert!(!response.verified);
        assert_eq!(response.evidence_level.as_deref(), Some("E0HypothesisOnly"));
    }
}
