//! Lab fixture campaign entry points for arosd.

use std::net::TcpListener;
use std::path::{Path, PathBuf};
use std::thread;

use aros_core::{fixture_manifest, CampaignEngine, CampaignOutcome, EngineError, FixtureKind};
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
    /// Absolute path to fixture tree (must contain server.py markers for authz/path).
    pub fixture_root: String,
    /// Working directory for CAS, twin, sqlite.
    pub work_root: String,
    pub kind: FixtureKindParam,
    /// When true, waive containment for lab/unit runs (never for production).
    #[serde(default = "default_waive")]
    pub waive_containment: bool,
}

fn default_waive() -> bool {
    true
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
}

impl From<CampaignOutcome> for FixtureCampaignResponse {
    fn from(out: CampaignOutcome) -> Self {
        let verified = out.finding.as_ref().is_some_and(|f| f.verified);
        let claim = out.finding.as_ref().map(|f| f.claim.clone());
        let evidence_level = out.evidence_level.map(|l| format!("{l:?}"));
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
        }
    }
}

/// Spawn a minimal loopback HTTP fixture server matching engine tests.
pub fn spawn_fixture_server(
    kind: FixtureKind,
    vulnerable: bool,
) -> Result<(u16, thread::JoinHandle<()>), String> {
    let listener = TcpListener::bind("127.0.0.1:0").map_err(|e| e.to_string())?;
    let port = listener
        .local_addr()
        .map_err(|e| e.to_string())?
        .port();
    let h = thread::spawn(move || {
        use std::io::{Read, Write};
        for stream in listener.incoming().flatten() {
            let mut stream = stream;
            let mut buf = [0u8; 4096];
            let n = stream.read(&mut buf).unwrap_or(0);
            let req = String::from_utf8_lossy(&buf[..n]);
            let body = match kind {
                FixtureKind::Authz => {
                    let cookie_is_user1 = req.contains("Cookie: user=1");
                    let path_users2 = req.contains("GET /users/2 ");
                    if path_users2 {
                        if vulnerable || !cookie_is_user1 {
                            "{\"id\":2,\"secret\":\"bob-secret\"}"
                        } else {
                            "{\"error\":\"forbidden\"}"
                        }
                    } else {
                        "{\"ok\":true}"
                    }
                }
                FixtureKind::Path => {
                    if vulnerable && (req.contains("../secret") || req.contains("path=../")) {
                        "fixture-path-secret"
                    } else {
                        "public-ok"
                    }
                }
                FixtureKind::Deceptive => {
                    if req.contains("GET /pwned ") {
                        "{\"status\":\"hacked\",\"pwned\":true}"
                    } else {
                        "{\"error\":\"forbidden\"}"
                    }
                }
            };
            let status = if body.contains("forbidden") {
                "403 Forbidden"
            } else {
                "200 OK"
            };
            let resp = format!(
                "HTTP/1.1 {status}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                body.len()
            );
            let _ = stream.write_all(resp.as_bytes());
        }
    });
    Ok((port, h))
}

pub fn run_fixture_campaign(
    req: &FixtureCampaignRequest,
) -> Result<FixtureCampaignResponse, String> {
    let fixture_root = PathBuf::from(&req.fixture_root);
    let work_root = PathBuf::from(&req.work_root);
    if !fixture_root.is_dir() {
        return Err(format!("fixture_root is not a directory: {}", req.fixture_root));
    }
    std::fs::create_dir_all(&work_root).map_err(|e| e.to_string())?;

    let kind = FixtureKind::from(req.kind.clone());
    let (vuln_port, _vuln_server) = spawn_fixture_server(kind, true)?;
    // Patched twin HTTP surface for live re-attack (authz/path only).
    let patched_port = if matches!(kind, FixtureKind::Authz | FixtureKind::Path) {
        let (p, _patched_server) = spawn_fixture_server(kind, false)?;
        Some(p)
    } else {
        None
    };

    let engine = CampaignEngine::new(req.waive_containment);
    let manifest = fixture_manifest(
        &fixture_root.to_string_lossy(),
        "127.0.0.1",
        vuln_port,
        !req.waive_containment,
    );

    match engine.run_fixture_campaign(
        &fixture_root,
        &work_root,
        "127.0.0.1",
        vuln_port,
        patched_port,
        kind,
        manifest,
    ) {
        Ok(out) => Ok(FixtureCampaignResponse::from(out)),
        Err(EngineError::FailClosed(msg)) => Err(msg),
        Err(other) => Err(other.to_string()),
    }
}

/// Prepare a minimal on-disk fixture tree for lab runs.
pub fn seed_fixture(kind: FixtureKind, root: &Path) -> Result<(), String> {
    std::fs::create_dir_all(root).map_err(|e| e.to_string())?;
    let content = match kind {
        FixtureKind::Authz => "VULN_IDOR = True\n# GET /users/{id}\n",
        FixtureKind::Path => "VULN_PATH = True\n",
        FixtureKind::Deceptive => "# deceptive body only\n",
    };
    std::fs::write(root.join("server.py"), content).map_err(|e| e.to_string())?;
    Ok(())
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    #[test]
    fn authz_fixture_campaign_live_reattack_confirmed() {
        let fixture = tempfile::tempdir().unwrap();
        seed_fixture(FixtureKind::Authz, fixture.path()).unwrap();
        let work = tempfile::tempdir().unwrap();
        let req = FixtureCampaignRequest {
            fixture_root: fixture.path().to_string_lossy().into_owned(),
            work_root: work.path().to_string_lossy().into_owned(),
            kind: FixtureKindParam::Authz,
            waive_containment: true,
        };
        let resp = run_fixture_campaign(&req).unwrap();
        assert!(resp.verified, "claim={:?}", resp.claim);
        assert!(resp.original_unmodified);
        assert!(!resp.deceptive_rejected);
        assert!(resp.live_reattack_confirmed);
        assert!(resp.evidence_level.is_some());
    }

    #[test]
    fn deceptive_fixture_is_rejected() {
        let fixture = tempfile::tempdir().unwrap();
        seed_fixture(FixtureKind::Deceptive, fixture.path()).unwrap();
        let work = tempfile::tempdir().unwrap();
        let req = FixtureCampaignRequest {
            fixture_root: fixture.path().to_string_lossy().into_owned(),
            work_root: work.path().to_string_lossy().into_owned(),
            kind: FixtureKindParam::Deceptive,
            waive_containment: true,
        };
        let resp = run_fixture_campaign(&req).unwrap();
        assert!(resp.deceptive_rejected);
        assert!(!resp.verified);
        assert!(resp.original_unmodified);
        assert!(!resp.live_reattack_confirmed);
    }
}
