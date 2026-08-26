use std::io::{Read, Write};
use std::net::{Ipv4Addr, Shutdown, SocketAddr, TcpStream};
use std::time::Duration;

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
///
/// When `AROS_THEUSTAD_URL` is set to an `http://127.0.0.1` endpoint, the
/// adapter POSTs the evidence bundle and fails closed on transport errors.
pub struct TheustadAdapter {
    pub endpoint: Option<String>,
}

impl TheustadAdapter {
    pub fn unavailable() -> Self {
        Self { endpoint: None }
    }

    pub fn from_env() -> Self {
        let endpoint = std::env::var("AROS_THEUSTAD_URL")
            .ok()
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty());
        Self { endpoint }
    }

    pub fn is_available(&self) -> bool {
        self.endpoint.is_some()
    }

    fn query_remote(&self, bundle: &EvidenceBundle, verifier: &VerifierRun) -> AuthorityResult {
        let Some(url) = &self.endpoint else {
            return BuiltinEvidenceAuthority.adjudicate(bundle, verifier);
        };
        let payload = serde_json::json!({
            "bundle": bundle,
            "verifier_result": verifier.result,
            "verifier_mode": verifier.mode,
        });
        match post_loopback_json(url, &payload) {
            Ok((_status, body)) => {
                parse_authority_body(&body).unwrap_or(AuthorityResult::InsufficientEvidence)
            }
            Err(_) => AuthorityResult::InsufficientEvidence,
        }
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
        self.query_remote(bundle, verifier)
    }
}

fn parse_authority_body(body: &str) -> Option<AuthorityResult> {
    if let Ok(v) = serde_json::from_str::<AuthorityResult>(body.trim()) {
        return Some(v);
    }
    let value: serde_json::Value = serde_json::from_str(body).ok()?;
    let token = value
        .get("result")
        .or_else(|| value.get("authority_result"))
        .cloned()
        .unwrap_or(value);
    serde_json::from_value(token).ok()
}

/// POST JSON to an http:// loopback URL. Non-loopback hosts are refused.
fn post_loopback_json(url: &str, body: &serde_json::Value) -> Result<(u16, String), String> {
    let rest = url
        .strip_prefix("http://")
        .ok_or_else(|| "THEUSTAD URL must be http://127.0.0.1 in v0.1".to_string())?;
    let (hostport, path_owned) = match rest.split_once('/') {
        Some((h, "")) => (h, "/".to_string()),
        Some((h, p)) => (h, format!("/{p}")),
        None => (rest, "/".to_string()),
    };
    let (host, port): (&str, u16) = if let Some((h, p)) = hostport.rsplit_once(':') {
        let port: u16 = p.parse().map_err(|_| "invalid THEUSTAD port".to_string())?;
        (h, port)
    } else {
        (hostport, 80)
    };
    if host != "127.0.0.1" && host != "localhost" && host != "[::1]" && host != "::1" {
        return Err("THEUSTAD URL must be loopback in v0.1".into());
    }
    let bytes = serde_json::to_vec(body).map_err(|e| e.to_string())?;
    let addr = if host == "127.0.0.1" || host == "localhost" {
        SocketAddr::from((Ipv4Addr::LOCALHOST, port))
    } else {
        return Err("THEUSTAD URL must be loopback in v0.1".into());
    };
    let mut stream = TcpStream::connect(addr).map_err(|e| format!("THEUSTAD connect: {e}"))?;
    stream
        .set_read_timeout(Some(Duration::from_secs(3)))
        .map_err(|e| e.to_string())?;
    stream
        .set_write_timeout(Some(Duration::from_secs(3)))
        .map_err(|e| e.to_string())?;
    let req = format!(
        "POST {path_owned} HTTP/1.1\r\nHost: {host}:{port}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
        bytes.len()
    );
    stream
        .write_all(req.as_bytes())
        .map_err(|e| e.to_string())?;
    stream.write_all(&bytes).map_err(|e| e.to_string())?;
    let _ = stream.shutdown(Shutdown::Write);
    let mut buf = Vec::new();
    stream.read_to_end(&mut buf).map_err(|e| e.to_string())?;
    let raw = String::from_utf8_lossy(&buf);
    let (head, resp_body) = raw.split_once("\r\n\r\n").unwrap_or((raw.as_ref(), ""));
    let status = head
        .lines()
        .next()
        .and_then(|l| l.split_whitespace().nth(1))
        .and_then(|s| s.parse().ok())
        .unwrap_or(0);
    Ok((status, resp_body.to_string()))
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;
    use aros_types::{
        CampaignId, EvidenceLevel, FindingId, SnapshotId, VerifierMode, VerifierRun, VerifierRunId,
    };
    use std::io::{Read, Write};
    use std::net::{Shutdown, TcpListener};
    use std::thread;
    use std::time::Duration;

    fn sample_bundle() -> EvidenceBundle {
        EvidenceBundle {
            finding_id: FindingId::new(),
            campaign_id: CampaignId::new(),
            manifest_hash: "h".into(),
            snapshot_id: SnapshotId::new(),
            sandbox_id: None,
            claim: "idor".into(),
            artifact_digests: vec!["abc".into()],
            level: EvidenceLevel::E4IndependentReproduction,
        }
    }

    fn sample_run(result: AuthorityResult) -> VerifierRun {
        VerifierRun {
            id: VerifierRunId::new(),
            finding_id: FindingId::new(),
            campaign_id: CampaignId::new(),
            manifest_hash: "h".into(),
            mode: VerifierMode::ReproduceCandidate,
            result,
            notes: String::new(),
        }
    }

    #[test]
    fn unavailable_falls_back_to_builtin() {
        let a = TheustadAdapter::unavailable();
        assert!(!a.is_available());
        let r = a.adjudicate(&sample_bundle(), &sample_run(AuthorityResult::Verified));
        assert_eq!(r, AuthorityResult::Verified);
    }

    #[test]
    fn configured_but_down_fails_closed() {
        let a = TheustadAdapter {
            endpoint: Some("http://127.0.0.1:1/adjudicate".into()),
        };
        let r = a.adjudicate(&sample_bundle(), &sample_run(AuthorityResult::Verified));
        assert_eq!(r, AuthorityResult::InsufficientEvidence);
    }

    #[test]
    fn non_loopback_url_fails_closed() {
        let a = TheustadAdapter {
            endpoint: Some("http://8.8.8.8/adjudicate".into()),
        };
        let r = a.adjudicate(&sample_bundle(), &sample_run(AuthorityResult::Verified));
        assert_eq!(r, AuthorityResult::InsufficientEvidence);
    }

    #[test]
    fn parse_authority_body_reads_result_field() {
        assert_eq!(
            parse_authority_body(r#"{"result":"VERIFIED"}"#),
            Some(AuthorityResult::Verified)
        );
        assert_eq!(
            parse_authority_body("\"FALSIFIED\""),
            Some(AuthorityResult::Falsified)
        );
    }

    #[test]
    fn http_loopback_adjudicates() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        let h = thread::spawn(move || {
            if let Some(mut stream) = listener.incoming().flatten().next() {
                let _ = stream.set_read_timeout(Some(Duration::from_millis(200)));
                let mut buf = [0u8; 8192];
                loop {
                    match stream.read(&mut buf) {
                        Ok(0) | Err(_) => break,
                        Ok(_) => {}
                    }
                }
                let body = r#"{"result":"VERIFIED"}"#;
                let resp = format!(
                    "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                    body.len()
                );
                let _ = stream.write_all(resp.as_bytes());
                let _ = stream.shutdown(Shutdown::Write);
            }
        });
        thread::sleep(Duration::from_millis(30));
        let url = format!("http://127.0.0.1:{port}/adjudicate");
        let payload = serde_json::json!({"probe": true});
        let exchanged = post_loopback_json(&url, &payload);
        let _ = h.join();
        let (status, body) = exchanged.expect("THEUSTAD HTTP exchange");
        assert_eq!(status, 200, "body={body:?}");
        assert_eq!(
            parse_authority_body(&body),
            Some(AuthorityResult::Verified),
            "body={body:?}"
        );
        let adapter = TheustadAdapter {
            endpoint: Some(url),
        };
        // Server already closed; a second POST must fail closed, not builtin-verify.
        let second = adapter.adjudicate(&sample_bundle(), &sample_run(AuthorityResult::Verified));
        assert_eq!(second, AuthorityResult::InsufficientEvidence);
    }

    #[test]
    fn from_env_does_not_panic() {
        let _ = TheustadAdapter::from_env();
    }
}
