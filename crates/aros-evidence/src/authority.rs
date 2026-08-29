use std::io::{Read, Write};
use std::net::{Ipv4Addr, Shutdown, SocketAddr, TcpStream};
use std::time::Duration;

use aros_types::{
    env_name, AuthorityResult, EvidenceBundle, EvidenceLevel, VerifierMode, VerifierRun,
};

pub trait EvidenceAuthority {
    fn name(&self) -> &'static str;
    fn adjudicate(&self, bundle: &EvidenceBundle, verifier: &VerifierRun) -> AuthorityResult;
}

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

pub struct TheustadAdapter {
    pub endpoint: Option<String>,
}

impl TheustadAdapter {
    pub fn unavailable() -> Self {
        Self { endpoint: None }
    }

    pub fn from_env() -> Self {
        Self {
            endpoint: std::env::var(env_name("THEUSTAD_URL"))
                .ok()
                .map(|value| value.trim().to_string())
                .filter(|value| !value.is_empty()),
        }
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
            "verifier_mode": verifier.mode
        });
        match post_loopback_json(url, &payload) {
            Ok((status, body)) if (200..300).contains(&status) => {
                parse_authority_body(&body).unwrap_or(AuthorityResult::InsufficientEvidence)
            }
            Ok(_) | Err(_) => AuthorityResult::InsufficientEvidence,
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
    if let Ok(value) = serde_json::from_str::<AuthorityResult>(body.trim()) {
        return Some(value);
    }
    let value: serde_json::Value = serde_json::from_str(body).ok()?;
    let token = value
        .get("result")
        .or_else(|| value.get("authority_result"))
        .cloned()
        .unwrap_or(value);
    serde_json::from_value(token).ok()
}

fn post_loopback_json(url: &str, body: &serde_json::Value) -> Result<(u16, String), String> {
    let rest = url
        .strip_prefix("http://")
        .ok_or_else(|| "THEUSTAD URL must be http:// loopback in v0.1".to_string())?;
    let (hostport, path_owned) = match rest.split_once('/') {
        Some((host, "")) => (host, "/".to_string()),
        Some((host, path)) => (host, format!("/{path}")),
        None => (rest, "/".to_string()),
    };
    let (host, port): (&str, u16) = if let Some((host, port)) = hostport.rsplit_once(':') {
        (
            host,
            port.parse()
                .map_err(|_| "invalid THEUSTAD port".to_string())?,
        )
    } else {
        (hostport, 80)
    };
    if host != "127.0.0.1" && host != "localhost" && host != "[::1]" && host != "::1" {
        return Err("THEUSTAD URL must be loopback in v0.1".into());
    }
    let bytes = serde_json::to_vec(body).map_err(|error| error.to_string())?;
    let addr = if host == "127.0.0.1" || host == "localhost" {
        SocketAddr::from((Ipv4Addr::LOCALHOST, port))
    } else {
        return Err("IPv6 THEUSTAD loopback transport is not implemented in v0.1".into());
    };
    let mut stream =
        TcpStream::connect(addr).map_err(|error| format!("THEUSTAD connect: {error}"))?;
    stream
        .set_read_timeout(Some(Duration::from_secs(3)))
        .map_err(|error| error.to_string())?;
    stream
        .set_write_timeout(Some(Duration::from_secs(3)))
        .map_err(|error| error.to_string())?;
    let request = format!(
        "POST {path_owned} HTTP/1.1\r\nHost: {host}:{port}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
        bytes.len()
    );
    stream
        .write_all(request.as_bytes())
        .map_err(|error| error.to_string())?;
    stream
        .write_all(&bytes)
        .map_err(|error| error.to_string())?;
    let _ = stream.shutdown(Shutdown::Write);
    let mut buf = Vec::new();
    stream
        .read_to_end(&mut buf)
        .map_err(|error| error.to_string())?;
    let raw = String::from_utf8_lossy(&buf);
    let (head, response_body) = raw.split_once("\r\n\r\n").unwrap_or((raw.as_ref(), ""));
    let status = head
        .lines()
        .next()
        .and_then(|line| line.split_whitespace().nth(1))
        .and_then(|value| value.parse().ok())
        .unwrap_or(0);
    Ok((status, response_body.to_string()))
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;
    use aros_types::{CampaignId, FindingId, SnapshotId, VerifierRunId};
    use std::net::TcpListener;
    use std::thread;

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
        assert_eq!(
            TheustadAdapter::unavailable()
                .adjudicate(&sample_bundle(), &sample_run(AuthorityResult::Verified)),
            AuthorityResult::Verified
        );
    }

    #[test]
    fn configured_but_down_fails_closed() {
        let adapter = TheustadAdapter {
            endpoint: Some("http://127.0.0.1:1/adjudicate".into()),
        };
        assert_eq!(
            adapter.adjudicate(&sample_bundle(), &sample_run(AuthorityResult::Verified)),
            AuthorityResult::InsufficientEvidence
        );
    }

    #[test]
    fn non_loopback_url_fails_closed() {
        let adapter = TheustadAdapter {
            endpoint: Some("http://8.8.8.8/adjudicate".into()),
        };
        assert_eq!(
            adapter.adjudicate(&sample_bundle(), &sample_run(AuthorityResult::Verified)),
            AuthorityResult::InsufficientEvidence
        );
    }

    fn serve_once(status: &'static str, body: &'static str) -> String {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        thread::spawn(move || {
            if let Some(mut stream) = listener.incoming().flatten().next() {
                let _ = stream.set_read_timeout(Some(Duration::from_millis(100)));
                let mut buf = [0u8; 8192];
                let _ = stream.read(&mut buf);
                let response = format!(
                    "HTTP/1.1 {status}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                    body.len()
                );
                let _ = stream.write_all(response.as_bytes());
            }
        });
        format!("http://127.0.0.1:{port}/adjudicate")
    }

    #[test]
    fn http_2xx_adjudicates() {
        let url = serve_once("200 OK", r#"{"result":"VERIFIED"}"#);
        std::thread::sleep(Duration::from_millis(20));
        let adapter = TheustadAdapter {
            endpoint: Some(url),
        };
        assert_eq!(
            adapter.adjudicate(&sample_bundle(), &sample_run(AuthorityResult::Verified)),
            AuthorityResult::Verified
        );
    }

    #[test]
    fn non_2xx_fails_closed_even_with_verified_body() {
        let url = serve_once("500 Internal Server Error", r#"{"result":"VERIFIED"}"#);
        std::thread::sleep(Duration::from_millis(20));
        let adapter = TheustadAdapter {
            endpoint: Some(url),
        };
        assert_eq!(
            adapter.adjudicate(&sample_bundle(), &sample_run(AuthorityResult::Verified)),
            AuthorityResult::InsufficientEvidence
        );
    }

    #[test]
    fn from_env_does_not_panic() {
        let _ = TheustadAdapter::from_env();
    }
}
