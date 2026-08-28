//! Integration tests for independent verifier reproduction against real targets.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::io::Write;
use std::process::{Command, Stdio};

use aros_core::{
    snapshot::snapshot_tree, FixtureReplayKind, VerifierInput, VerifierOracle,
    VerifierProcessResult, VerifierReplay,
};
use aros_types::TargetId;

const AUTHZ_SERVER: &str = r#"
import json, os
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
USERS={"1":{"id":"1","secret":"alice-secret"},"2":{"id":"2","secret":"bob-secret"}}
VULN_IDOR=True
class H(BaseHTTPRequestHandler):
    def log_message(self,*a): pass
    def do_GET(self):
        if self.path=="/health": return self.j(200,{"ok":True})
        if self.path.startswith("/users/"):
            uid=self.path.rsplit("/",1)[-1]
            cookie=self.headers.get("Cookie","")
            caller=next((p.strip().split("=",1)[1] for p in cookie.split(";") if p.strip().startswith("user=")),None)
            if not VULN_IDOR and caller != uid: return self.j(403,{"error":"forbidden"})
            return self.j(200,USERS[uid])
        return self.j(404,{"error":"no"})
    def j(self,status,body):
        data=json.dumps(body).encode(); self.send_response(status); self.send_header("Content-Length",str(len(data))); self.end_headers(); self.wfile.write(data)
ThreadingHTTPServer(("127.0.0.1",int(os.environ["AROS_FIXTURE_PORT"])),H).serve_forever()
"#;

const PATCHED_AUTHZ_SERVER: &str = r#"
import json, os
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
USERS={"1":{"id":"1","secret":"alice-secret"},"2":{"id":"2","secret":"bob-secret"}}
VULN_IDOR=False
class H(BaseHTTPRequestHandler):
    def log_message(self,*a): pass
    def do_GET(self):
        if self.path=="/health": return self.j(200,{"ok":True})
        if self.path.startswith("/users/"):
            uid=self.path.rsplit("/",1)[-1]
            cookie=self.headers.get("Cookie","")
            caller=next((p.strip().split("=",1)[1] for p in cookie.split(";") if p.strip().startswith("user=")),None)
            if caller != uid: return self.j(403,{"error":"forbidden"})
            return self.j(200,USERS[uid])
        return self.j(404,{"error":"no"})
    def j(self,status,body):
        data=json.dumps(body).encode(); self.send_response(status); self.send_header("Content-Length",str(len(data))); self.end_headers(); self.wfile.write(data)
ThreadingHTTPServer(("127.0.0.1",int(os.environ["AROS_FIXTURE_PORT"])),H).serve_forever()
"#;

const PATH_SERVER: &str = r#"
import os
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs,urlparse
ROOT=Path(__file__).resolve().parent/"data"; VULN_PATH=True
class H(BaseHTTPRequestHandler):
    def log_message(self,*a): pass
    def do_GET(self):
        p=urlparse(self.path)
        if p.path=="/health": return self.s(200,b"ok")
        if p.path!="/files": return self.s(404,b"no")
        rel=parse_qs(p.query).get("path",[""])[0]
        target=(ROOT/rel).resolve()
        if not target.is_file(): return self.s(404,b"missing")
        return self.s(200,target.read_bytes())
    def s(self,status,body): self.send_response(status); self.send_header("Content-Length",str(len(body))); self.end_headers(); self.wfile.write(body)
ThreadingHTTPServer(("127.0.0.1",int(os.environ["AROS_FIXTURE_PORT"])),H).serve_forever()
"#;

fn run_real_verifier(input: &VerifierInput) -> VerifierProcessResult {
    let verifier = env!("CARGO_BIN_EXE_aros-verifier");
    let mut child = Command::new(verifier)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    child
        .stdin
        .take()
        .unwrap()
        .write_all(&serde_json::to_vec(input).unwrap())
        .unwrap();
    let output = child.wait_with_output().unwrap();
    assert!(
        output.status.success(),
        "verifier stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    serde_json::from_slice(&output.stdout).unwrap()
}

fn oracle_contains(needle: &str) -> VerifierOracle {
    VerifierOracle {
        expected_status: Some(200),
        body_contains: Some(needle.into()),
        body_not_contains: None,
    }
}

#[test]
fn verifier_process_executes_actual_target_and_observes_oracle() {
    let fixture = tempfile::tempdir().unwrap();
    std::fs::write(fixture.path().join("server.py"), AUTHZ_SERVER).unwrap();
    let snapshot = snapshot_tree(TargetId::new(), fixture.path()).unwrap();
    let input = VerifierInput {
        claim: "user 1 can read user 2".into(),
        snapshot_id: snapshot.id.to_string(),
        oracle_contract: "cross-user request returns user-2 secret".into(),
        invariant: "tenant isolation".into(),
        replay: Some(VerifierReplay {
            target_root: fixture.path().to_string_lossy().into_owned(),
            expected_tree_digest: snapshot.source_tree_digest.clone(),
            kind: FixtureReplayKind::Authz,
            request_path: "/users/2".into(),
            cookie: Some("user=1".into()),
            oracle: oracle_contains("bob-secret"),
        }),
    };
    let result = run_real_verifier(&input);
    assert!(result.accepted, "{}", result.reason);
    assert_eq!(
        result.target_digest_observed.as_deref(),
        Some(snapshot.source_tree_digest.as_str())
    );
}

#[test]
fn verifier_rejects_patched_target_even_without_cookie() {
    let fixture = tempfile::tempdir().unwrap();
    std::fs::write(fixture.path().join("server.py"), PATCHED_AUTHZ_SERVER).unwrap();
    let snapshot = snapshot_tree(TargetId::new(), fixture.path()).unwrap();
    let input = VerifierInput {
        claim: "anonymous caller reads user 2".into(),
        snapshot_id: snapshot.id.to_string(),
        oracle_contract: "response contains user-2 secret".into(),
        invariant: "tenant isolation".into(),
        replay: Some(VerifierReplay {
            target_root: fixture.path().to_string_lossy().into_owned(),
            expected_tree_digest: snapshot.source_tree_digest,
            kind: FixtureReplayKind::Authz,
            request_path: "/users/2".into(),
            cookie: None,
            oracle: oracle_contains("bob-secret"),
        }),
    };
    let result = run_real_verifier(&input);
    assert!(!result.accepted, "patched target must not be reproduced");
    assert!(!result.oracle_observed);
}

#[test]
fn exact_target_mutation_is_rejected_by_real_verifier() {
    let fixture = tempfile::tempdir().unwrap();
    std::fs::create_dir(fixture.path().join("data")).unwrap();
    std::fs::write(fixture.path().join("secret.txt"), "fixture-path-secret").unwrap();
    std::fs::write(fixture.path().join("server.py"), PATH_SERVER).unwrap();
    let snapshot = snapshot_tree(TargetId::new(), fixture.path()).unwrap();
    std::fs::write(fixture.path().join("server.py"), format!("{PATH_SERVER}\n# mutation\n")).unwrap();

    let input = VerifierInput {
        claim: "path traversal".into(),
        snapshot_id: snapshot.id.to_string(),
        oracle_contract: "body contains fixture-path-secret".into(),
        invariant: "data root confinement".into(),
        replay: Some(VerifierReplay {
            target_root: fixture.path().to_string_lossy().into_owned(),
            expected_tree_digest: snapshot.source_tree_digest,
            kind: FixtureReplayKind::Path,
            request_path: "/files?path=../secret.txt".into(),
            cookie: None,
            oracle: oracle_contains("fixture-path-secret"),
        }),
    };
    let result = run_real_verifier(&input);
    assert!(!result.accepted);
    assert!(result.reason.contains("digest mismatch"));
}
