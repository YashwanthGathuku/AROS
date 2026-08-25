//! Loopback framed-IPC listener used to supervise a Python research worker.

use std::process::{Child, Command, Stdio};
use std::time::Duration;

use prost::Message;
use thiserror::Error;
use tokio::net::{TcpListener, TcpStream};
use tokio::time::timeout;

use crate::frame::{default_max_frame, read_envelope, write_envelope, IpcError};
use crate::messages::{envelope, Envelope, HelloAck, PROTOCOL_VERSION};

#[derive(Debug, Error)]
pub enum SessionError {
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
    #[error("ipc: {0}")]
    Ipc(#[from] IpcError),
    #[error("handshake timeout")]
    Timeout,
    #[error("worker exited before handshake: {0}")]
    WorkerExit(i32),
    #[error("expected hello, got other envelope")]
    NotHello,
    #[error("no connected worker stream")]
    NoStream,
    #[error("worker token mismatch")]
    BadToken,
}

pub struct WorkerSupervisor {
    pub listener_addr: String,
    pub expected_token: String,
    child: Option<Child>,
    stream: Option<TcpStream>,
}

impl WorkerSupervisor {
    pub async fn bind_loopback() -> Result<(Self, TcpListener), SessionError> {
        let listener = TcpListener::bind("127.0.0.1:0").await?;
        let addr = listener.local_addr()?.to_string();
        Ok((
            Self {
                listener_addr: addr,
                expected_token: uuid::Uuid::new_v4().to_string(),
                child: None,
                stream: None,
            },
            listener,
        ))
    }

    pub fn spawn_python(
        &mut self,
        python: &str,
        extra_args: &[&str],
        pythonpath: &str,
    ) -> Result<(), SessionError> {
        let mut cmd = Command::new(python);
        cmd.args([
            "-m",
            "aros_research.worker",
            "--tcp",
            &self.listener_addr,
            "--token",
            &self.expected_token,
        ]);
        cmd.args(extra_args);
        cmd.env("PYTHONPATH", pythonpath);
        cmd.stdin(Stdio::null());
        cmd.stdout(Stdio::piped());
        cmd.stderr(Stdio::piped());
        self.child = Some(cmd.spawn()?);
        Ok(())
    }

    pub async fn accept_hello(&mut self, listener: &TcpListener) -> Result<String, SessionError> {
        let (mut stream, _) = timeout(Duration::from_secs(10), listener.accept())
            .await
            .map_err(|_| SessionError::Timeout)?
            .map_err(SessionError::Io)?;
        let env = timeout(
            Duration::from_secs(10),
            read_envelope(&mut stream, default_max_frame()),
        )
        .await
        .map_err(|_| SessionError::Timeout)??;
        let py_ver = match &env.kind {
            Some(envelope::Kind::Hello(h)) => {
                if h.token != self.expected_token {
                    return Err(SessionError::BadToken);
                }
                h.python_version.clone()
            }
            _ => return Err(SessionError::NotHello),
        };
        let ack = Envelope {
            protocol_version: PROTOCOL_VERSION,
            request_id: env.request_id,
            kind: Some(envelope::Kind::HelloAck(HelloAck {
                daemon_version: env!("CARGO_PKG_VERSION").into(),
                max_frame_bytes: default_max_frame(),
                campaign_id: String::new(),
                manifest_hash: String::new(),
            })),
        };
        write_envelope(&mut stream, &ack, default_max_frame()).await?;
        self.stream = Some(stream);
        Ok(py_ver)
    }

    pub async fn read_next(&mut self) -> Result<Envelope, SessionError> {
        let stream = self.stream.as_mut().ok_or(SessionError::NoStream)?;
        Ok(read_envelope(stream, default_max_frame()).await?)
    }

    pub async fn write_next(&mut self, env: Envelope) -> Result<(), SessionError> {
        let stream = self.stream.as_mut().ok_or(SessionError::NoStream)?;
        write_envelope(stream, &env, default_max_frame()).await?;
        Ok(())
    }

    pub fn worker_alive(&mut self) -> bool {
        match self.child.as_mut() {
            Some(c) => c.try_wait().ok().flatten().is_none(),
            None => false,
        }
    }

    pub fn kill_worker(&mut self) {
        if let Some(c) = self.child.as_mut() {
            let _ = c.kill();
            let _ = c.wait();
        }
        self.child = None;
    }
}

impl Drop for WorkerSupervisor {
    fn drop(&mut self) {
        self.kill_worker();
    }
}

/// Decode a Python-produced Hello envelope (used by cross-language tests).
pub fn decode_hello_python_version(bytes: &[u8]) -> Result<String, IpcError> {
    if bytes.len() < 5 {
        return Err(IpcError::Decode);
    }
    let len = u32::from_be_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]) as usize;
    if 4 + len > bytes.len() {
        return Err(IpcError::Decode);
    }
    let env = Envelope::decode(&bytes[4..4 + len]).map_err(|_| IpcError::Decode)?;
    match env.kind {
        Some(envelope::Kind::Hello(h)) => Ok(h.python_version),
        _ => Err(IpcError::EmptyKind),
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;
    use crate::messages::IntentResult;
    use std::io::Write;
    use std::path::PathBuf;
    use std::process::{Command, Stdio};

    fn python_bin() -> String {
        std::env::var("AROS_PYTHON").unwrap_or_else(|_| "python".into())
    }

    fn repo_pythonpath() -> String {
        let root = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("../..")
            .join("python");
        root.to_string_lossy().into_owned()
    }

    #[tokio::test]
    async fn python_hello_roundtrip_and_crash_does_not_kill_supervisor() {
        let py = python_bin();
        let check = Command::new(&py)
            .args(["-c", "import aros_research"])
            .env("PYTHONPATH", repo_pythonpath())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status();
        if !check.map(|s| s.success()).unwrap_or(false) {
            eprintln!("skip: python worker import failed");
            return;
        }

        let (mut sup, listener) = WorkerSupervisor::bind_loopback().await.unwrap();
        sup.spawn_python(&py, &["--crash-after-hello"], &repo_pythonpath())
            .unwrap();
        let ver = sup.accept_hello(&listener).await.unwrap();
        assert!(ver.starts_with("3."));
        // Worker requested crash after hello; supervisor (this test process) continues.
        for _ in 0..50 {
            if !sup.worker_alive() {
                break;
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
        assert!(!sup.worker_alive());
        let _ = std::io::stderr().write_all(b"supervisor still running after worker crash\n");
    }

    #[tokio::test]
    async fn python_tool_intent_closed_loop_with_intent_result() {
        let py = python_bin();
        let check = Command::new(&py)
            .args(["-c", "import aros_research"])
            .env("PYTHONPATH", repo_pythonpath())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status();
        if !check.map(|s| s.success()).unwrap_or(false) {
            return;
        }
        let (mut sup, listener) = WorkerSupervisor::bind_loopback().await.unwrap();
        sup.spawn_python(
            &py,
            &[
                "--probe-intent",
                "fuzz_adapter",
                "--probe-path",
                "/var/run/docker.sock",
            ],
            &repo_pythonpath(),
        )
        .unwrap();
        let _ver = sup.accept_hello(&listener).await.unwrap();
        let env = sup.read_next().await.unwrap();
        let request_id = env.request_id.clone();
        match env.kind {
            Some(envelope::Kind::ToolIntent(t)) => {
                assert_eq!(t.capability, "fuzz_adapter");
                assert_eq!(t.path.as_deref(), Some("/var/run/docker.sock"));
            }
            other => panic!("expected tool intent, got {other:?}"),
        }
        // Complete the closed loop: policy layer would DENY this; reply accordingly.
        let reply = Envelope {
            protocol_version: PROTOCOL_VERSION,
            request_id,
            kind: Some(envelope::Kind::IntentResult(IntentResult {
                decision: "DENY".into(),
                reason: "capability fuzz_adapter is not on the tool allowlist".into(),
                exit_status: None,
                stdout_digest: None,
            })),
        };
        sup.write_next(reply).await.unwrap();
        // Worker should exit after receiving IntentResult.
        for _ in 0..50 {
            if !sup.worker_alive() {
                break;
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
        assert!(!sup.worker_alive(), "worker should exit after IntentResult");
    }
}
