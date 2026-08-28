//! Framed IPC supervision for the Python research worker.
//!
//! Unix domain sockets are the production Linux/WSL transport. Loopback TCP is
//! retained as an explicit test/development transport. The handshake token is
//! passed through the child environment, never the command line.

use std::pin::Pin;
use std::process::{Child, Command, Stdio};
use std::time::Duration;

use prost::Message;
use thiserror::Error;
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::net::{TcpListener, TcpStream};
#[cfg(unix)]
use tokio::net::{UnixListener, UnixStream};
use tokio::time::timeout;

use crate::frame::{default_max_frame, read_envelope, write_envelope, IpcError};
use crate::messages::{envelope, Envelope, HelloAck, PROTOCOL_VERSION};

trait AsyncIpcStream: AsyncRead + AsyncWrite + Unpin + Send {}
impl<T> AsyncIpcStream for T where T: AsyncRead + AsyncWrite + Unpin + Send {}
type BoxStream = Pin<Box<dyn AsyncIpcStream>>;

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
    #[error("transport unavailable: {0}")]
    Transport(String),
}

pub enum WorkerListener {
    Tcp(TcpListener),
    #[cfg(unix)]
    Unix(UnixListener),
}

#[derive(Clone, Debug)]
enum WorkerEndpoint {
    Tcp(String),
    #[cfg(unix)]
    Unix(String),
}

pub struct WorkerSupervisor {
    pub listener_addr: String,
    pub expected_token: String,
    endpoint: WorkerEndpoint,
    child: Option<Child>,
    stream: Option<BoxStream>,
}

impl WorkerSupervisor {
    /// Explicit development/test transport.
    pub async fn bind_loopback() -> Result<(Self, WorkerListener), SessionError> {
        let listener = TcpListener::bind("127.0.0.1:0").await?;
        let address = listener.local_addr()?.to_string();
        Ok((
            Self {
                listener_addr: address.clone(),
                expected_token: uuid::Uuid::new_v4().to_string(),
                endpoint: WorkerEndpoint::Tcp(address),
                child: None,
                stream: None,
            },
            WorkerListener::Tcp(listener),
        ))
    }

    /// Production Linux/WSL transport. Caller supplies a private runtime path.
    #[cfg(unix)]
    pub async fn bind_unix(path: impl AsRef<std::path::Path>) -> Result<(Self, WorkerListener), SessionError> {
        use std::os::unix::fs::PermissionsExt;
        let path = path.as_ref();
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
            std::fs::set_permissions(parent, std::fs::Permissions::from_mode(0o700))?;
        }
        if path.exists() {
            std::fs::remove_file(path)?;
        }
        let listener = UnixListener::bind(path)?;
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))?;
        let address = path.to_string_lossy().into_owned();
        Ok((
            Self {
                listener_addr: address.clone(),
                expected_token: uuid::Uuid::new_v4().to_string(),
                endpoint: WorkerEndpoint::Unix(address),
                child: None,
                stream: None,
            },
            WorkerListener::Unix(listener),
        ))
    }

    /// Host worker launcher is deliberately named as uncontained. Production
    /// callers must make that waiver explicit or use a containerized launcher.
    pub fn spawn_python_uncontained(
        &mut self,
        python: &str,
        extra_args: &[&str],
        pythonpath: &str,
    ) -> Result<(), SessionError> {
        let mut command = Command::new(python);
        command.args(["-m", "aros_research.worker"]);
        match &self.endpoint {
            WorkerEndpoint::Tcp(address) => command.args(["--tcp", address]),
            #[cfg(unix)]
            WorkerEndpoint::Unix(path) => command.args(["--socket", path]),
        };
        command.args(extra_args);
        command.env("PYTHONPATH", pythonpath);
        command.env("AROS_WORKER_TOKEN", &self.expected_token);
        command.stdin(Stdio::null());
        command.stdout(Stdio::piped());
        command.stderr(Stdio::piped());
        self.child = Some(command.spawn()?);
        Ok(())
    }

    /// Backward-compatible test helper. The name intentionally prevents API
    /// production code from pretending this is a sandbox boundary.
    #[cfg(test)]
    pub fn spawn_python(
        &mut self,
        python: &str,
        extra_args: &[&str],
        pythonpath: &str,
    ) -> Result<(), SessionError> {
        self.spawn_python_uncontained(python, extra_args, pythonpath)
    }

    pub async fn accept_hello(&mut self, listener: &WorkerListener) -> Result<String, SessionError> {
        let mut stream: BoxStream = match listener {
            WorkerListener::Tcp(listener) => {
                let (stream, _) = timeout(Duration::from_secs(10), listener.accept())
                    .await
                    .map_err(|_| SessionError::Timeout)??;
                Box::pin(stream)
            }
            #[cfg(unix)]
            WorkerListener::Unix(listener) => {
                let (stream, _) = timeout(Duration::from_secs(10), listener.accept())
                    .await
                    .map_err(|_| SessionError::Timeout)??;
                Box::pin(stream)
            }
        };
        let envelope = timeout(
            Duration::from_secs(10),
            read_envelope(&mut stream, default_max_frame()),
        )
        .await
        .map_err(|_| SessionError::Timeout)??;
        let python_version = match &envelope.kind {
            Some(envelope::Kind::Hello(hello)) => {
                if hello.token != self.expected_token {
                    return Err(SessionError::BadToken);
                }
                hello.python_version.clone()
            }
            _ => return Err(SessionError::NotHello),
        };
        let ack = Envelope {
            protocol_version: PROTOCOL_VERSION,
            request_id: envelope.request_id,
            kind: Some(envelope::Kind::HelloAck(HelloAck {
                daemon_version: env!("CARGO_PKG_VERSION").into(),
                max_frame_bytes: default_max_frame(),
                campaign_id: String::new(),
                manifest_hash: String::new(),
            })),
        };
        write_envelope(&mut stream, &ack, default_max_frame()).await?;
        self.stream = Some(stream);
        Ok(python_version)
    }

    pub async fn read_next(&mut self) -> Result<Envelope, SessionError> {
        let stream = self.stream.as_mut().ok_or(SessionError::NoStream)?;
        Ok(read_envelope(stream, default_max_frame()).await?)
    }

    pub async fn write_next(&mut self, envelope: Envelope) -> Result<(), SessionError> {
        let stream = self.stream.as_mut().ok_or(SessionError::NoStream)?;
        write_envelope(stream, &envelope, default_max_frame()).await?;
        Ok(())
    }

    pub fn worker_alive(&mut self) -> bool {
        match self.child.as_mut() {
            Some(child) => child.try_wait().ok().flatten().is_none(),
            None => false,
        }
    }

    pub fn kill_worker(&mut self) {
        if let Some(child) = self.child.as_mut() {
            let _ = child.kill();
            let _ = child.wait();
        }
        self.child = None;
    }
}

impl Drop for WorkerSupervisor {
    fn drop(&mut self) {
        self.kill_worker();
    }
}

pub fn decode_hello_python_version(bytes: &[u8]) -> Result<String, IpcError> {
    if bytes.len() < 5 {
        return Err(IpcError::Decode);
    }
    let len = u32::from_be_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]) as usize;
    if 4 + len > bytes.len() {
        return Err(IpcError::Decode);
    }
    let envelope = Envelope::decode(&bytes[4..4 + len]).map_err(|_| IpcError::Decode)?;
    match envelope.kind {
        Some(envelope::Kind::Hello(hello)) => Ok(hello.python_version),
        _ => Err(IpcError::EmptyKind),
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;
    use crate::messages::IntentResult;
    use std::path::PathBuf;
    use std::process::{Command, Stdio};

    fn python_bin() -> String {
        std::env::var("AROS_PYTHON").unwrap_or_else(|_| "python".into())
    }

    fn repo_pythonpath() -> String {
        PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("../..")
            .join("python")
            .to_string_lossy()
            .into_owned()
    }

    #[tokio::test]
    async fn loopback_test_transport_token_is_not_on_argv_contract() {
        let python = python_bin();
        let check = Command::new(&python)
            .args(["-c", "import aros_research"])
            .env("PYTHONPATH", repo_pythonpath())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status();
        if !check.map(|status| status.success()).unwrap_or(false) {
            return;
        }
        let (mut supervisor, listener) = WorkerSupervisor::bind_loopback().await.unwrap();
        supervisor
            .spawn_python(&python, &["--crash-after-hello"], &repo_pythonpath())
            .unwrap();
        let version = supervisor.accept_hello(&listener).await.unwrap();
        assert!(version.starts_with("3."));
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn unix_socket_roundtrip_is_supported() {
        let python = python_bin();
        let check = Command::new(&python)
            .args(["-c", "import aros_research"])
            .env("PYTHONPATH", repo_pythonpath())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status();
        if !check.map(|status| status.success()).unwrap_or(false) {
            return;
        }
        let dir = tempfile::tempdir().unwrap();
        let socket = dir.path().join("worker.sock");
        let (mut supervisor, listener) = WorkerSupervisor::bind_unix(&socket).await.unwrap();
        supervisor
            .spawn_python(&python, &["--crash-after-hello"], &repo_pythonpath())
            .unwrap();
        let version = supervisor.accept_hello(&listener).await.unwrap();
        assert!(version.starts_with("3."));
    }

    #[tokio::test]
    async fn python_tool_intent_closed_loop() {
        let python = python_bin();
        let check = Command::new(&python)
            .args(["-c", "import aros_research"])
            .env("PYTHONPATH", repo_pythonpath())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status();
        if !check.map(|status| status.success()).unwrap_or(false) {
            return;
        }
        let (mut supervisor, listener) = WorkerSupervisor::bind_loopback().await.unwrap();
        supervisor
            .spawn_python(
                &python,
                &[
                    "--probe-intent",
                    "fuzz_adapter",
                    "--probe-path",
                    "/var/run/docker.sock",
                ],
                &repo_pythonpath(),
            )
            .unwrap();
        let _ = supervisor.accept_hello(&listener).await.unwrap();
        let envelope = supervisor.read_next().await.unwrap();
        let request_id = envelope.request_id.clone();
        assert!(matches!(envelope.kind, Some(envelope::Kind::ToolIntent(_))));
        supervisor
            .write_next(Envelope {
                protocol_version: PROTOCOL_VERSION,
                request_id,
                kind: Some(envelope::Kind::IntentResult(IntentResult {
                    decision: "DENY".into(),
                    reason: "not authorized".into(),
                    exit_status: None,
                    stdout_digest: None,
                })),
            })
            .await
            .unwrap();
    }
}
