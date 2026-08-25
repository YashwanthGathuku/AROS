//! Sandbox lifecycle. Fake provider never claims containment.

#![forbid(unsafe_code)]

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use aros_types::{unix_now_ms, SandboxId};
use thiserror::Error;

#[derive(Debug, Error)]
pub enum SandboxError {
    #[error("{0}")]
    FailClosed(String),
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
    #[error("sandbox not found: {0}")]
    NotFound(String),
    #[error("invalid sandbox state transition")]
    InvalidState,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SandboxPhase {
    Prepared,
    PolicyVerified,
    Running,
    Frozen,
    Destroyed,
}

#[derive(Clone, Debug)]
pub struct SandboxHandle {
    pub id: SandboxId,
    pub phase: SandboxPhase,
    pub workdir: PathBuf,
    pub containment_demonstrated: bool,
    pub provider: String,
    pub created_unix_ms: u64,
}

#[derive(Clone, Debug)]
pub struct ExecResult {
    pub exit_status: i32,
    pub stdout: Vec<u8>,
    pub stderr: Vec<u8>,
}

pub trait SandboxProvider: Send + Sync {
    fn name(&self) -> &'static str;
    fn prepare(&self, workdir: &Path) -> Result<SandboxHandle, SandboxError>;
    fn verify_policy(&self, handle: &mut SandboxHandle) -> Result<(), SandboxError>;
    fn spawn(&self, handle: &mut SandboxHandle) -> Result<(), SandboxError>;
    fn execute(
        &self,
        handle: &SandboxHandle,
        argv: &[String],
        env: &BTreeMap<String, String>,
    ) -> Result<ExecResult, SandboxError>;
    fn snapshot(&self, handle: &SandboxHandle) -> Result<String, SandboxError>;
    fn reset(&self, handle: &mut SandboxHandle) -> Result<(), SandboxError>;
    fn freeze(&self, handle: &mut SandboxHandle) -> Result<(), SandboxError>;
    fn collect(&self, handle: &SandboxHandle, relpath: &str) -> Result<Vec<u8>, SandboxError>;
    fn destroy(&self, handle: &mut SandboxHandle) -> Result<(), SandboxError>;
}

/// In-process tempdir provider. **Never** sets containment_demonstrated.
pub struct FakeSandboxProvider;

impl SandboxProvider for FakeSandboxProvider {
    fn name(&self) -> &'static str {
        "fake"
    }

    fn prepare(&self, workdir: &Path) -> Result<SandboxHandle, SandboxError> {
        std::fs::create_dir_all(workdir)?;
        Ok(SandboxHandle {
            id: SandboxId::new(),
            phase: SandboxPhase::Prepared,
            workdir: workdir.to_path_buf(),
            containment_demonstrated: false,
            provider: self.name().to_string(),
            created_unix_ms: unix_now_ms(),
        })
    }

    fn verify_policy(&self, handle: &mut SandboxHandle) -> Result<(), SandboxError> {
        if handle.phase != SandboxPhase::Prepared {
            return Err(SandboxError::InvalidState);
        }
        handle.phase = SandboxPhase::PolicyVerified;
        Ok(())
    }

    fn spawn(&self, handle: &mut SandboxHandle) -> Result<(), SandboxError> {
        if handle.phase != SandboxPhase::PolicyVerified {
            return Err(SandboxError::InvalidState);
        }
        handle.phase = SandboxPhase::Running;
        Ok(())
    }

    fn execute(
        &self,
        handle: &SandboxHandle,
        argv: &[String],
        _env: &BTreeMap<String, String>,
    ) -> Result<ExecResult, SandboxError> {
        if handle.phase != SandboxPhase::Running {
            return Err(SandboxError::InvalidState);
        }
        if argv.is_empty() {
            return Err(SandboxError::FailClosed("empty argv".into()));
        }
        Ok(ExecResult {
            exit_status: 0,
            stdout: format!("fake-exec:{argv:?}").into_bytes(),
            stderr: Vec::new(),
        })
    }

    fn snapshot(&self, handle: &SandboxHandle) -> Result<String, SandboxError> {
        Ok(format!("fake-snap-{}", handle.id))
    }

    fn reset(&self, handle: &mut SandboxHandle) -> Result<(), SandboxError> {
        handle.phase = SandboxPhase::Prepared;
        Ok(())
    }

    fn freeze(&self, handle: &mut SandboxHandle) -> Result<(), SandboxError> {
        handle.phase = SandboxPhase::Frozen;
        Ok(())
    }

    fn collect(&self, handle: &SandboxHandle, relpath: &str) -> Result<Vec<u8>, SandboxError> {
        let path = handle.workdir.join(relpath);
        Ok(std::fs::read(path)?)
    }

    fn destroy(&self, handle: &mut SandboxHandle) -> Result<(), SandboxError> {
        handle.phase = SandboxPhase::Destroyed;
        let _ = std::fs::remove_dir_all(&handle.workdir);
        Ok(())
    }
}

/// Rootless OCI provider. Without a demonstrated runtime this fail-closes.
pub struct RootlessOciSandboxProvider {
    pub runtime: Option<String>,
}

impl RootlessOciSandboxProvider {
    pub fn detect() -> Self {
        let runtime = ["podman", "docker"]
            .into_iter()
            .find(|bin| which_ok(bin))
            .map(str::to_string);
        Self { runtime }
    }

    pub fn can_run(&self) -> bool {
        self.runtime.is_some()
    }
}

fn which_ok(bin: &str) -> bool {
    std::env::var_os("PATH")
        .map(|paths| {
            std::env::split_paths(&paths).any(|dir| {
                let p = dir.join(bin);
                p.is_file() || p.with_extension("exe").is_file()
            })
        })
        .unwrap_or(false)
}

impl SandboxProvider for RootlessOciSandboxProvider {
    fn name(&self) -> &'static str {
        "rootless-oci"
    }

    fn prepare(&self, _workdir: &Path) -> Result<SandboxHandle, SandboxError> {
        match &self.runtime {
            None => Err(SandboxError::FailClosed(
                "no rootless OCI runtime (podman/docker); campaign fails closed".into(),
            )),
            Some(_) => Err(SandboxError::FailClosed(
                "OCI runtime present but network containment has not been demonstrated on this host"
                    .into(),
            )),
        }
    }

    fn verify_policy(&self, _handle: &mut SandboxHandle) -> Result<(), SandboxError> {
        Err(SandboxError::FailClosed(
            "oci containment not demonstrated".into(),
        ))
    }

    fn spawn(&self, _handle: &mut SandboxHandle) -> Result<(), SandboxError> {
        Err(SandboxError::FailClosed(
            "oci containment not demonstrated".into(),
        ))
    }

    fn execute(
        &self,
        _handle: &SandboxHandle,
        _argv: &[String],
        _env: &BTreeMap<String, String>,
    ) -> Result<ExecResult, SandboxError> {
        Err(SandboxError::FailClosed(
            "oci containment not demonstrated".into(),
        ))
    }

    fn snapshot(&self, _handle: &SandboxHandle) -> Result<String, SandboxError> {
        Err(SandboxError::FailClosed(
            "oci containment not demonstrated".into(),
        ))
    }

    fn reset(&self, _handle: &mut SandboxHandle) -> Result<(), SandboxError> {
        Err(SandboxError::FailClosed(
            "oci containment not demonstrated".into(),
        ))
    }

    fn freeze(&self, _handle: &mut SandboxHandle) -> Result<(), SandboxError> {
        Err(SandboxError::FailClosed(
            "oci containment not demonstrated".into(),
        ))
    }

    fn collect(&self, _handle: &SandboxHandle, _relpath: &str) -> Result<Vec<u8>, SandboxError> {
        Err(SandboxError::FailClosed(
            "oci containment not demonstrated".into(),
        ))
    }

    fn destroy(&self, handle: &mut SandboxHandle) -> Result<(), SandboxError> {
        handle.phase = SandboxPhase::Destroyed;
        Ok(())
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn fake_never_claims_containment() {
        let dir = tempfile::tempdir().unwrap();
        let p = FakeSandboxProvider;
        let h = p.prepare(dir.path()).unwrap();
        assert!(!h.containment_demonstrated);
        assert_eq!(h.phase, SandboxPhase::Prepared);
    }

    #[test]
    fn oci_without_runtime_fails_closed() {
        let p = RootlessOciSandboxProvider { runtime: None };
        let dir = tempfile::tempdir().unwrap();
        let err = p.prepare(dir.path()).unwrap_err();
        assert!(matches!(err, SandboxError::FailClosed(_)));
    }

    #[test]
    fn fake_state_machine_rejects_execute_before_spawn() {
        let dir = tempfile::tempdir().unwrap();
        let p = FakeSandboxProvider;
        let h = p.prepare(dir.path()).unwrap();
        let err = p
            .execute(&h, &["true".into()], &BTreeMap::new())
            .unwrap_err();
        assert!(matches!(err, SandboxError::InvalidState));
    }
}
