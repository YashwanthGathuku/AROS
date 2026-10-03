//! Narrow trusted acquisition executor.
//!
//! This is not the research ToolBroker. Acquisition has a separate authority
//! envelope: only validated GitHub HTTPS URLs, only git clone, no shell,
//! bounded timeout, and the authority ends before the immutable research
//! snapshot is created.

use std::path::Path;
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::acquisition::AcquisitionPlan;

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct AcquisitionAuthorization {
    pub github_https: bool,
    pub destination_root: String,
    pub wall_time_ms: u64,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct AcquisitionReceipt {
    pub exit_status: i32,
    pub destination: String,
    pub elapsed_ms: u64,
    pub network_authority_revoked: bool,
}

#[derive(Debug, Error)]
pub enum AcquisitionExecutionError {
    #[error("acquisition is not authorized for GitHub HTTPS")]
    Unauthorized,
    #[error("destination escapes authorized acquisition root")]
    DestinationEscape,
    #[error("destination already exists")]
    DestinationExists,
    #[error("git failed with status {0}")]
    GitFailed(i32),
    #[error("git acquisition timed out")]
    Timeout,
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
}

pub fn execute_acquisition(
    plan: &AcquisitionPlan,
    authorization: &AcquisitionAuthorization,
) -> Result<AcquisitionReceipt, AcquisitionExecutionError> {
    if !authorization.github_https || !plan.repository.canonical_url.starts_with("https://github.com/") {
        return Err(AcquisitionExecutionError::Unauthorized);
    }
    let root = Path::new(&authorization.destination_root);
    std::fs::create_dir_all(root)?;
    let canonical_root = root.canonicalize()?;
    if plan.destination.exists() {
        return Err(AcquisitionExecutionError::DestinationExists);
    }
    let parent = plan.destination.parent().ok_or(AcquisitionExecutionError::DestinationEscape)?;
    std::fs::create_dir_all(parent)?;
    let canonical_parent = parent.canonicalize()?;
    if !canonical_parent.starts_with(&canonical_root) {
        return Err(AcquisitionExecutionError::DestinationEscape);
    }

    let mut command = Command::new("git");
    command
        .args(&plan.clone_argv)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .env("GIT_TERMINAL_PROMPT", "0")
        .env("GIT_CONFIG_NOSYSTEM", "1");

    let started = Instant::now();
    let mut child = command.spawn()?;
    let timeout = Duration::from_millis(authorization.wall_time_ms.max(1));
    loop {
        if let Some(status) = child.try_wait()? {
            if !status.success() {
                return Err(AcquisitionExecutionError::GitFailed(status.code().unwrap_or(-1)));
            }
            return Ok(AcquisitionReceipt {
                exit_status: status.code().unwrap_or(0),
                destination: plan.destination.display().to_string(),
                elapsed_ms: started.elapsed().as_millis().try_into().unwrap_or(u64::MAX),
                network_authority_revoked: true,
            });
        }
        if started.elapsed() >= timeout {
            let _ = child.kill();
            let _ = child.wait();
            return Err(AcquisitionExecutionError::Timeout);
        }
        std::thread::sleep(Duration::from_millis(25));
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::acquisition::acquisition_plan;

    #[test]
    fn refuses_execution_without_explicit_github_authority() {
        let root = tempfile::tempdir().expect("root");
        let plan = acquisition_plan(
            "https://github.com/erev0s/VAmPI",
            root.path(),
            Some("master"),
        )
        .expect("plan");
        let auth = AcquisitionAuthorization {
            github_https: false,
            destination_root: root.path().display().to_string(),
            wall_time_ms: 1000,
        };
        assert!(matches!(
            execute_acquisition(&plan, &auth),
            Err(AcquisitionExecutionError::Unauthorized)
        ));
    }
}
