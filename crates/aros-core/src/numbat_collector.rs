//! Loopback Numbat collector plan.
//!
//! The argv is `collect --addr 127.0.0.1:4318`. A correlation id is stored on
//! the plan and is not an argument. A missing file named numbat is not started.

use std::path::Path;
use std::process::{Command, Stdio};

use crate::provider_raw::require_correlation_id;

pub const NUMBAT_COLLECT_ADDR: &str = "127.0.0.1:4318";

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct NumbatCollectPlan {
    pub argv: Vec<String>,
    pub correlation_id: String,
}

#[derive(Debug, PartialEq, Eq)]
pub enum NumbatCollectError {
    NotInstalled,
    Name,
    Address,
    Correlation,
}

impl std::fmt::Display for NumbatCollectError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::NotInstalled => write!(formatter, "numbat collector is not installed"),
            Self::Name => write!(formatter, "numbat collector executable name is not numbat"),
            Self::Address => write!(formatter, "numbat collector address is not loopback"),
            Self::Correlation => write!(formatter, "numbat collector correlation id is invalid"),
        }
    }
}

pub fn plan_numbat_collect(correlation_id: &str) -> Result<NumbatCollectPlan, NumbatCollectError> {
    let correlation_id =
        require_correlation_id(correlation_id).map_err(|_| NumbatCollectError::Correlation)?;
    Ok(NumbatCollectPlan {
        argv: vec![
            "collect".into(),
            "--addr".into(),
            NUMBAT_COLLECT_ADDR.into(),
        ],
        correlation_id,
    })
}

pub fn numbat_executable_name_ok(path: &Path) -> bool {
    path.file_name()
        .and_then(|name| name.to_str())
        .is_some_and(|name| {
            let name = name.to_ascii_lowercase();
            name == "numbat" || name == "numbat.exe"
        })
}

/// Start the planned collector. A path that is not an existing `numbat` file
/// returns before `Command::spawn`.
pub fn spawn_numbat_collect(
    executable: &Path,
    plan: &NumbatCollectPlan,
) -> Result<std::process::Child, NumbatCollectError> {
    if !numbat_executable_name_ok(executable) {
        return Err(NumbatCollectError::Name);
    }
    if !executable.is_file() {
        return Err(NumbatCollectError::NotInstalled);
    }
    if plan.argv
        != [
            "collect".to_string(),
            "--addr".to_string(),
            NUMBAT_COLLECT_ADDR.to_string(),
        ]
    {
        return Err(NumbatCollectError::Address);
    }
    Command::new(executable)
        .args(&plan.argv)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .map_err(|_| NumbatCollectError::NotInstalled)
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    #[test]
    fn plan_is_loopback_and_keeps_the_correlation_id_off_argv() {
        let plan = plan_numbat_collect("run-1").unwrap();
        assert_eq!(plan.argv, vec!["collect", "--addr", "127.0.0.1:4318"]);
        assert_eq!(plan.correlation_id, "run-1");
        assert!(plan.argv.iter().all(|arg| arg != "run-1"));
        assert!(plan_numbat_collect("").is_err());
        assert!(plan_numbat_collect("has space").is_err());
    }

    #[test]
    fn missing_or_misnamed_collector_does_not_spawn() {
        let plan = plan_numbat_collect("run-1").unwrap();
        let missing = std::env::temp_dir()
            .join("aros-numbat-missing")
            .join("numbat.exe");
        assert_eq!(
            spawn_numbat_collect(&missing, &plan).unwrap_err(),
            NumbatCollectError::NotInstalled
        );
        let other = std::env::temp_dir().join("python.exe");
        assert_eq!(
            spawn_numbat_collect(&other, &plan).unwrap_err(),
            NumbatCollectError::Name
        );
    }
}
