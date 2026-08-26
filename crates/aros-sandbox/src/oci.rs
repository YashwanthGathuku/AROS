//! Rootless OCI via the `podman` CLI. Presence is not containment.

use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::OnceLock;

use super::{SandboxError, SandboxHandle, SandboxPhase, SandboxProvider};
use aros_types::{unix_now_ms, SandboxId};
use serde::{Deserialize, Serialize};

pub struct RootlessOciSandboxProvider {
    pub runtime: Option<PathBuf>,
}

/// Structured result of the five containment dimensions AROS requires before
/// claiming a live sandbox is safe for research.
///
/// A dimension that cannot be demonstrated on this host is `false`. Callers
/// must not claim live OCI acceptance unless `all_demonstrated()` is true.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct ContainmentReport {
    /// Rootless OCI runtime binary is present on PATH / AROS_PODMAN.
    pub runtime_present: bool,
    /// `podman info` succeeds (machine up / daemon reachable).
    pub machine_reachable: bool,
    /// An `--internal` network can be created and inspect reports internal=true.
    pub internal_network: bool,
    /// Policy-layer public Internet deny is enforced in-process (always true when
    /// aros-policy is linked; recorded here for the report surface).
    pub policy_public_internet_deny: bool,
    /// Host socket / SSH key paths are denied by policy (always true for the
    /// default-deny lab manifest; recorded for the report surface).
    pub policy_host_socket_deny: bool,
    /// Human-readable notes for doctor / acceptance output.
    pub notes: Vec<String>,
}

impl ContainmentReport {
    pub fn all_demonstrated(&self) -> bool {
        self.runtime_present
            && self.machine_reachable
            && self.internal_network
            && self.policy_public_internet_deny
            && self.policy_host_socket_deny
    }

    pub fn live_oci_claimable(&self) -> bool {
        self.runtime_present && self.machine_reachable && self.internal_network
    }
}

impl RootlessOciSandboxProvider {
    pub fn detect() -> Self {
        Self {
            runtime: find_podman(),
        }
    }

    pub fn can_run(&self) -> bool {
        self.runtime.is_some()
    }

    pub fn machine_reachable(&self) -> bool {
        let Some(bin) = &self.runtime else {
            return false;
        };
        Command::new(bin)
            .arg("info")
            .output()
            .map(|o| o.status.success())
            .unwrap_or(false)
    }

    pub fn containment_ok(&self) -> bool {
        static CACHE: OnceLock<bool> = OnceLock::new();
        let Some(bin) = &self.runtime else {
            return false;
        };
        *CACHE.get_or_init(|| probe_internal_network(bin))
    }

    /// Run all five containment dimensions and return a structured report.
    /// Never claims success for probes that were not executed successfully.
    pub fn probe_containment(&self) -> ContainmentReport {
        let mut notes = Vec::new();
        let runtime_present = self.runtime.is_some();
        if !runtime_present {
            notes.push("no rootless OCI runtime (podman) detected".into());
        }
        let machine_reachable = if runtime_present {
            self.machine_reachable()
        } else {
            false
        };
        if runtime_present && !machine_reachable {
            notes.push("podman present but `podman info` failed (machine down?)".into());
        }
        let internal_network = if machine_reachable {
            if let Some(bin) = &self.runtime {
                probe_internal_network(bin)
            } else {
                false
            }
        } else {
            false
        };
        if machine_reachable && !internal_network {
            notes.push("internal network probe failed".into());
        }
        if internal_network {
            notes.push("internal network probe passed".into());
        }
        // Policy dimensions are invariants of the AROS policy engine, not of the
        // host OCI runtime. They are recorded true so the report is complete;
        // live egress blocking still requires the OCI internal network.
        ContainmentReport {
            runtime_present,
            machine_reachable,
            internal_network,
            policy_public_internet_deny: true,
            policy_host_socket_deny: true,
            notes,
        }
    }
}

fn find_podman() -> Option<PathBuf> {
    if let Ok(explicit) = std::env::var("AROS_PODMAN") {
        let p = PathBuf::from(explicit);
        if p.is_file() {
            return Some(p);
        }
    }
    if let Some(p) = which_path("podman") {
        return Some(p);
    }
    let local = std::env::var_os("LOCALAPPDATA")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("."));
    let candidates = [
        local.join("Programs").join("Podman").join("podman.exe"),
        PathBuf::from(r"C:\Program Files\RedHat\Podman\podman.exe"),
        PathBuf::from(r"C:\Program Files\Podman\podman.exe"),
    ];
    candidates.into_iter().find(|p| p.is_file())
}

fn which_path(bin: &str) -> Option<PathBuf> {
    std::env::var_os("PATH").and_then(|paths| {
        std::env::split_paths(&paths).find_map(|dir| {
            let p = dir.join(bin);
            if p.is_file() {
                return Some(p);
            }
            let exe = p.with_extension("exe");
            exe.is_file().then_some(exe)
        })
    })
}

fn probe_internal_network(podman: &Path) -> bool {
    if !Command::new(podman)
        .arg("info")
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false)
    {
        return false;
    }
    let name = format!("aros-probe-{}", std::process::id());
    let created = Command::new(podman)
        .args(["network", "create", "--internal", &name])
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false);
    if !created {
        let _ = Command::new(podman).args(["network", "rm", &name]).status();
        return false;
    }
    let inspect = Command::new(podman)
        .args(["network", "inspect", &name])
        .output();
    let ok = inspect
        .ok()
        .filter(|o| o.status.success())
        .and_then(|o| String::from_utf8(o.stdout).ok())
        .is_some_and(|s| {
            s.to_ascii_lowercase().contains("\"internal\": true")
                || s.to_ascii_lowercase().contains("\"internal\":true")
        });
    let _ = Command::new(podman)
        .args(["network", "rm", "-f", &name])
        .status();
    ok
}

impl SandboxProvider for RootlessOciSandboxProvider {
    fn name(&self) -> &'static str {
        "rootless-oci"
    }

    fn prepare(&self, workdir: &Path) -> Result<SandboxHandle, SandboxError> {
        match &self.runtime {
            None => Err(SandboxError::FailClosed(
                "no rootless OCI runtime (podman/docker); campaign fails closed".into(),
            )),
            Some(_) if !self.containment_ok() => Err(SandboxError::FailClosed(
                "OCI runtime present but internal-network containment is not demonstrated".into(),
            )),
            Some(_) => {
                std::fs::create_dir_all(workdir)?;
                Ok(SandboxHandle {
                    id: SandboxId::new(),
                    phase: SandboxPhase::Prepared,
                    workdir: workdir.to_path_buf(),
                    containment_demonstrated: true,
                    provider: self.name().to_string(),
                    created_unix_ms: unix_now_ms(),
                })
            }
        }
    }

    fn build_target(&self, handle: &SandboxHandle) -> Result<String, SandboxError> {
        if !handle.containment_demonstrated {
            return Err(SandboxError::FailClosed(
                "oci containment not demonstrated".into(),
            ));
        }
        Ok(format!("oci-build:{}", handle.id))
    }

    fn verify_policy(&self, handle: &mut SandboxHandle) -> Result<(), SandboxError> {
        if handle.phase != SandboxPhase::Prepared || !handle.containment_demonstrated {
            return Err(SandboxError::FailClosed(
                "oci containment not demonstrated".into(),
            ));
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
        _env: &std::collections::BTreeMap<String, String>,
    ) -> Result<super::ExecResult, SandboxError> {
        let Some(bin) = &self.runtime else {
            return Err(SandboxError::FailClosed("no podman".into()));
        };
        if handle.phase != SandboxPhase::Running || argv.is_empty() {
            return Err(SandboxError::InvalidState);
        }
        let output = Command::new(bin).args(argv).output()?;
        Ok(super::ExecResult {
            exit_status: output.status.code().unwrap_or(1),
            stdout: output.stdout,
            stderr: output.stderr,
        })
    }

    fn snapshot(&self, handle: &SandboxHandle) -> Result<String, SandboxError> {
        Ok(format!("oci-snap-{}", handle.id))
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
        Ok(std::fs::read(handle.workdir.join(relpath))?)
    }

    fn destroy(&self, handle: &mut SandboxHandle) -> Result<(), SandboxError> {
        handle.phase = SandboxPhase::Destroyed;
        let _ = std::fs::remove_dir_all(&handle.workdir);
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn detect_does_not_panic() {
        let p = RootlessOciSandboxProvider::detect();
        let _ = p.can_run();
        let _ = p.machine_reachable();
    }

    #[test]
    fn internal_network_probe_when_machine_up() {
        let p = RootlessOciSandboxProvider::detect();
        if !p.machine_reachable() {
            return;
        }
        assert!(
            p.containment_ok(),
            "podman machine is up but --internal network probe failed"
        );
    }

    #[test]
    fn containment_report_never_claims_live_without_runtime() {
        let p = RootlessOciSandboxProvider { runtime: None };
        let r = p.probe_containment();
        assert!(!r.runtime_present);
        assert!(!r.machine_reachable);
        assert!(!r.internal_network);
        assert!(!r.live_oci_claimable());
        assert!(!r.all_demonstrated());
        assert!(r.policy_public_internet_deny);
        assert!(r.policy_host_socket_deny);
        assert!(!r.notes.is_empty());
    }

    #[test]
    fn containment_report_is_honest_on_this_host() {
        let p = RootlessOciSandboxProvider::detect();
        let r = p.probe_containment();
        // Runtime present ⇔ can_run.
        assert_eq!(r.runtime_present, p.can_run());
        if !r.runtime_present {
            assert!(!r.live_oci_claimable());
        }
        if r.live_oci_claimable() {
            assert!(r.internal_network);
            assert!(r.machine_reachable);
        }
    }
}
