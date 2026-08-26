//! Rootless OCI via the `podman` CLI. Presence is not containment.

use std::io::Read;
use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};
use std::sync::OnceLock;
use std::time::{Duration, Instant};

use super::{SandboxError, SandboxHandle, SandboxPhase, SandboxProvider};
use aros_types::{unix_now_ms, SandboxId};
use serde::{Deserialize, Serialize};

pub struct RootlessOciSandboxProvider {
    pub runtime: Option<PathBuf>,
}

/// Structured result of the containment dimensions AROS requires before
/// claiming a live sandbox is safe for research.
///
/// A dimension that cannot be demonstrated on this host is `false`. Callers
/// must not claim live OCI acceptance unless `live_oci_claimable()` is true.
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
    /// Two containers on the internal network can reach each other.
    pub target_reachable: bool,
    /// Unauthorized public IPv4 (1.1.1.1) is not reachable from the sandbox.
    pub unauthorized_external_denied: bool,
    /// Public DNS (8.8.8.8:53 / hostname resolution) is not an egress bypass.
    pub dns_bypass_denied: bool,
    /// Host/gateway address is not reachable, or the internal net has no gateway.
    pub host_gateway_denied: bool,
    /// IPv6 (2001:4860:4860::8888) is not an egress bypass.
    pub ipv6_bypass_denied: bool,
    /// Packet probes actually ran (image present). False means "not demonstrated".
    pub packet_probes_ran: bool,
    /// Human-readable notes for doctor / acceptance output.
    pub notes: Vec<String>,
}

impl ContainmentReport {
    pub fn packet_isolation_demonstrated(&self) -> bool {
        self.packet_probes_ran
            && self.target_reachable
            && self.unauthorized_external_denied
            && self.dns_bypass_denied
            && self.host_gateway_denied
            && self.ipv6_bypass_denied
    }

    pub fn all_demonstrated(&self) -> bool {
        self.live_oci_claimable()
            && self.policy_public_internet_deny
            && self.policy_host_socket_deny
    }

    pub fn live_oci_claimable(&self) -> bool {
        self.runtime_present
            && self.machine_reachable
            && self.internal_network
            && self.packet_isolation_demonstrated()
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
        self.probe_containment().live_oci_claimable()
    }

    /// Run all containment dimensions and return a structured report.
    /// Never claims success for probes that were not executed successfully.
    pub fn probe_containment(&self) -> ContainmentReport {
        if self.runtime.is_none() {
            return ContainmentReport {
                notes: vec!["no rootless OCI runtime (podman) detected".into()],
                policy_public_internet_deny: true,
                policy_host_socket_deny: true,
                ..ContainmentReport::default()
            };
        }
        static CACHE: OnceLock<ContainmentReport> = OnceLock::new();
        CACHE
            .get_or_init(|| self.probe_containment_uncached())
            .clone()
    }

    fn probe_containment_uncached(&self) -> ContainmentReport {
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

        let mut report = ContainmentReport {
            runtime_present,
            machine_reachable,
            internal_network: false,
            policy_public_internet_deny: true,
            policy_host_socket_deny: true,
            target_reachable: false,
            unauthorized_external_denied: false,
            dns_bypass_denied: false,
            host_gateway_denied: false,
            ipv6_bypass_denied: false,
            packet_probes_ran: false,
            notes,
        };

        if !machine_reachable {
            return report;
        }
        let Some(bin) = &self.runtime else {
            return report;
        };

        let name = format!("aros-probe-{}", std::process::id());
        let created = run_timeout(
            Command::new(bin).args(["network", "create", "--internal", &name]),
            Duration::from_secs(20),
        )
        .is_some_and(|o| o.status.success());
        if !created {
            let _ = Command::new(bin)
                .args(["network", "rm", "-f", &name])
                .status();
            report.notes.push("internal network create failed".into());
            return report;
        }

        let inspect = run_timeout(
            Command::new(bin).args(["network", "inspect", &name]),
            Duration::from_secs(15),
        );
        let inspect_txt = inspect
            .as_ref()
            .filter(|o| o.status.success())
            .and_then(|o| String::from_utf8(o.stdout.clone()).ok())
            .unwrap_or_default();
        let internal = inspect_txt
            .to_ascii_lowercase()
            .contains("\"internal\": true")
            || inspect_txt
                .to_ascii_lowercase()
                .contains("\"internal\":true");
        report.internal_network = internal;
        if internal {
            report.notes.push("internal network probe passed".into());
        } else {
            report
                .notes
                .push("internal network inspect did not report internal=true".into());
        }

        if internal {
            let packets = probe_packet_isolation(bin, &name, &inspect_txt);
            report.target_reachable = packets.target_reachable;
            report.unauthorized_external_denied = packets.unauthorized_external_denied;
            report.dns_bypass_denied = packets.dns_bypass_denied;
            report.host_gateway_denied = packets.host_gateway_denied;
            report.ipv6_bypass_denied = packets.ipv6_bypass_denied;
            report.packet_probes_ran = packets.ran;
            report.notes.extend(packets.notes);
        }

        let _ = Command::new(bin)
            .args(["network", "rm", "-f", &name])
            .status();
        report
    }
}

struct PacketIsolation {
    ran: bool,
    target_reachable: bool,
    unauthorized_external_denied: bool,
    dns_bypass_denied: bool,
    host_gateway_denied: bool,
    ipv6_bypass_denied: bool,
    notes: Vec<String>,
}

fn probe_packet_isolation(podman: &Path, net: &str, inspect_txt: &str) -> PacketIsolation {
    let mut notes = Vec::new();
    let Some(image) = resolve_probe_image(podman) else {
        notes.push(
            "packet probes not run: no alpine/busybox image (set AROS_OCI_PULL=1 to pull)".into(),
        );
        return PacketIsolation {
            ran: false,
            target_reachable: false,
            unauthorized_external_denied: false,
            dns_bypass_denied: false,
            host_gateway_denied: false,
            ipv6_bypass_denied: false,
            notes,
        };
    };
    notes.push(format!("packet probe image: {image}"));

    let tgt = format!("aros-pkt-tgt-{}", std::process::id());
    let _ = Command::new(podman).args(["rm", "-f", &tgt]).status();

    let started = run_timeout(
        Command::new(podman).args([
            "run",
            "-d",
            "--name",
            &tgt,
            "--network",
            net,
            "--pull=never",
            "--timeout",
            "30",
            &image,
            "sleep",
            "25",
        ]),
        Duration::from_secs(25),
    )
    .is_some_and(|o| o.status.success());

    let target_reachable = if started {
        let ip = container_ip(podman, &tgt);
        let peer = ip.unwrap_or_else(|| tgt.clone());
        let ping = run_timeout(
            Command::new(podman).args([
                "run",
                "--rm",
                "--network",
                net,
                "--pull=never",
                "--timeout",
                "10",
                &image,
                "ping",
                "-c",
                "1",
                "-W",
                "2",
                &peer,
            ]),
            Duration::from_secs(15),
        );
        ping.is_some_and(|o| o.status.success())
    } else {
        notes.push("target container failed to start on internal network".into());
        false
    };
    if target_reachable {
        notes.push("target reachable on internal network".into());
    } else {
        notes.push("target reachability on internal network not demonstrated".into());
    }

    let unauthorized_external_denied = !egress_succeeds(
        podman,
        net,
        &image,
        &[
            "wget",
            "-T",
            "2",
            "-q",
            "-O",
            "/dev/null",
            "http://1.1.1.1/",
        ],
    );
    notes.push(format!(
        "unauthorized 1.1.1.1 denied: {unauthorized_external_denied}"
    ));

    let dns_bypass_denied =
        !egress_succeeds(podman, net, &image, &["nslookup", "example.com", "8.8.8.8"])
            && !egress_succeeds(
                podman,
                net,
                &image,
                &[
                    "wget",
                    "-T",
                    "2",
                    "-q",
                    "-O",
                    "/dev/null",
                    "http://one.one.one.one/",
                ],
            );
    notes.push(format!("public DNS bypass denied: {dns_bypass_denied}"));

    let host_gateway_denied = host_gateway_is_denied(podman, net, &image, inspect_txt);
    notes.push(format!("host gateway denied: {host_gateway_denied}"));

    let ipv6_bypass_denied = !egress_succeeds(
        podman,
        net,
        &image,
        &[
            "wget",
            "-T",
            "2",
            "-q",
            "-O",
            "/dev/null",
            "http://[2001:4860:4860::8888]/",
        ],
    ) && !egress_succeeds(
        podman,
        net,
        &image,
        &["ping", "-6", "-c", "1", "-W", "2", "2001:4860:4860::8888"],
    );
    notes.push(format!("IPv6 bypass denied: {ipv6_bypass_denied}"));

    let _ = Command::new(podman).args(["rm", "-f", &tgt]).status();

    PacketIsolation {
        ran: true,
        target_reachable,
        unauthorized_external_denied,
        dns_bypass_denied,
        host_gateway_denied,
        ipv6_bypass_denied,
        notes,
    }
}

fn host_gateway_is_denied(podman: &Path, net: &str, image: &str, inspect_txt: &str) -> bool {
    let gateway = extract_gateway(inspect_txt);
    match gateway {
        None => true,
        Some(gw) => {
            !egress_succeeds(podman, net, image, &["ping", "-c", "1", "-W", "2", &gw])
                && !egress_succeeds(
                    podman,
                    net,
                    image,
                    &[
                        "wget",
                        "-T",
                        "2",
                        "-q",
                        "-O",
                        "/dev/null",
                        &format!("http://{gw}/"),
                    ],
                )
        }
    }
}

fn extract_gateway(inspect_txt: &str) -> Option<String> {
    let lower = inspect_txt.to_ascii_lowercase();
    for key in ["\"gateway\": \"", "\"gateway\":\""] {
        if let Some(idx) = lower.find(key) {
            let rest = &inspect_txt[idx + key.len()..];
            let end = rest.find('"').unwrap_or(0);
            let val = rest[..end].trim();
            if !val.is_empty() && val != "null" {
                return Some(val.to_string());
            }
        }
    }
    None
}

fn container_ip(podman: &Path, name: &str) -> Option<String> {
    let out = run_timeout(
        Command::new(podman).args([
            "inspect",
            "-f",
            "{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}",
            name,
        ]),
        Duration::from_secs(10),
    )?;
    if !out.status.success() {
        return None;
    }
    let ip = String::from_utf8(out.stdout).ok()?;
    let ip = ip.trim();
    if ip.is_empty() {
        None
    } else {
        Some(ip.to_string())
    }
}

fn egress_succeeds(podman: &Path, net: &str, image: &str, argv: &[&str]) -> bool {
    let mut args: Vec<String> = [
        "run",
        "--rm",
        "--network",
        net,
        "--pull=never",
        "--timeout",
        "8",
        image,
    ]
    .into_iter()
    .map(str::to_string)
    .collect();
    args.extend(argv.iter().map(|s| (*s).to_string()));
    run_timeout(Command::new(podman).args(&args), Duration::from_secs(12))
        .is_some_and(|o| o.status.success())
}

fn resolve_probe_image(podman: &Path) -> Option<String> {
    for name in ["alpine", "docker.io/library/alpine:latest", "busybox"] {
        if image_exists(podman, name) {
            return Some(name.to_string());
        }
    }
    if !may_pull_image() {
        return None;
    }
    let pulled = run_timeout(
        Command::new(podman).args(["pull", "docker.io/library/alpine:latest"]),
        Duration::from_secs(90),
    )
    .is_some_and(|o| o.status.success());
    if pulled {
        Some("docker.io/library/alpine:latest".into())
    } else {
        None
    }
}

fn image_exists(podman: &Path, name: &str) -> bool {
    run_timeout(
        Command::new(podman).args(["image", "exists", name]),
        Duration::from_secs(10),
    )
    .is_some_and(|o| o.status.success())
}

fn may_pull_image() -> bool {
    match std::env::var("AROS_OCI_PULL").ok().as_deref() {
        Some("0") => false,
        Some("1") => true,
        _ => !cfg!(test),
    }
}

fn run_timeout(cmd: &mut Command, timeout: Duration) -> Option<Output> {
    cmd.stdout(Stdio::piped());
    cmd.stderr(Stdio::piped());
    let mut child = cmd.spawn().ok()?;
    let start = Instant::now();
    loop {
        match child.try_wait() {
            Ok(Some(status)) => {
                let mut stdout = Vec::new();
                let mut stderr = Vec::new();
                if let Some(mut s) = child.stdout.take() {
                    let _ = s.read_to_end(&mut stdout);
                }
                if let Some(mut s) = child.stderr.take() {
                    let _ = s.read_to_end(&mut stderr);
                }
                return Some(Output {
                    status,
                    stdout,
                    stderr,
                });
            }
            Ok(None) if start.elapsed() < timeout => {
                std::thread::sleep(Duration::from_millis(50));
            }
            Ok(None) => {
                let _ = child.kill();
                let _ = child.wait();
                return None;
            }
            Err(_) => return None,
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
                "OCI runtime present but live packet isolation is not demonstrated".into(),
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
        let r = p.probe_containment();
        assert!(
            r.internal_network,
            "podman machine is up but --internal network probe failed: {:?}",
            r.notes
        );
    }

    #[test]
    fn containment_report_never_claims_live_without_runtime() {
        let p = RootlessOciSandboxProvider { runtime: None };
        let r = p.probe_containment();
        assert!(!r.runtime_present);
        assert!(!r.machine_reachable);
        assert!(!r.internal_network);
        assert!(!r.packet_probes_ran);
        assert!(!r.live_oci_claimable());
        assert!(!r.all_demonstrated());
        assert!(r.policy_public_internet_deny);
        assert!(r.policy_host_socket_deny);
        assert!(!r.notes.is_empty());
    }

    #[test]
    fn live_oci_claimable_requires_packet_probes() {
        let mut r = ContainmentReport {
            runtime_present: true,
            machine_reachable: true,
            internal_network: true,
            policy_public_internet_deny: true,
            policy_host_socket_deny: true,
            packet_probes_ran: false,
            ..ContainmentReport::default()
        };
        assert!(!r.live_oci_claimable());
        r.packet_probes_ran = true;
        r.target_reachable = true;
        r.unauthorized_external_denied = true;
        r.dns_bypass_denied = true;
        r.host_gateway_denied = true;
        r.ipv6_bypass_denied = true;
        assert!(r.live_oci_claimable());
        r.unauthorized_external_denied = false;
        assert!(!r.live_oci_claimable());
    }

    #[test]
    fn containment_report_is_honest_on_this_host() {
        let p = RootlessOciSandboxProvider::detect();
        let r = p.probe_containment();
        assert_eq!(r.runtime_present, p.can_run());
        if !r.runtime_present {
            assert!(!r.live_oci_claimable());
        }
        if r.live_oci_claimable() {
            assert!(r.internal_network);
            assert!(r.machine_reachable);
            assert!(r.packet_isolation_demonstrated());
        }
        if !r.packet_probes_ran {
            assert!(
                !r.live_oci_claimable(),
                "must not claim live OCI without running packet probes"
            );
        }
    }

    #[test]
    fn five_way_packet_probes_when_image_available() {
        let p = RootlessOciSandboxProvider::detect();
        if !p.machine_reachable() {
            return;
        }
        let r = p.probe_containment();
        if !r.packet_probes_ran {
            // Honest skip: no alpine/busybox image and tests do not pull by default.
            return;
        }
        assert!(
            r.target_reachable,
            "target reachability failed: {:?}",
            r.notes
        );
        assert!(
            r.unauthorized_external_denied,
            "1.1.1.1 was reachable from internal net: {:?}",
            r.notes
        );
        assert!(
            r.dns_bypass_denied,
            "public DNS bypassed isolation: {:?}",
            r.notes
        );
        assert!(
            r.host_gateway_denied,
            "host gateway reachable from internal net: {:?}",
            r.notes
        );
        assert!(
            r.ipv6_bypass_denied,
            "IPv6 bypassed isolation: {:?}",
            r.notes
        );
        assert!(r.live_oci_claimable());
    }

    #[test]
    fn extract_gateway_parses_inspect() {
        let json = r#"[{"internal": true, "subnets": [{"gateway": "10.89.0.1"}]}]"#;
        assert_eq!(extract_gateway(json).as_deref(), Some("10.89.0.1"));
        assert!(extract_gateway(r#"{"internal": true, "gateway": ""}"#).is_none());
    }
}
