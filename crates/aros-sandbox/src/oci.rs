//! Rootless OCI via the `podman` CLI. Presence is not containment.

use std::io::Read;
use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};
use std::time::{Duration, Instant};

use super::{SandboxError, SandboxHandle, SandboxPhase, SandboxProvider};
use aros_types::{env_name, unix_now_ms, SandboxId};
use serde::{Deserialize, Serialize};

pub struct RootlessOciSandboxProvider {
    pub runtime: Option<PathBuf>,
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ProbeOutcome {
    Proven,
    Failed,
    #[default]
    Indeterminate,
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct ContainmentReport {
    pub runtime_present: bool,
    pub machine_reachable: bool,
    pub internal_network: bool,
    pub policy_public_internet_deny: bool,
    pub policy_host_socket_deny: bool,
    pub target_reachable: bool,
    pub unauthorized_external_denied: bool,
    pub dns_bypass_denied: bool,
    pub host_gateway_denied: bool,
    pub ipv6_bypass_denied: bool,
    pub target_reachability_probe: ProbeOutcome,
    pub external_egress_probe: ProbeOutcome,
    pub dns_bypass_probe: ProbeOutcome,
    pub host_gateway_probe: ProbeOutcome,
    pub ipv6_bypass_probe: ProbeOutcome,
    pub packet_probes_ran: bool,
    pub notes: Vec<String>,
}

impl ContainmentReport {
    pub fn packet_isolation_demonstrated(&self) -> bool {
        self.packet_probes_ran
            && self.target_reachability_probe == ProbeOutcome::Proven
            && self.external_egress_probe == ProbeOutcome::Proven
            && self.dns_bypass_probe == ProbeOutcome::Proven
            && self.host_gateway_probe == ProbeOutcome::Proven
            && self.ipv6_bypass_probe == ProbeOutcome::Proven
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
            .map(|output| output.status.success())
            .unwrap_or(false)
    }

    pub fn containment_ok(&self) -> bool {
        self.probe_containment_fresh().live_oci_claimable()
    }

    pub fn probe_containment(&self) -> ContainmentReport {
        self.probe_containment_fresh()
    }

    /// Security admission always measures current state. Positive results are
    /// intentionally not cached.
    pub fn probe_containment_fresh(&self) -> ContainmentReport {
        self.probe_containment_uncached()
    }

    fn probe_containment_uncached(&self) -> ContainmentReport {
        let runtime_present = self.runtime.is_some();
        let machine_reachable = runtime_present && self.machine_reachable();
        let mut report = ContainmentReport {
            runtime_present,
            machine_reachable,
            policy_public_internet_deny: true,
            policy_host_socket_deny: true,
            ..ContainmentReport::default()
        };
        if !runtime_present {
            report
                .notes
                .push("no rootless OCI runtime (podman) detected".into());
            return report;
        }
        if !machine_reachable {
            report
                .notes
                .push("podman present but `podman info` failed".into());
            return report;
        }
        let Some(bin) = &self.runtime else {
            return report;
        };

        let network_name = format!("aros-probe-{}-{}", std::process::id(), unix_now_ms());
        let created = run_timeout(
            Command::new(bin).args(["network", "create", "--internal", &network_name]),
            Duration::from_secs(20),
        )
        .is_some_and(|output| output.status.success());
        if !created {
            report.notes.push("internal network create failed".into());
            return report;
        }

        let inspect = run_timeout(
            Command::new(bin).args(["network", "inspect", &network_name]),
            Duration::from_secs(15),
        );
        let inspect_text = inspect
            .as_ref()
            .filter(|output| output.status.success())
            .and_then(|output| String::from_utf8(output.stdout.clone()).ok())
            .unwrap_or_default();
        report.internal_network = inspect_text
            .to_ascii_lowercase()
            .contains("\"internal\": true")
            || inspect_text
                .to_ascii_lowercase()
                .contains("\"internal\":true");
        if report.internal_network {
            let packet = probe_packet_isolation(bin, &network_name, &inspect_text);
            report.packet_probes_ran = packet.ran;
            report.target_reachability_probe = packet.target_reachability;
            report.external_egress_probe = packet.external_egress;
            report.dns_bypass_probe = packet.dns_bypass;
            report.host_gateway_probe = packet.host_gateway;
            report.ipv6_bypass_probe = packet.ipv6_bypass;
            report.target_reachable = packet.target_reachability == ProbeOutcome::Proven;
            report.unauthorized_external_denied = packet.external_egress == ProbeOutcome::Proven;
            report.dns_bypass_denied = packet.dns_bypass == ProbeOutcome::Proven;
            report.host_gateway_denied = packet.host_gateway == ProbeOutcome::Proven;
            report.ipv6_bypass_denied = packet.ipv6_bypass == ProbeOutcome::Proven;
            report.notes.extend(packet.notes);
        } else {
            report
                .notes
                .push("internal network inspect did not report internal=true".into());
        }
        let _ = Command::new(bin)
            .args(["network", "rm", "-f", &network_name])
            .status();
        report
    }
}

struct PacketIsolation {
    ran: bool,
    target_reachability: ProbeOutcome,
    external_egress: ProbeOutcome,
    dns_bypass: ProbeOutcome,
    host_gateway: ProbeOutcome,
    ipv6_bypass: ProbeOutcome,
    notes: Vec<String>,
}

impl PacketIsolation {
    fn indeterminate(note: String) -> Self {
        Self {
            ran: false,
            target_reachability: ProbeOutcome::Indeterminate,
            external_egress: ProbeOutcome::Indeterminate,
            dns_bypass: ProbeOutcome::Indeterminate,
            host_gateway: ProbeOutcome::Indeterminate,
            ipv6_bypass: ProbeOutcome::Indeterminate,
            notes: vec![note],
        }
    }
}

fn probe_packet_isolation(podman: &Path, network: &str, inspect_text: &str) -> PacketIsolation {
    let Some(image) = resolve_probe_image(podman) else {
        return PacketIsolation::indeterminate(
            "packet probes not run: no alpine/busybox image (set AROS_OCI_PULL=1 to pull)".into(),
        );
    };
    let mut notes = vec![format!("packet probe image: {image}")];

    // `nc` is used for transport reachability. HTTP clients are intentionally
    // not used: HTTP 403/404/500 must never be mistaken for network isolation.
    let preflight = probe_exec(
        podman,
        network,
        &image,
        &[
            "sh",
            "-c",
            "command -v nc >/dev/null && command -v ping >/dev/null && command -v nslookup >/dev/null",
        ],
        Duration::from_secs(12),
    );
    match preflight {
        Some(output) if output.status.success() => {
            notes.push("packet probe tool preflight passed".into())
        }
        Some(output) => {
            notes.push(format!(
                "packet probe preflight failed (exit {:?})",
                output.status.code()
            ));
            return PacketIsolation::indeterminate(notes.join("; "));
        }
        None => return PacketIsolation::indeterminate("packet probe preflight timed out".into()),
    }

    let target_name = format!("aros-pkt-tgt-{}-{}", std::process::id(), unix_now_ms());
    let started = run_timeout(
        Command::new(podman).args([
            "run",
            "-d",
            "--name",
            &target_name,
            "--network",
            network,
            "--pull=never",
            &image,
            "sh",
            "-c",
            "nc -l -p 18080 >/dev/null 2>&1",
        ]),
        Duration::from_secs(20),
    );
    let target_reachability = match started {
        None => ProbeOutcome::Indeterminate,
        Some(output) if !output.status.success() => ProbeOutcome::Failed,
        Some(_) => {
            let peer = container_ip(podman, &target_name).unwrap_or_else(|| target_name.clone());
            allow_transport_probe(podman, network, &image, &peer, 18080)
        }
    };
    notes.push(format!("target reachability: {target_reachability:?}"));

    let external_egress = deny_transport_probe(podman, network, &image, "1.1.1.1", 80);
    notes.push(format!(
        "unauthorized public IPv4 deny: {external_egress:?}"
    ));

    let dns_direct = deny_command_probe(
        podman,
        network,
        &image,
        &["nslookup", "example.com", "8.8.8.8"],
    );
    let dns_resolved_transport =
        deny_transport_probe(podman, network, &image, "one.one.one.one", 80);
    let dns_bypass = combine_denials(&[dns_direct, dns_resolved_transport]);
    notes.push(format!("public DNS bypass deny: {dns_bypass:?}"));

    let host_gateway = host_gateway_probe(podman, network, &image, inspect_text);
    notes.push(format!("host/gateway deny: {host_gateway:?}"));

    let ipv6_ping = deny_command_probe(
        podman,
        network,
        &image,
        &["ping", "-6", "-c", "1", "-W", "2", "2001:4860:4860::8888"],
    );
    let ipv6_bypass = ipv6_ping;
    notes.push(format!("IPv6 bypass deny: {ipv6_bypass:?}"));

    let _ = Command::new(podman)
        .args(["rm", "-f", &target_name])
        .status();
    PacketIsolation {
        ran: true,
        target_reachability,
        external_egress,
        dns_bypass,
        host_gateway,
        ipv6_bypass,
        notes,
    }
}

fn combine_denials(values: &[ProbeOutcome]) -> ProbeOutcome {
    if values.contains(&ProbeOutcome::Failed) {
        ProbeOutcome::Failed
    } else if values.iter().all(|value| *value == ProbeOutcome::Proven) {
        ProbeOutcome::Proven
    } else {
        ProbeOutcome::Indeterminate
    }
}

fn allow_transport_probe(
    podman: &Path,
    network: &str,
    image: &str,
    host: &str,
    port: u16,
) -> ProbeOutcome {
    match nc_probe(podman, network, image, host, port) {
        Some(output) if output.status.success() => ProbeOutcome::Proven,
        Some(_) => ProbeOutcome::Failed,
        None => ProbeOutcome::Indeterminate,
    }
}

fn deny_transport_probe(
    podman: &Path,
    network: &str,
    image: &str,
    host: &str,
    port: u16,
) -> ProbeOutcome {
    match nc_probe(podman, network, image, host, port) {
        Some(output) if output.status.success() => ProbeOutcome::Failed,
        Some(_) => ProbeOutcome::Proven,
        None => ProbeOutcome::Indeterminate,
    }
}

fn nc_probe(podman: &Path, network: &str, image: &str, host: &str, port: u16) -> Option<Output> {
    let port_string = port.to_string();
    probe_exec(
        podman,
        network,
        image,
        &["nc", "-z", "-w", "2", host, &port_string],
        Duration::from_secs(12),
    )
}

/// Command-level denial is reserved for protocols where a successful command
/// itself proves reachability (DNS query/ping). HTTP status commands are not
/// accepted here.
fn deny_command_probe(podman: &Path, network: &str, image: &str, argv: &[&str]) -> ProbeOutcome {
    match probe_exec(podman, network, image, argv, Duration::from_secs(12)) {
        Some(output) if output.status.success() => ProbeOutcome::Failed,
        Some(_) => ProbeOutcome::Proven,
        None => ProbeOutcome::Indeterminate,
    }
}

fn host_gateway_probe(
    podman: &Path,
    network: &str,
    image: &str,
    inspect_text: &str,
) -> ProbeOutcome {
    let Some(gateway) = extract_gateway(inspect_text) else {
        return ProbeOutcome::Proven;
    };
    // Ping and multiple common service ports must all be denied. A refused TCP
    // port alone is not treated as proof that the gateway is unreachable.
    let ping = deny_command_probe(
        podman,
        network,
        image,
        &["ping", "-c", "1", "-W", "2", &gateway],
    );
    let ssh = deny_transport_probe(podman, network, image, &gateway, 22);
    let http = deny_transport_probe(podman, network, image, &gateway, 80);
    combine_denials(&[ping, ssh, http])
}

fn probe_exec(
    podman: &Path,
    network: &str,
    image: &str,
    argv: &[&str],
    timeout: Duration,
) -> Option<Output> {
    let mut args: Vec<String> = [
        "run",
        "--rm",
        "--network",
        network,
        "--pull=never",
        "--timeout",
        "8",
        image,
    ]
    .into_iter()
    .map(str::to_string)
    .collect();
    args.extend(argv.iter().map(|value| (*value).to_string()));
    run_timeout(Command::new(podman).args(&args), timeout)
}

fn extract_gateway(inspect_text: &str) -> Option<String> {
    let lower = inspect_text.to_ascii_lowercase();
    for key in ["\"gateway\": \"", "\"gateway\":\""] {
        if let Some(index) = lower.find(key) {
            let rest = &inspect_text[index + key.len()..];
            let end = rest.find('"').unwrap_or(0);
            let value = rest[..end].trim();
            if !value.is_empty() && value != "null" {
                return Some(value.to_string());
            }
        }
    }
    None
}

fn container_ip(podman: &Path, name: &str) -> Option<String> {
    let output = run_timeout(
        Command::new(podman).args([
            "inspect",
            "-f",
            "{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}",
            name,
        ]),
        Duration::from_secs(10),
    )?;
    if !output.status.success() {
        return None;
    }
    let ip = String::from_utf8(output.stdout).ok()?;
    let ip = ip.trim();
    (!ip.is_empty()).then(|| ip.to_string())
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
    .is_some_and(|output| output.status.success());
    pulled.then_some("docker.io/library/alpine:latest".into())
}

fn image_exists(podman: &Path, name: &str) -> bool {
    run_timeout(
        Command::new(podman).args(["image", "exists", name]),
        Duration::from_secs(10),
    )
    .is_some_and(|output| output.status.success())
}

fn may_pull_image() -> bool {
    match std::env::var(env_name("OCI_PULL")).ok().as_deref() {
        Some("0") => false,
        Some("1") => true,
        _ => !cfg!(test),
    }
}

fn run_timeout(command: &mut Command, timeout: Duration) -> Option<Output> {
    command.stdout(Stdio::piped());
    command.stderr(Stdio::piped());
    let mut child = command.spawn().ok()?;
    let start = Instant::now();
    loop {
        match child.try_wait() {
            Ok(Some(status)) => {
                let mut stdout = Vec::new();
                let mut stderr = Vec::new();
                if let Some(mut stream) = child.stdout.take() {
                    let _ = stream.read_to_end(&mut stdout);
                }
                if let Some(mut stream) = child.stderr.take() {
                    let _ = stream.read_to_end(&mut stderr);
                }
                return Some(Output {
                    status,
                    stdout,
                    stderr,
                });
            }
            Ok(None) if start.elapsed() < timeout => thread_sleep(),
            Ok(None) => {
                let _ = child.kill();
                let _ = child.wait();
                return None;
            }
            Err(_) => return None,
        }
    }
}

fn thread_sleep() {
    std::thread::sleep(Duration::from_millis(50));
}

fn find_podman() -> Option<PathBuf> {
    if let Ok(explicit) = std::env::var(env_name("PODMAN")) {
        let path = PathBuf::from(explicit);
        if path.is_file() {
            return Some(path);
        }
    }
    if let Some(path) = which_path("podman") {
        return Some(path);
    }
    let local = std::env::var_os("LOCALAPPDATA")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("."));
    [
        local.join("Programs").join("Podman").join("podman.exe"),
        PathBuf::from(r"C:\Program Files\RedHat\Podman\podman.exe"),
        PathBuf::from(r"C:\Program Files\Podman\podman.exe"),
    ]
    .into_iter()
    .find(|path| path.is_file())
}

fn which_path(binary: &str) -> Option<PathBuf> {
    std::env::var_os("PATH").and_then(|paths| {
        std::env::split_paths(&paths).find_map(|dir| {
            let path = dir.join(binary);
            if path.is_file() {
                return Some(path);
            }
            let executable = path.with_extension("exe");
            executable.is_file().then_some(executable)
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
                "no rootless OCI runtime (podman); campaign fails closed".into(),
            )),
            Some(_) if !self.containment_ok() => Err(SandboxError::FailClosed(
                "OCI runtime present but fresh live packet isolation is not demonstrated".into(),
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
        Err(SandboxError::FailClosed(
            "campaign-bound OCI target construction is not implemented; capability probe is not an execution sandbox".into(),
        ))
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
        Err(SandboxError::FailClosed(
            "campaign-bound OCI target spawn is not implemented".into(),
        ))
    }

    fn execute(
        &self,
        handle: &SandboxHandle,
        _argv: &[String],
        _env: &std::collections::BTreeMap<String, String>,
    ) -> Result<super::ExecResult, SandboxError> {
        if handle.phase != SandboxPhase::Running {
            return Err(SandboxError::InvalidState);
        }
        Err(SandboxError::FailClosed(
            "raw podman argv execution is forbidden; typed campaign-bound execution is required"
                .into(),
        ))
    }

    fn snapshot(&self, _handle: &SandboxHandle) -> Result<String, SandboxError> {
        Err(SandboxError::FailClosed(
            "campaign-bound OCI snapshot is not implemented".into(),
        ))
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
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    fn proven_report() -> ContainmentReport {
        ContainmentReport {
            runtime_present: true,
            machine_reachable: true,
            internal_network: true,
            policy_public_internet_deny: true,
            policy_host_socket_deny: true,
            target_reachable: true,
            unauthorized_external_denied: true,
            dns_bypass_denied: true,
            host_gateway_denied: true,
            ipv6_bypass_denied: true,
            target_reachability_probe: ProbeOutcome::Proven,
            external_egress_probe: ProbeOutcome::Proven,
            dns_bypass_probe: ProbeOutcome::Proven,
            host_gateway_probe: ProbeOutcome::Proven,
            ipv6_bypass_probe: ProbeOutcome::Proven,
            packet_probes_ran: true,
            notes: Vec::new(),
        }
    }

    #[test]
    fn live_claim_requires_all_five_proven() {
        let mut report = proven_report();
        assert!(report.live_oci_claimable());
        report.external_egress_probe = ProbeOutcome::Indeterminate;
        assert!(!report.live_oci_claimable());
        report.external_egress_probe = ProbeOutcome::Failed;
        assert!(!report.live_oci_claimable());
    }

    #[test]
    fn legacy_boolean_cannot_override_indeterminate_probe() {
        let mut report = proven_report();
        report.external_egress_probe = ProbeOutcome::Indeterminate;
        report.unauthorized_external_denied = true;
        assert!(!report.live_oci_claimable());
    }

    #[test]
    fn absent_gateway_is_positive_only_for_that_dimension() {
        assert_eq!(extract_gateway(r#"{"subnets":[{"gateway":null}]}"#), None);
    }
}
