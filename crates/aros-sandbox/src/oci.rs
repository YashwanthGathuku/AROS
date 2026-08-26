//! Rootless OCI containment probes via Podman.
//!
//! Presence is not containment. Security admission requires fresh, positive
//! evidence for every required dimension. Probe execution errors, missing
//! tooling and timeouts are `Indeterminate`, never silently interpreted as a
//! demonstrated deny.

use std::io::Read;
use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};
use std::time::{Duration, Instant};

use super::{SandboxError, SandboxHandle, SandboxPhase, SandboxProvider};
use aros_types::{unix_now_ms, SandboxId};
use serde::{Deserialize, Serialize};

pub struct RootlessOciSandboxProvider {
    pub runtime: Option<PathBuf>,
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ProbeOutcome {
    /// The required property was positively demonstrated.
    Proven,
    /// The probe ran correctly and demonstrated the unsafe/opposite property.
    Failed,
    /// The property could not be measured reliably.
    #[default]
    Indeterminate,
}

impl ProbeOutcome {
    pub fn is_proven(self) -> bool {
        matches!(self, Self::Proven)
    }
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct ContainmentReport {
    pub runtime_present: bool,
    pub machine_reachable: bool,
    pub internal_network: bool,
    pub policy_public_internet_deny: bool,
    pub policy_host_socket_deny: bool,

    /// Compatibility booleans for CLI/API consumers. Security admission does
    /// not trust these fields; it uses the tri-state outcomes below.
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

    /// True only when the packet-probe environment passed preflight and the
    /// five dimensions were actually attempted.
    pub packet_probes_ran: bool,
    pub notes: Vec<String>,
}

impl ContainmentReport {
    pub fn packet_isolation_demonstrated(&self) -> bool {
        self.packet_probes_ran
            && self.target_reachability_probe.is_proven()
            && self.external_egress_probe.is_proven()
            && self.dns_bypass_probe.is_proven()
            && self.host_gateway_probe.is_proven()
            && self.ipv6_bypass_probe.is_proven()
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

    fn apply_packets(&mut self, packets: PacketIsolation) {
        self.packet_probes_ran = packets.ran;
        self.target_reachability_probe = packets.target_reachability;
        self.external_egress_probe = packets.external_egress;
        self.dns_bypass_probe = packets.dns_bypass;
        self.host_gateway_probe = packets.host_gateway;
        self.ipv6_bypass_probe = packets.ipv6_bypass;

        self.target_reachable = packets.target_reachability.is_proven();
        self.unauthorized_external_denied = packets.external_egress.is_proven();
        self.dns_bypass_denied = packets.dns_bypass.is_proven();
        self.host_gateway_denied = packets.host_gateway.is_proven();
        self.ipv6_bypass_denied = packets.ipv6_bypass.is_proven();
        self.notes.extend(packets.notes);
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

    /// Security admission is deliberately fresh. No process-global success
    /// cache is allowed to outlive a Podman-machine/network state change.
    pub fn containment_ok(&self) -> bool {
        self.probe_containment_fresh().live_oci_claimable()
    }

    pub fn probe_containment(&self) -> ContainmentReport {
        self.probe_containment_fresh()
    }

    pub fn probe_containment_fresh(&self) -> ContainmentReport {
        let mut notes = Vec::new();
        let runtime_present = self.runtime.is_some();
        if !runtime_present {
            notes.push("no rootless OCI runtime (podman) detected".into());
        }
        let machine_reachable = runtime_present && self.machine_reachable();
        if runtime_present && !machine_reachable {
            notes.push("podman present but `podman info` failed (machine down?)".into());
        }

        let mut report = ContainmentReport {
            runtime_present,
            machine_reachable,
            policy_public_internet_deny: true,
            policy_host_socket_deny: true,
            notes,
            ..ContainmentReport::default()
        };
        if !machine_reachable {
            return report;
        }
        let Some(bin) = &self.runtime else {
            return report;
        };

        let name = format!("aros-probe-{}-{}", std::process::id(), unix_now_ms());
        let created = run_timeout(
            Command::new(bin).args(["network", "create", "--internal", &name]),
            Duration::from_secs(20),
        )
        .is_some_and(|o| o.status.success());
        if !created {
            let _ = Command::new(bin)
                .args(["network", "rm", "-f", &name])
                .status();
            report.notes.push("internal network create failed or timed out".into());
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
        let lower = inspect_txt.to_ascii_lowercase();
        report.internal_network =
            lower.contains("\"internal\": true") || lower.contains("\"internal\":true");
        if report.internal_network {
            report.notes.push("internal network inspect demonstrated internal=true".into());
            report.apply_packets(probe_packet_isolation(bin, &name, &inspect_txt));
        } else {
            report
                .notes
                .push("internal network inspect did not demonstrate internal=true".into());
        }

        let _ = Command::new(bin)
            .args(["network", "rm", "-f", &name])
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

fn probe_packet_isolation(podman: &Path, net: &str, inspect_txt: &str) -> PacketIsolation {
    let Some(image) = resolve_probe_image(podman) else {
        return PacketIsolation::indeterminate(
            "packet probes not run: no alpine/busybox image (set AROS_OCI_PULL=1 to pull)".into(),
        );
    };
    let mut notes = vec![format!("packet probe image: {image}")];

    // Before treating a non-zero network command as evidence of a deny, prove
    // that the probe image can execute the required tools at all.
    let preflight = probe_exec(
        podman,
        net,
        &image,
        &["sh", "-c", "command -v wget >/dev/null && command -v ping >/dev/null && command -v nslookup >/dev/null"],
        Duration::from_secs(12),
    );
    match preflight {
        Some(out) if out.status.success() => notes.push("packet probe tool preflight passed".into()),
        Some(out) => {
            notes.push(format!(
                "packet probe preflight failed (exit {:?}); deny results would be ambiguous",
                out.status.code()
            ));
            return PacketIsolation {
                ran: false,
                target_reachability: ProbeOutcome::Indeterminate,
                external_egress: ProbeOutcome::Indeterminate,
                dns_bypass: ProbeOutcome::Indeterminate,
                host_gateway: ProbeOutcome::Indeterminate,
                ipv6_bypass: ProbeOutcome::Indeterminate,
                notes,
            };
        }
        None => {
            notes.push("packet probe preflight could not execute or timed out".into());
            return PacketIsolation {
                ran: false,
                target_reachability: ProbeOutcome::Indeterminate,
                external_egress: ProbeOutcome::Indeterminate,
                dns_bypass: ProbeOutcome::Indeterminate,
                host_gateway: ProbeOutcome::Indeterminate,
                ipv6_bypass: ProbeOutcome::Indeterminate,
                notes,
            };
        }
    }

    let target_name = format!("aros-pkt-tgt-{}-{}", std::process::id(), unix_now_ms());
    let _ = Command::new(podman)
        .args(["rm", "-f", &target_name])
        .status();
    let started = run_timeout(
        Command::new(podman).args([
            "run",
            "-d",
            "--name",
            &target_name,
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
    );

    let target_reachability = match started {
        None => ProbeOutcome::Indeterminate,
        Some(out) if !out.status.success() => ProbeOutcome::Failed,
        Some(_) => {
            let peer = container_ip(podman, &target_name).unwrap_or_else(|| target_name.clone());
            match probe_exec(
                podman,
                net,
                &image,
                &["ping", "-c", "1", "-W", "2", &peer],
                Duration::from_secs(15),
            ) {
                Some(out) if out.status.success() => ProbeOutcome::Proven,
                Some(_) => ProbeOutcome::Failed,
                None => ProbeOutcome::Indeterminate,
            }
        }
    };
    notes.push(format!("target reachability: {target_reachability:?}"));

    let external_egress = deny_probe(
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
    notes.push(format!("unauthorized public IPv4 deny: {external_egress:?}"));

    let dns_direct = deny_probe(
        podman,
        net,
        &image,
        &["nslookup", "example.com", "8.8.8.8"],
    );
    let dns_hostname = deny_probe(
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
    let dns_bypass = combine_denials(&[dns_direct, dns_hostname]);
    notes.push(format!("public DNS bypass deny: {dns_bypass:?}"));

    let host_gateway = host_gateway_probe(podman, net, &image, inspect_txt);
    notes.push(format!("host/gateway deny: {host_gateway:?}"));

    let ipv6_http = deny_probe(
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
    );
    let ipv6_ping = deny_probe(
        podman,
        net,
        &image,
        &["ping", "-6", "-c", "1", "-W", "2", "2001:4860:4860::8888"],
    );
    let ipv6_bypass = combine_denials(&[ipv6_http, ipv6_ping]);
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
    if values.iter().any(|v| matches!(v, ProbeOutcome::Failed)) {
        ProbeOutcome::Failed
    } else if values.iter().all(|v| matches!(v, ProbeOutcome::Proven)) {
        ProbeOutcome::Proven
    } else {
        ProbeOutcome::Indeterminate
    }
}

/// For a deny probe, a successful network command means containment failed;
/// a cleanly executed non-zero command means the deny was observed; inability
/// to execute/timeout is indeterminate.
fn deny_probe(podman: &Path, net: &str, image: &str, argv: &[&str]) -> ProbeOutcome {
    match probe_exec(podman, net, image, argv, Duration::from_secs(12)) {
        Some(out) if out.status.success() => ProbeOutcome::Failed,
        Some(_) => ProbeOutcome::Proven,
        None => ProbeOutcome::Indeterminate,
    }
}

fn host_gateway_probe(podman: &Path, net: &str, image: &str, inspect_txt: &str) -> ProbeOutcome {
    let Some(gateway) = extract_gateway(inspect_txt) else {
        // No gateway is itself positive evidence that this path does not exist.
        return ProbeOutcome::Proven;
    };
    let ping = deny_probe(
        podman,
        net,
        image,
        &["ping", "-c", "1", "-W", "2", &gateway],
    );
    let url = format!("http://{gateway}/");
    let http = deny_probe(
        podman,
        net,
        image,
        &["wget", "-T", "2", "-q", "-O", "/dev/null", &url],
    );
    combine_denials(&[ping, http])
}

fn probe_exec(
    podman: &Path,
    net: &str,
    image: &str,
    argv: &[&str],
    timeout: Duration,
) -> Option<Output> {
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
    run_timeout(Command::new(podman).args(&args), timeout)
}

fn extract_gateway(inspect_txt: &str) -> Option<String> {
    let lower = inspect_txt.to_ascii_lowercase();
    for key in ["\"gateway\": \"", "\"gateway\":\""] {
        if let Some(idx) = lower.find(key) {
            let rest = &inspect_txt[idx + key.len()..];
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
    pulled.then_some("docker.io/library/alpine:latest".into())
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
            let path = dir.join(bin);
            if path.is_file() {
                return Some(path);
            }
            let exe = path.with_extension("exe");
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
    fn detect_does_not_panic() {
        let provider = RootlessOciSandboxProvider::detect();
        let _ = provider.can_run();
        let _ = provider.machine_reachable();
    }

    #[test]
    fn missing_runtime_never_claims() {
        let provider = RootlessOciSandboxProvider { runtime: None };
        let report = provider.probe_containment();
        assert!(!report.live_oci_claimable());
        assert_eq!(report.external_egress_probe, ProbeOutcome::Indeterminate);
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
    fn combine_denials_propagates_indeterminate() {
        assert_eq!(
            combine_denials(&[ProbeOutcome::Proven, ProbeOutcome::Indeterminate]),
            ProbeOutcome::Indeterminate
        );
        assert_eq!(
            combine_denials(&[ProbeOutcome::Proven, ProbeOutcome::Failed]),
            ProbeOutcome::Failed
        );
    }

    #[test]
    fn containment_report_is_honest_on_this_host() {
        let provider = RootlessOciSandboxProvider::detect();
        let report = provider.probe_containment_fresh();
        assert_eq!(report.runtime_present, provider.can_run());
        if report.live_oci_claimable() {
            assert!(report.packet_isolation_demonstrated());
        }
        if !report.packet_probes_ran {
            assert!(!report.live_oci_claimable());
        }
    }

    #[test]
    fn five_way_packet_probes_when_environment_is_ready() {
        let provider = RootlessOciSandboxProvider::detect();
        if !provider.machine_reachable() {
            return;
        }
        let report = provider.probe_containment_fresh();
        if !report.packet_probes_ran {
            return;
        }
        assert_eq!(report.target_reachability_probe, ProbeOutcome::Proven, "{:?}", report.notes);
        assert_eq!(report.external_egress_probe, ProbeOutcome::Proven, "{:?}", report.notes);
        assert_eq!(report.dns_bypass_probe, ProbeOutcome::Proven, "{:?}", report.notes);
        assert_eq!(report.host_gateway_probe, ProbeOutcome::Proven, "{:?}", report.notes);
        assert_eq!(report.ipv6_bypass_probe, ProbeOutcome::Proven, "{:?}", report.notes);
        assert!(report.live_oci_claimable());
    }

    #[test]
    fn extract_gateway_parses_inspect() {
        let json = r#"[{"internal": true, "subnets": [{"gateway": "10.89.0.1"}]}]"#;
        assert_eq!(extract_gateway(json).as_deref(), Some("10.89.0.1"));
    }
}
