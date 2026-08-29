//! Campaign-bound rootless OCI target execution.
//!
//! Unlike `ContainmentReport` capability probing, this module creates the exact
//! network and container that execute a campaign target. The same campaign
//! network is probed before the target is admitted. Only a random loopback
//! published port is exposed back to the trusted Rust control plane.

use std::io::Read;
use std::net::{TcpListener, TcpStream};
use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};
use std::time::{Duration, Instant};

use aros_types::{env_name, BINARY_NAME, SandboxId};

use crate::oci::{ContainmentReport, ProbeOutcome};
use crate::SandboxError;

const TARGET_PORT: u16 = 18080;

/// Concrete campaign resources. `sandbox_id` is embedded in both runtime names
/// so evidence referencing it maps to resources that actually existed.
pub struct CampaignOciTarget {
    pub sandbox_id: SandboxId,
    pub container_id: String,
    pub host_port: u16,
    pub containment_report: ContainmentReport,
    runtime: PathBuf,
    network_name: String,
    container_name: String,
    stopped: bool,
}

impl CampaignOciTarget {
    pub fn start(target_root: &Path) -> Result<Self, SandboxError> {
        let runtime = find_podman().ok_or_else(|| {
            SandboxError::FailClosed("rootless Podman is required for contained target execution".into())
        })?;
        if !podman_reachable(&runtime) {
            return Err(SandboxError::FailClosed(
                "Podman exists but its rootless machine/runtime is unreachable".into(),
            ));
        }
        let root = target_root.canonicalize()?;
        if !root.join("server.py").is_file() {
            return Err(SandboxError::FailClosed(
                "contained fixture target must contain server.py".into(),
            ));
        }

        let target_image = resolve_target_image(&runtime).ok_or_else(|| {
            SandboxError::FailClosed(
                "Python OCI target image is unavailable; configure TARGET_CONTAINER_IMAGE or enable OCI_PULL"
                    .into(),
            )
        })?;
        let sandbox_id = SandboxId::new();
        let short_id = sandbox_id.to_string();
        let network_name = format!("{BINARY_NAME}-campaign-{short_id}");
        let container_name = format!("{BINARY_NAME}-campaign-{short_id}-target");

        create_internal_network(&runtime, &network_name)?;
        let result = Self::start_on_created_network(
            runtime.clone(),
            root,
            target_image,
            sandbox_id,
            network_name.clone(),
            container_name.clone(),
        );
        if result.is_err() {
            cleanup(&runtime, &container_name, &network_name);
        }
        result
    }

    fn start_on_created_network(
        runtime: PathBuf,
        root: PathBuf,
        target_image: String,
        sandbox_id: SandboxId,
        network_name: String,
        container_name: String,
    ) -> Result<Self, SandboxError> {
        let inspect_text = inspect_internal_network(&runtime, &network_name)?;
        let containment_report = probe_campaign_network(&runtime, &network_name, &inspect_text)?;
        if !containment_report.live_oci_claimable() {
            return Err(SandboxError::FailClosed(
                "campaign network did not prove all five containment dimensions".into(),
            ));
        }

        let reservation = TcpListener::bind("127.0.0.1:0")?;
        let host_port = reservation.local_addr()?.port();
        drop(reservation);
        let publish = format!("127.0.0.1:{host_port}:{TARGET_PORT}");
        let mount = format!("{}:/target:ro", root.display());
        let target_port = TARGET_PORT.to_string();
        let started = run_timeout(
            Command::new(&runtime).args([
                "run",
                "-d",
                "--name",
                &container_name,
                "--network",
                &network_name,
                "--pull=never",
                "--read-only",
                "--cap-drop=ALL",
                "--security-opt",
                "no-new-privileges",
                "--pids-limit",
                "128",
                "--memory",
                "256m",
                "--cpus",
                "1",
                "--tmpfs",
                "/tmp:rw,noexec,nosuid,size=32m",
                "--publish",
                &publish,
                "--volume",
                &mount,
                "--workdir",
                "/target",
                "--env",
                "SECURITY_FIXTURE_BIND=0.0.0.0",
                "--env",
                &format!("SECURITY_FIXTURE_PORT={target_port}"),
                &target_image,
                "python",
                "server.py",
            ]),
            Duration::from_secs(30),
        )
        .ok_or_else(|| SandboxError::FailClosed("contained target launch timed out".into()))?;
        if !started.status.success() {
            return Err(SandboxError::FailClosed(format!(
                "contained target launch failed: {}",
                String::from_utf8_lossy(&started.stderr)
            )));
        }
        let container_id = String::from_utf8(started.stdout)
            .map_err(|_| SandboxError::FailClosed("Podman container id was not UTF-8".into()))?
            .trim()
            .to_string();
        if container_id.is_empty() {
            return Err(SandboxError::FailClosed(
                "Podman did not return a concrete target container id".into(),
            ));
        }

        let deadline = Instant::now() + Duration::from_secs(8);
        while Instant::now() < deadline {
            if TcpStream::connect(("127.0.0.1", host_port)).is_ok() {
                return Ok(Self {
                    sandbox_id,
                    container_id,
                    host_port,
                    containment_report,
                    runtime,
                    network_name,
                    container_name,
                    stopped: false,
                });
            }
            std::thread::sleep(Duration::from_millis(50));
        }
        Err(SandboxError::FailClosed(
            "contained target did not become reachable through trusted loopback publication".into(),
        ))
    }

    pub fn stop(&mut self) {
        if self.stopped {
            return;
        }
        cleanup(&self.runtime, &self.container_name, &self.network_name);
        self.stopped = true;
    }
}

impl Drop for CampaignOciTarget {
    fn drop(&mut self) {
        self.stop();
    }
}

fn create_internal_network(runtime: &Path, network: &str) -> Result<(), SandboxError> {
    let created = run_timeout(
        Command::new(runtime).args(["network", "create", "--internal", network]),
        Duration::from_secs(20),
    );
    match created {
        Some(output) if output.status.success() => Ok(()),
        Some(output) => Err(SandboxError::FailClosed(format!(
            "campaign network create failed: {}",
            String::from_utf8_lossy(&output.stderr)
        ))),
        None => Err(SandboxError::FailClosed(
            "campaign network create timed out".into(),
        )),
    }
}

fn inspect_internal_network(runtime: &Path, network: &str) -> Result<String, SandboxError> {
    let output = run_timeout(
        Command::new(runtime).args(["network", "inspect", network]),
        Duration::from_secs(15),
    )
    .ok_or_else(|| SandboxError::FailClosed("campaign network inspect timed out".into()))?;
    if !output.status.success() {
        return Err(SandboxError::FailClosed(
            "campaign network inspect failed".into(),
        ));
    }
    let text = String::from_utf8(output.stdout)
        .map_err(|_| SandboxError::FailClosed("campaign network inspect was not UTF-8".into()))?;
    let lower = text.to_ascii_lowercase();
    if !(lower.contains("\"internal\": true") || lower.contains("\"internal\":true")) {
        return Err(SandboxError::FailClosed(
            "campaign network is not reported as internal".into(),
        ));
    }
    Ok(text)
}

fn probe_campaign_network(
    runtime: &Path,
    network: &str,
    inspect_text: &str,
) -> Result<ContainmentReport, SandboxError> {
    let image = resolve_probe_image(runtime).ok_or_else(|| {
        SandboxError::FailClosed("alpine/busybox probe image unavailable".into())
    })?;
    let preflight = probe_exec(
        runtime,
        network,
        &image,
        &["sh", "-c", "command -v nc >/dev/null && command -v ping >/dev/null && command -v nslookup >/dev/null"],
    );
    if !preflight.is_some_and(|output| output.status.success()) {
        return Err(SandboxError::FailClosed(
            "campaign network probe tools are unavailable".into(),
        ));
    }

    let probe_target = format!("{BINARY_NAME}-probe-{}", SandboxId::new());
    let started = run_timeout(
        Command::new(runtime).args([
            "run",
            "-d",
            "--name",
            &probe_target,
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
        Some(output) if output.status.success() => {
            allow_transport(runtime, network, &image, &probe_target, 18080)
        }
        Some(_) => ProbeOutcome::Failed,
        None => ProbeOutcome::Indeterminate,
    };
    let external_egress = deny_transport(runtime, network, &image, "1.1.1.1", 80);
    let dns_direct = deny_command(
        runtime,
        network,
        &image,
        &["nslookup", "example.com", "8.8.8.8"],
    );
    let dns_transport = deny_transport(runtime, network, &image, "one.one.one.one", 80);
    let dns_bypass = combine_denials(&[dns_direct, dns_transport]);
    let host_gateway = match extract_gateway(inspect_text) {
        None => ProbeOutcome::Proven,
        Some(gateway) => combine_denials(&[
            deny_command(runtime, network, &image, &["ping", "-c", "1", "-W", "2", &gateway]),
            deny_transport(runtime, network, &image, &gateway, 80),
        ]),
    };
    let ipv6_bypass = deny_command(
        runtime,
        network,
        &image,
        &["ping", "-6", "-c", "1", "-W", "2", "2001:4860:4860::8888"],
    );
    let _ = Command::new(runtime).args(["rm", "-f", &probe_target]).status();

    Ok(ContainmentReport {
        runtime_present: true,
        machine_reachable: true,
        internal_network: true,
        policy_public_internet_deny: true,
        policy_host_socket_deny: true,
        target_reachable: target_reachability == ProbeOutcome::Proven,
        unauthorized_external_denied: external_egress == ProbeOutcome::Proven,
        dns_bypass_denied: dns_bypass == ProbeOutcome::Proven,
        host_gateway_denied: host_gateway == ProbeOutcome::Proven,
        ipv6_bypass_denied: ipv6_bypass == ProbeOutcome::Proven,
        target_reachability_probe: target_reachability,
        external_egress_probe: external_egress,
        dns_bypass_probe: dns_bypass,
        host_gateway_probe: host_gateway,
        ipv6_bypass_probe: ipv6_bypass,
        packet_probes_ran: true,
        notes: vec![format!("campaign-bound network={network}; probe_image={image}")],
    })
}

fn allow_transport(runtime: &Path, network: &str, image: &str, host: &str, port: u16) -> ProbeOutcome {
    match nc(runtime, network, image, host, port) {
        Some(output) if output.status.success() => ProbeOutcome::Proven,
        Some(_) => ProbeOutcome::Failed,
        None => ProbeOutcome::Indeterminate,
    }
}

fn deny_transport(runtime: &Path, network: &str, image: &str, host: &str, port: u16) -> ProbeOutcome {
    match nc(runtime, network, image, host, port) {
        Some(output) if output.status.success() => ProbeOutcome::Failed,
        Some(_) => ProbeOutcome::Proven,
        None => ProbeOutcome::Indeterminate,
    }
}

fn nc(runtime: &Path, network: &str, image: &str, host: &str, port: u16) -> Option<Output> {
    let port = port.to_string();
    probe_exec(runtime, network, image, &["nc", "-z", "-w", "2", host, &port])
}

fn deny_command(runtime: &Path, network: &str, image: &str, argv: &[&str]) -> ProbeOutcome {
    match probe_exec(runtime, network, image, argv) {
        Some(output) if output.status.success() => ProbeOutcome::Failed,
        Some(_) => ProbeOutcome::Proven,
        None => ProbeOutcome::Indeterminate,
    }
}

fn probe_exec(runtime: &Path, network: &str, image: &str, argv: &[&str]) -> Option<Output> {
    let mut args = vec![
        "run".to_string(),
        "--rm".into(),
        "--network".into(),
        network.into(),
        "--pull=never".into(),
        image.into(),
    ];
    args.extend(argv.iter().map(|value| (*value).to_string()));
    run_timeout(Command::new(runtime).args(args), Duration::from_secs(12))
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

fn extract_gateway(inspect_text: &str) -> Option<String> {
    let lower = inspect_text.to_ascii_lowercase();
    for key in ["\"gateway\": \"", "\"gateway\":\""] {
        if let Some(index) = lower.find(key) {
            let rest = &inspect_text[index + key.len()..];
            let end = rest.find('"')?;
            let value = rest[..end].trim();
            if !value.is_empty() && value != "null" {
                return Some(value.to_string());
            }
        }
    }
    None
}

fn resolve_probe_image(runtime: &Path) -> Option<String> {
    for candidate in ["alpine", "docker.io/library/alpine:latest", "busybox"] {
        if image_exists(runtime, candidate) {
            return Some(candidate.to_string());
        }
    }
    if !may_pull() {
        return None;
    }
    let image = "docker.io/library/alpine:latest";
    let output = run_timeout(Command::new(runtime).args(["pull", image]), Duration::from_secs(120));
    output
        .is_some_and(|result| result.status.success())
        .then(|| image.to_string())
}

fn resolve_target_image(runtime: &Path) -> Option<String> {
    let image = std::env::var(env_name("TARGET_CONTAINER_IMAGE"))
        .ok()
        .filter(|value| !value.trim().is_empty())
        .unwrap_or_else(|| "docker.io/library/python:3.14-alpine".into());
    if image_exists(runtime, &image) {
        return Some(image);
    }
    if !may_pull() {
        return None;
    }
    let output = run_timeout(
        Command::new(runtime).args(["pull", &image]),
        Duration::from_secs(120),
    );
    output
        .is_some_and(|result| result.status.success())
        .then_some(image)
}

fn image_exists(runtime: &Path, image: &str) -> bool {
    run_timeout(
        Command::new(runtime).args(["image", "exists", image]),
        Duration::from_secs(10),
    )
    .is_some_and(|output| output.status.success())
}

fn may_pull() -> bool {
    match std::env::var(env_name("OCI_PULL")).ok().as_deref() {
        Some("0") => false,
        Some("1") => true,
        _ => !cfg!(test),
    }
}

fn podman_reachable(runtime: &Path) -> bool {
    run_timeout(Command::new(runtime).arg("info"), Duration::from_secs(15))
        .is_some_and(|output| output.status.success())
}

fn cleanup(runtime: &Path, container: &str, network: &str) {
    let _ = Command::new(runtime).args(["rm", "-f", container]).status();
    let _ = Command::new(runtime).args(["network", "rm", "-f", network]).status();
}

fn find_podman() -> Option<PathBuf> {
    if let Ok(explicit) = std::env::var(env_name("PODMAN")) {
        let path = PathBuf::from(explicit);
        if path.is_file() {
            return Some(path);
        }
    }
    std::env::var_os("PATH").and_then(|paths| {
        std::env::split_paths(&paths).find_map(|dir| {
            let plain = dir.join("podman");
            if plain.is_file() {
                return Some(plain);
            }
            let exe = plain.with_extension("exe");
            exe.is_file().then_some(exe)
        })
    })
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn denial_combiner_never_promotes_indeterminate() {
        assert_eq!(
            combine_denials(&[ProbeOutcome::Proven, ProbeOutcome::Indeterminate]),
            ProbeOutcome::Indeterminate
        );
        assert_eq!(
            combine_denials(&[ProbeOutcome::Proven, ProbeOutcome::Failed]),
            ProbeOutcome::Failed
        );
    }
}
