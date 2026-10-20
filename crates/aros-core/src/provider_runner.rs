//! Run one external provider invocation under process, time, and output budgets.
//!
//! Unwaived execution calls [`CampaignOciTarget::exec_generator_ex`] and returns
//! that error when containment cannot be demonstrated. An explicit waiver runs
//! on the host, labeled [`ProviderExecutionKind::WaivedHost`]. Returned bytes
//! are untrusted provider output.

use std::io::{ErrorKind, Read};
use std::path::Path;
use std::process::{Command, ExitStatus, Stdio};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::thread;
use std::time::{Duration, Instant};

use aros_policy::shell::{argv_contains_shell_metacharacters, executable_is_shell};
use aros_sandbox::CampaignOciTarget;
use serde::{Deserialize, Serialize};

use crate::integrations::{IntegrationInvocation, IntegrationRole, GROK_PROMPT_PLACEHOLDER};

const MIN_WALL_CLOCK_MS: u64 = 1;
const MAX_WALL_CLOCK_MS: u64 = 10 * 60_000;
const MIN_MEMORY_MB: u32 = 1;
const MAX_MEMORY_MB: u32 = 4096;
const MAX_OUTPUT_BYTES: usize = 8 * 1024 * 1024;
const MAX_ARG_BYTES: usize = 4096;
const MAX_ARGV: usize = 32;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ProviderExecutionKind {
    /// `exec_generator_ex` returned after the campaign network proved containment.
    ContainedOci,
    /// Explicit waiver. This runner applied no memory limit and no network deny.
    WaivedHost,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProviderRunBudgets {
    pub wall_clock_ms: u64,
    pub memory_mb: u32,
    pub max_output_bytes: usize,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProviderRunOutput {
    pub provider: String,
    pub role: IntegrationRole,
    pub execution: ProviderExecutionKind,
    pub memory_mb_requested: u32,
    /// True only when the OCI path passed `--memory` to Podman.
    pub memory_limit_applied: bool,
    /// This runner does not make the work root read-only on either path.
    pub read_only_enforced: bool,
    /// True on the waived host path. That process keeps the host network stack.
    pub host_network_inherited: bool,
    pub max_output_bytes: usize,
    pub wall_clock_ms_elapsed: u64,
    pub exit_code: Option<i32>,
    pub stdout: Vec<u8>,
    pub stderr: Vec<u8>,
    /// OCI returns one combined string. `stderr` is empty in that case.
    pub streams_combined: bool,
    pub output_truncated: bool,
    /// True when the waived host path killed the process for the byte cap.
    pub output_killed_at_cap: bool,
}

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum ProviderRunError {
    #[error("{0}")]
    FailClosed(String),
}

/// Admit `invocation` and run it under `budgets`.
///
/// `waive_containment` is the only path that starts a host process. That result
/// uses [`ProviderExecutionKind::WaivedHost`].
pub fn run_provider(
    invocation: &IntegrationInvocation,
    work_root: &Path,
    budgets: ProviderRunBudgets,
    waive_containment: bool,
) -> Result<ProviderRunOutput, ProviderRunError> {
    validate_budgets(budgets)?;
    refuse_unbounded_invocation(invocation)?;
    if !work_root.is_dir() {
        return Err(ProviderRunError::FailClosed(
            "provider work root is not a directory".into(),
        ));
    }
    if let Some(cwd) = &invocation.cwd {
        if cwd.len() > MAX_ARG_BYTES || !same_directory(Path::new(cwd), work_root) {
            return Err(ProviderRunError::FailClosed(
                "invocation cwd does not match the runner work root".into(),
            ));
        }
    }

    if waive_containment {
        return run_waived_host(invocation, work_root, budgets);
    }
    run_contained(invocation, work_root, budgets)
}

fn validate_budgets(budgets: ProviderRunBudgets) -> Result<(), ProviderRunError> {
    if !(MIN_WALL_CLOCK_MS..=MAX_WALL_CLOCK_MS).contains(&budgets.wall_clock_ms) {
        return Err(ProviderRunError::FailClosed(format!(
            "provider wall_clock_ms is outside {MIN_WALL_CLOCK_MS}..={MAX_WALL_CLOCK_MS}"
        )));
    }
    if !(MIN_MEMORY_MB..=MAX_MEMORY_MB).contains(&budgets.memory_mb) {
        return Err(ProviderRunError::FailClosed(format!(
            "provider memory_mb is outside {MIN_MEMORY_MB}..={MAX_MEMORY_MB}"
        )));
    }
    if budgets.max_output_bytes == 0 || budgets.max_output_bytes > MAX_OUTPUT_BYTES {
        return Err(ProviderRunError::FailClosed(format!(
            "provider max_output_bytes is outside 1..={MAX_OUTPUT_BYTES}"
        )));
    }
    Ok(())
}

fn refuse_unbounded_invocation(invocation: &IntegrationInvocation) -> Result<(), ProviderRunError> {
    if invocation.may_authorize_actions {
        return Err(ProviderRunError::FailClosed(
            "provider invocation may not authorize actions".into(),
        ));
    }
    if invocation.may_verify_findings {
        return Err(ProviderRunError::FailClosed(
            "provider invocation may not verify findings".into(),
        ));
    }
    if invocation.executable.is_empty() || invocation.executable.len() > MAX_ARG_BYTES {
        return Err(ProviderRunError::FailClosed(
            "provider executable is empty or too long".into(),
        ));
    }
    if executable_is_shell(&invocation.executable) {
        return Err(ProviderRunError::FailClosed(
            "provider executable must not be a shell".into(),
        ));
    }
    if invocation.argv.len() > MAX_ARGV
        || invocation.argv.iter().any(|arg| arg.len() > MAX_ARG_BYTES)
    {
        return Err(ProviderRunError::FailClosed(
            "provider argv is too long".into(),
        ));
    }
    let mut program = Vec::with_capacity(invocation.argv.len() + 1);
    program.push(invocation.executable.clone());
    program.extend(invocation.argv.iter().cloned());
    if argv_contains_shell_metacharacters(&program) {
        return Err(ProviderRunError::FailClosed(
            "provider argv contains shell metacharacters".into(),
        ));
    }
    if invocation
        .argv
        .iter()
        .any(|arg| arg == GROK_PROMPT_PLACEHOLDER)
    {
        return Err(ProviderRunError::FailClosed(
            "provider prompt file is still the unbound placeholder".into(),
        ));
    }
    Ok(())
}

fn same_directory(planned: &Path, work_root: &Path) -> bool {
    match (planned.canonicalize(), work_root.canonicalize()) {
        (Ok(left), Ok(right)) => left == right,
        _ => false,
    }
}

fn run_contained(
    invocation: &IntegrationInvocation,
    work_root: &Path,
    budgets: ProviderRunBudgets,
) -> Result<ProviderRunOutput, ProviderRunError> {
    let mut argv = Vec::with_capacity(invocation.argv.len() + 1);
    argv.push(invocation.executable.clone());
    argv.extend(invocation.argv.iter().cloned());
    let started = Instant::now();
    let text = CampaignOciTarget::exec_generator_ex(
        work_root,
        &argv,
        Duration::from_millis(budgets.wall_clock_ms),
        budgets.memory_mb,
        None,
    )
    .map_err(|error| ProviderRunError::FailClosed(error.to_string()))?;
    let mut stdout = text.into_bytes();
    let output_truncated = stdout.len() > budgets.max_output_bytes;
    if output_truncated {
        stdout.truncate(budgets.max_output_bytes);
    }
    Ok(ProviderRunOutput {
        provider: invocation.provider.clone(),
        role: invocation.role,
        execution: ProviderExecutionKind::ContainedOci,
        memory_mb_requested: budgets.memory_mb,
        memory_limit_applied: true,
        read_only_enforced: false,
        host_network_inherited: false,
        max_output_bytes: budgets.max_output_bytes,
        wall_clock_ms_elapsed: elapsed_ms(started),
        exit_code: None,
        stdout,
        stderr: Vec::new(),
        streams_combined: true,
        output_truncated,
        output_killed_at_cap: false,
    })
}

fn run_waived_host(
    invocation: &IntegrationInvocation,
    work_root: &Path,
    budgets: ProviderRunBudgets,
) -> Result<ProviderRunOutput, ProviderRunError> {
    let started = Instant::now();
    let mut command = Command::new(&invocation.executable);
    command
        .args(&invocation.argv)
        .current_dir(work_root)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    scrub_env(&mut command);
    let mut child = command.spawn().map_err(|error| {
        ProviderRunError::FailClosed(format!("provider executable could not be started: {error}"))
    })?;
    let Some(stdout_pipe) = child.stdout.take() else {
        let _ = child.kill();
        let _ = child.wait();
        return Err(ProviderRunError::FailClosed(
            "provider stdout pipe was not created".into(),
        ));
    };
    let Some(stderr_pipe) = child.stderr.take() else {
        let _ = child.kill();
        let _ = child.wait();
        return Err(ProviderRunError::FailClosed(
            "provider stderr pipe was not created".into(),
        ));
    };

    let hit = Arc::new(AtomicBool::new(false));
    let stdout_hit = Arc::clone(&hit);
    let stderr_hit = Arc::clone(&hit);
    let limit = budgets.max_output_bytes;
    let stdout_reader = thread::spawn(move || read_limited(stdout_pipe, limit, &stdout_hit));
    let stderr_reader = thread::spawn(move || read_limited(stderr_pipe, limit, &stderr_hit));

    let wall = Duration::from_millis(budgets.wall_clock_ms);
    let stop = wait_for_child(&mut child, &started, wall, &hit);
    let stdout_result = stdout_reader.join();
    let stderr_result = stderr_reader.join();
    let (stdout, stdout_truncated) = stdout_result
        .map_err(|_| ProviderRunError::FailClosed("provider stdout reader stopped".into()))?;
    let (stderr, stderr_truncated) = stderr_result
        .map_err(|_| ProviderRunError::FailClosed("provider stderr reader stopped".into()))?;
    let output_killed_at_cap = matches!(stop, Stop::OutputCap(_));

    match stop {
        Stop::Timeout => Err(ProviderRunError::FailClosed(
            "provider exceeded wall_clock_ms".into(),
        )),
        Stop::WaitErr(error) => Err(ProviderRunError::FailClosed(format!(
            "provider process wait failed: {error}"
        ))),
        Stop::Exited(status) | Stop::OutputCap(status) => {
            let mut stdout = stdout;
            let mut stderr = stderr;
            let over_budget = stdout.len().saturating_add(stderr.len()) > budgets.max_output_bytes;
            if over_budget {
                let keep_out = stdout.len().min(budgets.max_output_bytes);
                stdout.truncate(keep_out);
                stderr.truncate(budgets.max_output_bytes - keep_out);
            }
            Ok(ProviderRunOutput {
                provider: invocation.provider.clone(),
                role: invocation.role,
                execution: ProviderExecutionKind::WaivedHost,
                memory_mb_requested: budgets.memory_mb,
                memory_limit_applied: false,
                read_only_enforced: false,
                host_network_inherited: true,
                max_output_bytes: budgets.max_output_bytes,
                wall_clock_ms_elapsed: elapsed_ms(started),
                exit_code: status.as_ref().and_then(ExitStatus::code),
                stdout,
                stderr,
                streams_combined: false,
                output_truncated: output_killed_at_cap
                    || stdout_truncated
                    || stderr_truncated
                    || over_budget,
                output_killed_at_cap,
            })
        }
    }
}

enum Stop {
    Exited(Option<ExitStatus>),
    OutputCap(Option<ExitStatus>),
    Timeout,
    WaitErr(std::io::Error),
}

fn wait_for_child(
    child: &mut std::process::Child,
    started: &Instant,
    wall: Duration,
    hit: &AtomicBool,
) -> Stop {
    loop {
        if hit.load(Ordering::SeqCst) {
            let _ = child.kill();
            return Stop::OutputCap(child.wait().ok());
        }
        if started.elapsed() >= wall {
            let _ = child.kill();
            let _ = child.wait();
            return Stop::Timeout;
        }
        match child.try_wait() {
            Ok(Some(status)) => return Stop::Exited(Some(status)),
            Ok(None) => thread::sleep(Duration::from_millis(20)),
            Err(error) => {
                let _ = child.kill();
                let _ = child.wait();
                return Stop::WaitErr(error);
            }
        }
    }
}

fn read_limited(mut reader: impl Read, limit: usize, hit: &AtomicBool) -> (Vec<u8>, bool) {
    let mut kept = Vec::new();
    let mut buf = [0u8; 8192];
    loop {
        if kept.len() >= limit {
            let mut extra = [0u8; 1];
            loop {
                match reader.read(&mut extra) {
                    Ok(0) => return (kept, false),
                    Ok(_) => {
                        hit.store(true, Ordering::SeqCst);
                        return (kept, true);
                    }
                    Err(error) if error.kind() == ErrorKind::Interrupted => continue,
                    Err(_) => {
                        hit.store(true, Ordering::SeqCst);
                        return (kept, true);
                    }
                }
            }
        }
        let want = buf.len().min(limit - kept.len());
        match reader.read(&mut buf[..want]) {
            Ok(0) => return (kept, false),
            Ok(n) => kept.extend_from_slice(&buf[..n]),
            Err(error) if error.kind() == ErrorKind::Interrupted => continue,
            Err(_) => return (kept, false),
        }
    }
}

fn scrub_env(command: &mut Command) {
    command.env_clear();
    for key in [
        "PATH",
        "PATHEXT",
        "SystemRoot",
        "SYSTEMROOT",
        "windir",
        "WINDIR",
        "TEMP",
        "TMP",
        "TMPDIR",
        "HOME",
        "USERPROFILE",
    ] {
        if let Some(value) = std::env::var_os(key) {
            command.env(key, value);
        }
    }
}

fn elapsed_ms(started: Instant) -> u64 {
    u64::try_from(started.elapsed().as_millis()).unwrap_or(u64::MAX)
}

#[cfg(test)]
#[allow(clippy::expect_used)]
mod tests {
    use std::process::Command;
    use std::time::{Duration, Instant};

    use super::*;
    use crate::integrations::{foreign_project_integrations, IntegrationRole};

    const HELPER_SRC: &str = r#"
fn main() {
    let mode = std::env::args().nth(1).unwrap_or_default();
    if mode == "sleep" {
        std::thread::sleep(std::time::Duration::from_secs(30));
        return;
    }
    if mode == "flood" {
        let chunk = vec![b'A'; 1024];
        let mut out = std::io::stdout();
        for _ in 0..8192 {
            let _ = std::io::Write::write_all(&mut out, &chunk);
        }
        return;
    }
    if mode == "env" {
        match std::env::var("CARGO_MANIFEST_DIR") {
            Ok(value) => println!("leaked:{value}"),
            Err(_) => println!("env-scrubbed"),
        }
        return;
    }
    println!("provider-bytes");
}
"#;

    fn budgets(wall_clock_ms: u64, max_output_bytes: usize) -> ProviderRunBudgets {
        ProviderRunBudgets {
            wall_clock_ms,
            memory_mb: 64,
            max_output_bytes,
        }
    }

    fn compile_helper(dir: &Path) -> std::path::PathBuf {
        let src = dir.join("helper.rs");
        std::fs::write(&src, HELPER_SRC).expect("helper source");
        let mut exe = dir.join("provider-helper");
        if cfg!(windows) {
            exe.set_extension("exe");
        }
        let output = Command::new("rustc")
            .arg("--edition=2021")
            .arg("-o")
            .arg(&exe)
            .arg(&src)
            .output()
            .expect("rustc");
        assert!(
            output.status.success(),
            "rustc failed: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        exe
    }

    fn helper_invocation(exe: &Path, work: &Path, args: &[&str]) -> IntegrationInvocation {
        IntegrationInvocation {
            provider: "test-helper".into(),
            role: IntegrationRole::ResearchHarness,
            executable: exe.display().to_string(),
            argv: args.iter().map(|arg| (*arg).to_string()).collect(),
            cwd: Some(work.display().to_string()),
            read_only: true,
            may_authorize_actions: false,
            may_verify_findings: false,
            output_semantics: "untrusted test bytes".into(),
        }
    }

    fn containment_failure(message: &str) -> bool {
        message.contains("rootless Podman")
            || message.contains("rootless machine/runtime is unreachable")
            || message.contains("no contained image mapping")
            || message.contains("campaign network did not prove")
    }

    #[test]
    fn authority_shell_placeholder_and_budgets_fail_closed_before_spawn() {
        let work = tempfile::tempdir().expect("work");
        let mut invocation = foreign_project_integrations(work.path()).grok_build;
        invocation.cwd = Some(work.path().display().to_string());
        invocation.executable = "aros-provider-missing-bin".into();
        invocation.may_authorize_actions = true;
        let error = run_provider(&invocation, work.path(), budgets(1_000, 1024), true)
            .expect_err("authority");
        assert!(error.to_string().contains("may not authorize actions"));

        invocation.may_authorize_actions = false;
        invocation.may_verify_findings = true;
        let error =
            run_provider(&invocation, work.path(), budgets(1_000, 1024), true).expect_err("verify");
        assert!(error.to_string().contains("may not verify findings"));

        invocation.may_verify_findings = false;
        invocation.executable = "powershell.exe".into();
        let error =
            run_provider(&invocation, work.path(), budgets(1_000, 1024), true).expect_err("shell");
        assert!(error.to_string().contains("must not be a shell"));

        invocation.executable = "aros-provider-missing-bin".into();
        invocation.argv = vec!["safe".into(), "a;b".into()];
        let error =
            run_provider(&invocation, work.path(), budgets(1_000, 1024), true).expect_err("meta");
        assert!(error.to_string().contains("shell metacharacters"));

        let unbound = foreign_project_integrations(work.path()).grok_build;
        let mut unbound = unbound;
        unbound.cwd = Some(work.path().display().to_string());
        let error = run_provider(&unbound, work.path(), budgets(1_000, 1024), true)
            .expect_err("placeholder");
        assert!(error.to_string().contains("unbound placeholder"));
        assert!(!error.to_string().contains("could not be started"));

        let missing = helper_invocation(Path::new("aros-provider-missing-bin"), work.path(), &[]);
        let error =
            run_provider(&missing, work.path(), budgets(1_000, 1024), true).expect_err("missing");
        assert!(error.to_string().contains("could not be started"));

        let error = run_provider(&missing, work.path(), budgets(0, 1024), true).expect_err("wall");
        assert!(error.to_string().contains("wall_clock_ms"));
        let error =
            run_provider(&missing, work.path(), budgets(1_000, 0), true).expect_err("bytes");
        assert!(error.to_string().contains("max_output_bytes"));

        invocation.executable = "aros-provider-missing-bin".into();
        invocation.argv.clear();
        invocation.cwd = Some(work.path().join("missing-cwd").display().to_string());
        let error =
            run_provider(&invocation, work.path(), budgets(1_000, 1024), false).expect_err("cwd");
        assert!(error.to_string().contains("cwd does not match"));
    }

    #[test]
    fn waived_host_run_caps_output_time_and_env_and_unwaived_fails_closed() {
        let work = tempfile::tempdir().expect("work");
        let exe = compile_helper(work.path());
        let line = helper_invocation(&exe, work.path(), &[]);
        let started = Instant::now();
        let output = run_provider(&line, work.path(), budgets(5_000, 4096), true).expect("line");
        assert!(started.elapsed() < Duration::from_secs(5));
        assert_eq!(output.execution, ProviderExecutionKind::WaivedHost);
        assert!(!output.memory_limit_applied);
        assert!(!output.read_only_enforced);
        assert!(output.host_network_inherited);
        assert_eq!(output.memory_mb_requested, 64);
        assert_eq!(
            String::from_utf8_lossy(&output.stdout).trim(),
            "provider-bytes"
        );
        assert!(!output.output_truncated);
        assert!(!output.output_killed_at_cap);
        let json = serde_json::to_string(&output).expect("json");
        assert!(!json.contains("\"evidence_level\""));
        assert!(!json.contains("\"verified\""));
        assert!(!json.contains("\"finding\""));

        let flood = helper_invocation(&exe, work.path(), &["flood"]);
        let started = Instant::now();
        let output = run_provider(&flood, work.path(), budgets(5_000, 2048), true).expect("flood");
        assert!(started.elapsed() < Duration::from_secs(5));
        assert!(output.output_truncated);
        assert!(output.output_killed_at_cap);
        assert!(output.stdout.len() + output.stderr.len() <= 2048);
        assert!(!output.stdout.is_empty());
        assert_eq!(output.execution, ProviderExecutionKind::WaivedHost);

        let sleep = helper_invocation(&exe, work.path(), &["sleep"]);
        let started = Instant::now();
        let error = run_provider(&sleep, work.path(), budgets(400, 1024), true).expect_err("sleep");
        assert!(started.elapsed() < Duration::from_secs(5));
        assert!(error.to_string().contains("exceeded wall_clock_ms"));

        let env = helper_invocation(&exe, work.path(), &["env"]);
        let output = run_provider(&env, work.path(), budgets(5_000, 4096), true).expect("env");
        let text = String::from_utf8_lossy(&output.stdout);
        assert!(text.contains("env-scrubbed"));
        assert!(!text.contains("leaked:"));

        let error =
            run_provider(&line, work.path(), budgets(5_000, 4096), false).expect_err("unwaived");
        let message = error.to_string();
        assert!(
            containment_failure(&message),
            "unexpected containment error: {message}"
        );
        assert!(!message.contains("provider-bytes"));
    }
}
