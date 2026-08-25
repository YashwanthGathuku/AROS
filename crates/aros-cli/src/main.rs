#![forbid(unsafe_code)]
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::ptr_arg)]

use std::path::PathBuf;
use std::process::ExitCode;

use aros_core::{fixture_manifest, CampaignEngine, FixtureKind};
use aros_sandbox::RootlessOciSandboxProvider;
use clap::{Parser, Subcommand};

#[derive(Parser)]
#[command(name = "aros", version, about = "Autonomous Adversarial Research OS")]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Check local environment (REQUIRED / OPTIONAL / UNSAFE)
    Doctor,
    /// Initialize a local AROS workspace directory
    Init {
        #[arg(default_value = ".")]
        path: PathBuf,
    },
    /// Run a repository fixture campaign with the deterministic mock researcher
    Campaign {
        #[command(subcommand)]
        cmd: CampaignCmd,
    },
    /// Evidence operations
    Evidence {
        #[command(subcommand)]
        cmd: EvidenceCmd,
    },
    /// Run the local fixture demo
    Demo {
        /// Explicit operator waiver: run the research loop without demonstrated OCI containment.
        #[arg(long)]
        operator_waive_containment: bool,
        #[arg(long, default_value = "authz")]
        fixture: String,
        #[arg(long, default_value = "127.0.0.1")]
        host: String,
        #[arg(long, default_value_t = 18080)]
        port: u16,
    },
}

#[derive(Subcommand)]
enum CampaignCmd {
    Run {
        #[arg(long)]
        fixture: PathBuf,
        #[arg(long, default_value = "authz")]
        kind: String,
        #[arg(long)]
        work: PathBuf,
        #[arg(long, default_value = "127.0.0.1")]
        host: String,
        #[arg(long, default_value_t = 18080)]
        port: u16,
        #[arg(long)]
        operator_waive_containment: bool,
    },
}

#[derive(Subcommand)]
enum EvidenceCmd {
    /// Verify the hash-chained event ledger in a work directory
    VerifyLedger {
        #[arg(long)]
        work: PathBuf,
    },
}

fn main() -> ExitCode {
    match Cli::parse().command {
        Commands::Doctor => doctor(),
        Commands::Init { path } => init_ws(&path),
        Commands::Campaign { cmd } => match cmd {
            CampaignCmd::Run {
                fixture,
                kind,
                work,
                host,
                port,
                operator_waive_containment,
            } => run_campaign(
                &fixture,
                &kind,
                &work,
                &host,
                port,
                operator_waive_containment,
            ),
        },
        Commands::Evidence { cmd } => match cmd {
            EvidenceCmd::VerifyLedger { work } => verify_ledger(&work),
        },
        Commands::Demo {
            operator_waive_containment,
            fixture,
            host,
            port,
        } => demo(&fixture, &host, port, operator_waive_containment),
    }
}

fn doctor() -> ExitCode {
    println!("AROS doctor");
    println!("  rustc: REQUIRED present ({})", rustc_ver());
    println!(
        "  python: REQUIRED>=3.13 SPEC_TARGET=3.14  host={}",
        python_ver()
    );
    let oci = RootlessOciSandboxProvider::detect();
    if oci.can_run() {
        println!(
            "  oci: OPTIONAL runtime {:?} — containment NOT demonstrated (UNSAFE until tests pass)",
            oci.runtime
        );
    } else {
        println!("  oci: UNSAFE/MISCONFIGURED — no podman/docker; campaigns fail closed");
    }
    println!("  sqlite: REQUIRED (rusqlite bundled)");
    println!("  grok-build: OPTIONAL (capability-detected harness)");
    println!("  theustad: OPTIONAL (adapter present, not required)");
    ExitCode::SUCCESS
}

fn rustc_ver() -> String {
    std::process::Command::new("rustc")
        .arg("--version")
        .output()
        .ok()
        .and_then(|o| String::from_utf8(o.stdout).ok())
        .unwrap_or_else(|| "unknown".into())
        .trim()
        .to_string()
}

fn python_ver() -> String {
    std::process::Command::new("python")
        .arg("--version")
        .output()
        .ok()
        .and_then(|o| String::from_utf8(o.stdout).ok())
        .unwrap_or_else(|| "missing".into())
        .trim()
        .to_string()
}

fn init_ws(path: &PathBuf) -> ExitCode {
    let _ = std::fs::create_dir_all(path.join("data"));
    println!("initialized {}", path.display());
    ExitCode::SUCCESS
}

fn parse_kind(s: &str) -> Option<FixtureKind> {
    match s {
        "authz" => Some(FixtureKind::Authz),
        "path" => Some(FixtureKind::Path),
        "deceptive" => Some(FixtureKind::Deceptive),
        _ => None,
    }
}

fn run_campaign(
    fixture: &PathBuf,
    kind: &str,
    work: &PathBuf,
    host: &str,
    port: u16,
    waive: bool,
) -> ExitCode {
    let Some(kind) = parse_kind(kind) else {
        eprintln!("unknown fixture kind");
        return ExitCode::FAILURE;
    };
    let engine = CampaignEngine::new(waive);
    let manifest = fixture_manifest(&fixture.to_string_lossy(), host, port, true);
    match engine.run_fixture_campaign(fixture, work, host, port, kind, manifest) {
        Ok(out) => {
            println!("{}", serde_json::to_string_pretty(&json_out(&out)).unwrap());
            ExitCode::SUCCESS
        }
        Err(e) => {
            eprintln!("campaign failed: {e}");
            ExitCode::FAILURE
        }
    }
}

fn json_out(out: &aros_core::CampaignOutcome) -> serde_json::Value {
    serde_json::json!({
        "state": format!("{:?}", out.campaign.state),
        "original_digest": out.original_digest,
        "original_digest_after": out.original_digest_after,
        "original_unmodified": out.original_digest == out.original_digest_after,
        "deceptive_rejected": out.deceptive_rejected,
        "verified": out.finding.as_ref().map(|f| f.verified),
        "evidence_level": format!("{:?}", out.evidence_level),
    })
}

fn verify_ledger(work: &PathBuf) -> ExitCode {
    use aros_store::Store;
    match Store::open(&work.join("aros.db")).and_then(|s| s.load_ledger()) {
        Ok(ledger) => match ledger.verify() {
            Ok(()) => {
                println!("ledger ok ({} events)", ledger.len());
                ExitCode::SUCCESS
            }
            Err(e) => {
                eprintln!("ledger verify failed: {e}");
                ExitCode::FAILURE
            }
        },
        Err(e) => {
            eprintln!("ledger load failed: {e}");
            ExitCode::FAILURE
        }
    }
}

fn demo(kind: &str, host: &str, port: u16, waive: bool) -> ExitCode {
    let root = match kind {
        "deceptive" => PathBuf::from("fixtures/deceptive"),
        other => PathBuf::from(format!("fixtures/vulnerable/{other}")),
    };
    let work = PathBuf::from("data/demo-work");
    let _ = std::fs::remove_dir_all(&work);
    run_campaign(&root, kind, &work, host, port, waive)
}
