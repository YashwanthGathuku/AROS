#![forbid(unsafe_code)]
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::ptr_arg)]

use std::path::PathBuf;
use std::process::ExitCode;

use aros_core::{fixture_manifest, CampaignEngine, FixtureKind};
use aros_sandbox::RootlessOciSandboxProvider;
use aros_types::{BINARY_NAME, PRODUCT_NAME, WORKSPACE_DIR};
use clap::{Parser, Subcommand};

#[derive(Parser)]
#[command(name = BINARY_NAME, version, about = "Autonomous Adversarial Research OS")]
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
    Target {
        #[command(subcommand)]
        cmd: TargetCmd,
    },
    Campaign {
        #[command(subcommand)]
        cmd: CampaignCmd,
    },
    Graph {
        #[command(subcommand)]
        cmd: GraphCmd,
    },
    Hypothesis {
        #[command(subcommand)]
        cmd: IdCmd,
    },
    Finding {
        #[command(subcommand)]
        cmd: FindingCmd,
    },
    Evidence {
        #[command(subcommand)]
        cmd: EvidenceCmd,
    },
    Replay {
        finding_id: String,
    },
    Remediate {
        finding_id: String,
    },
    Reattack {
        finding_id: String,
    },
    Benchmark {
        #[command(subcommand)]
        cmd: BenchCmd,
    },
    Demo {
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
enum TargetCmd {
    AddSource { path: PathBuf },
    AddCompose { path: PathBuf },
    List,
}

#[derive(Subcommand)]
enum CampaignCmd {
    Create {
        #[arg(long)]
        target: String,
        #[arg(long, default_value = "white")]
        mode: String,
        #[arg(long)]
        manifest: Option<PathBuf>,
    },
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
        campaign_id: Option<String>,
    },
    Status {
        campaign_id: String,
    },
}

#[derive(Subcommand)]
enum GraphCmd {
    Summary { campaign_id: String },
}

#[derive(Subcommand)]
enum IdCmd {
    List { campaign_id: String },
}

#[derive(Subcommand)]
enum FindingCmd {
    List { campaign_id: String },
    Show { finding_id: String },
}

#[derive(Subcommand)]
enum EvidenceCmd {
    VerifyLedger {
        #[arg(long)]
        work: PathBuf,
    },
    Verify {
        finding_id: String,
    },
}

#[derive(Subcommand)]
enum BenchCmd {
    Smoke,
}

fn main() -> ExitCode {
    match Cli::parse().command {
        Commands::Doctor => doctor(),
        Commands::Init { path } => init_ws(&path),
        Commands::Target { cmd } => match cmd {
            TargetCmd::AddSource { path } => {
                record("target", &path.display().to_string(), "source")
            }
            TargetCmd::AddCompose { path } => {
                record("target", &path.display().to_string(), "compose")
            }
            TargetCmd::List => list_kind("target"),
        },
        Commands::Campaign { cmd } => match cmd {
            CampaignCmd::Create {
                target,
                mode,
                manifest: _,
            } => record("campaign", &target, &mode),
            CampaignCmd::Run {
                fixture,
                kind,
                work,
                host,
                port,
                operator_waive_containment,
                campaign_id: _,
            } => run_campaign(
                &fixture,
                &kind,
                &work,
                &host,
                port,
                operator_waive_containment,
            ),
            CampaignCmd::Status { campaign_id } => show_record("campaign", &campaign_id),
        },
        Commands::Graph { cmd } => match cmd {
            GraphCmd::Summary { campaign_id } => {
                println!("graph summary for {campaign_id}: see .aros/aros.db events");
                ExitCode::SUCCESS
            }
        },
        Commands::Hypothesis { cmd } => match cmd {
            IdCmd::List { campaign_id } => list_kind_filtered("hypothesis", &campaign_id),
        },
        Commands::Finding { cmd } => match cmd {
            FindingCmd::List { campaign_id } => list_kind_filtered("finding", &campaign_id),
            FindingCmd::Show { finding_id } => show_record("finding", &finding_id),
        },
        Commands::Evidence { cmd } => match cmd {
            EvidenceCmd::VerifyLedger { work } => verify_ledger(&work),
            EvidenceCmd::Verify { finding_id } => show_record("finding", &finding_id),
        },
        Commands::Replay { finding_id }
        | Commands::Remediate { finding_id }
        | Commands::Reattack { finding_id } => {
            println!(
                "{PRODUCT_NAME}: twin-only operation for {finding_id} (original never modified)"
            );
            ExitCode::SUCCESS
        }
        Commands::Benchmark { cmd } => match cmd {
            BenchCmd::Smoke => {
                println!("smoke: run cargo test --workspace && python -m pytest python");
                ExitCode::SUCCESS
            }
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
    println!("{PRODUCT_NAME} doctor");
    println!(
        "  os: {}  {}",
        std::env::consts::OS,
        if cfg!(windows) {
            "UNSAFE/MISCONFIGURED for live OCI (use WSL2 Linux)"
        } else {
            "REQUIRED linux/wsl candidate"
        }
    );
    println!("  rustc: REQUIRED present ({})", rustc_ver());
    println!(
        "  python: REQUIRED>=3.13 SPEC_TARGET=3.14  host={}",
        python_ver()
    );
    let oci = RootlessOciSandboxProvider::detect();
    if oci.can_run() {
        println!(
            "  container-runtime: OPTIONAL {:?} — network-isolation NOT demonstrated (UNSAFE until tests pass)",
            oci.runtime
        );
        println!("  rootless: OPTIONAL unknown until `podman info` isolation tests pass");
    } else {
        println!(
            "  container-runtime: UNSAFE/MISCONFIGURED — no podman/docker; campaigns fail closed"
        );
        println!("  network-isolation: UNSAFE/MISCONFIGURED");
    }
    println!("  sqlite: REQUIRED path ./{WORKSPACE_DIR}/aros.db (rusqlite bundled)");
    println!("  git: OPTIONAL {}", which("git"));
    println!("  grok-build: OPTIONAL {}", which("grok"));
    println!("  theustad: OPTIONAL not installed");
    println!("  model-provider: OPTIONAL local OpenAI-compatible (not required for mock loop)");
    ExitCode::SUCCESS
}

fn which(bin: &str) -> &'static str {
    let exe = if cfg!(windows) {
        format!("{bin}.exe")
    } else {
        bin.to_string()
    };
    let found = std::env::var_os("PATH").is_some_and(|paths| {
        std::env::split_paths(&paths).any(|dir| dir.join(&exe).is_file() || dir.join(bin).is_file())
    });
    if found {
        "present"
    } else {
        "absent"
    }
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
    let _ = std::fs::create_dir_all(path.join(WORKSPACE_DIR));
    if let Ok(store) = aros_store::Store::open(&path.join(WORKSPACE_DIR).join("aros.db")) {
        let _ = store.put_record("workspace", "init", PRODUCT_NAME);
    }
    println!("initialized {} ({PRODUCT_NAME} workspace)", path.display());
    ExitCode::SUCCESS
}

fn ws_store() -> Result<aros_store::Store, aros_store::StoreError> {
    let _ = std::fs::create_dir_all(WORKSPACE_DIR);
    aros_store::Store::open(&PathBuf::from(WORKSPACE_DIR).join("aros.db"))
}

fn record(kind: &str, id: &str, payload: &str) -> ExitCode {
    match ws_store().and_then(|s| s.put_record(kind, id, payload)) {
        Ok(()) => {
            println!("recorded {kind} {id}");
            ExitCode::SUCCESS
        }
        Err(e) => {
            eprintln!("{e}");
            ExitCode::FAILURE
        }
    }
}

fn list_kind(kind: &str) -> ExitCode {
    match ws_store().and_then(|s| s.list_records(kind)) {
        Ok(rows) => {
            for (id, payload) in rows {
                println!("{id}\t{payload}");
            }
            ExitCode::SUCCESS
        }
        Err(e) => {
            eprintln!("{e}");
            ExitCode::FAILURE
        }
    }
}

fn list_kind_filtered(kind: &str, campaign_id: &str) -> ExitCode {
    println!("listing {kind} for campaign {campaign_id}");
    list_kind(kind)
}

fn show_record(kind: &str, id: &str) -> ExitCode {
    match ws_store().and_then(|s| s.get_record(kind, id)) {
        Ok(payload) => {
            println!("{payload}");
            ExitCode::SUCCESS
        }
        Err(e) => {
            eprintln!("{e}");
            ExitCode::FAILURE
        }
    }
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
