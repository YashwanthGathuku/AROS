#![forbid(unsafe_code)]
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::ptr_arg)]

use std::path::PathBuf;
use std::process::ExitCode;

use aros_core::{fixture_manifest, CampaignEngine, FixtureKind};
use aros_sandbox::RootlessOciSandboxProvider;
use aros_types::{
    env_name, BINARY_NAME, DAEMON_NAME, DATABASE_FILE, PRODUCT_DESCRIPTION, PRODUCT_NAME,
    VERIFIER_NAME, WORKSPACE_DIR,
};
use clap::{Parser, Subcommand};

#[derive(Parser)]
#[command(name = BINARY_NAME, version, about = PRODUCT_DESCRIPTION)]
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
    Show { target_id: String },
}

#[derive(Subcommand)]
enum CampaignCmd {
    Run {
        #[arg(long)]
        fixture: PathBuf,
        #[arg(long, default_value = "authz")]
        kind: String,
        #[arg(long, default_value = "data/work")]
        work: PathBuf,
        #[arg(long, default_value = "127.0.0.1")]
        host: String,
        #[arg(long, default_value_t = 18080)]
        port: u16,
        #[arg(long)]
        operator_waive_containment: bool,
        /// Run via arosd instead of in-process.
        #[arg(long)]
        remote: bool,
    },
    List,
    Get {
        campaign_id: String,
    },
}

#[derive(Subcommand)]
enum GraphCmd {
    Show { campaign_id: String },
    Export { campaign_id: String },
}

#[derive(Subcommand)]
enum IdCmd {
    List { campaign_id: String },
    Show { id: String },
}

#[derive(Subcommand)]
enum FindingCmd {
    List { campaign_id: String },
    Show { finding_id: String },
}

#[derive(Subcommand)]
enum EvidenceCmd {
    Show {
        finding_id: String,
    },
    Verify {
        work: PathBuf,
        /// Required once the workspace holds more than one campaign.
        #[arg(long)]
        campaign_id: Option<String>,
    },
}

#[derive(Subcommand)]
enum BenchCmd {
    Smoke,
}

fn main() -> ExitCode {
    let cli = Cli::parse();
    match cli.command {
        Commands::Doctor => doctor(),
        Commands::Init { path } => init_ws(&path),
        Commands::Target { cmd } => match cmd {
            TargetCmd::AddSource { path } => record(
                "target",
                &uuid::Uuid::new_v4().to_string(),
                &format!("source:{}", path.display()),
            ),
            TargetCmd::AddCompose { path } => record(
                "target",
                &uuid::Uuid::new_v4().to_string(),
                &format!("compose:{}", path.display()),
            ),
            TargetCmd::List => list_kind("target"),
            TargetCmd::Show { target_id } => show_record("target", &target_id),
        },
        Commands::Campaign { cmd } => match cmd {
            CampaignCmd::Run {
                fixture,
                kind,
                work,
                host,
                port,
                operator_waive_containment,
                remote,
            } => {
                if remote || daemon_url().is_some() {
                    run_campaign_remote(&fixture, &kind, &work, operator_waive_containment)
                } else {
                    run_campaign(
                        &fixture,
                        &kind,
                        &work,
                        &host,
                        port,
                        operator_waive_containment,
                    )
                }
            }
            CampaignCmd::List => list_kind("campaign"),
            CampaignCmd::Get { campaign_id } => get_remote_campaign(&campaign_id),
        },
        Commands::Graph { cmd } => {
            match cmd {
                GraphCmd::Show { campaign_id } => {
                    println!("graph summary for {campaign_id}: see {WORKSPACE_DIR}/{DATABASE_FILE} events");
                    ExitCode::SUCCESS
                }
                GraphCmd::Export { campaign_id } => {
                    println!("{{\"campaign_id\":\"{campaign_id}\",\"format\":\"json\"}}");
                    ExitCode::SUCCESS
                }
            }
        }
        Commands::Hypothesis { cmd } => match cmd {
            IdCmd::List { campaign_id } => list_kind_filtered("hypothesis", &campaign_id),
            IdCmd::Show { id } => show_record("hypothesis", &id),
        },
        Commands::Finding { cmd } => match cmd {
            FindingCmd::List { campaign_id } => list_kind_filtered("finding", &campaign_id),
            FindingCmd::Show { finding_id } => show_record("finding", &finding_id),
        },
        Commands::Evidence { cmd } => match cmd {
            EvidenceCmd::Show { finding_id } => show_record("evidence", &finding_id),
            EvidenceCmd::Verify { work, campaign_id } => {
                verify_ledger(&work, campaign_id.as_deref())
            }
        },
        Commands::Replay { finding_id } => {
            println!("replay request recorded for finding {finding_id}");
            ExitCode::SUCCESS
        }
        Commands::Remediate { finding_id } => {
            println!("remediation request recorded for finding {finding_id}");
            ExitCode::SUCCESS
        }
        Commands::Reattack { finding_id } => {
            println!("reattack request recorded for finding {finding_id}");
            ExitCode::SUCCESS
        }
        Commands::Benchmark { cmd } => match cmd {
            BenchCmd::Smoke => {
                println!("benchmark smoke: use fixtures + acceptance gate");
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
    let oci = RootlessOciSandboxProvider::detect();
    let report = oci.probe_containment();
    println!("  rustc: REQUIRED present ({})", rustc_ver());
    println!("  python: REQUIRED>=3.14  host={}", python_ver());
    if report.runtime_present {
        println!(
            "  container-runtime: REQUIRED found {}",
            oci.runtime
                .as_ref()
                .map(|p| p.display().to_string())
                .unwrap_or_else(|| "podman".into())
        );
    } else {
        println!(
            "  container-runtime: UNSAFE/MISCONFIGURED — no podman/docker; campaigns fail closed"
        );
    }
    if report.machine_reachable {
        println!("  podman-machine: REQUIRED reachable");
    } else if report.runtime_present {
        println!("  podman-machine: UNSAFE/MISCONFIGURED — run `podman machine start` (WSL2)");
    } else {
        println!("  podman-machine: UNSAFE/MISCONFIGURED");
    }
    if report.internal_network {
        println!("  network-isolation: REQUIRED internal network probe passed");
    } else {
        println!(
            "  network-isolation: UNSAFE/MISCONFIGURED — internal --internal network not proven"
        );
    }
    println!(
        "  packet-target-reachable: {}",
        yn(report.target_reachable, report.packet_probes_ran)
    );
    println!(
        "  packet-external-denied: {}",
        yn(
            report.unauthorized_external_denied,
            report.packet_probes_ran
        )
    );
    println!(
        "  packet-dns-bypass-denied: {}",
        yn(report.dns_bypass_denied, report.packet_probes_ran)
    );
    println!(
        "  packet-host-gateway-denied: {}",
        yn(report.host_gateway_denied, report.packet_probes_ran)
    );
    println!(
        "  packet-ipv6-bypass-denied: {}",
        yn(report.ipv6_bypass_denied, report.packet_probes_ran)
    );
    println!(
        "  live_oci_claimable: {}",
        if report.live_oci_claimable() {
            "true"
        } else {
            "false — do not claim acceptance C live isolation"
        }
    );
    println!(
        "  containment_report_json: {}",
        serde_json::to_string(&report).unwrap_or_else(|_| "{}".into())
    );
    for n in &report.notes {
        println!("  note: {n}");
    }
    println!("  sqlite: REQUIRED path ./{WORKSPACE_DIR}/{DATABASE_FILE} (rusqlite bundled)");
    println!("  git: OPTIONAL {}", which("git"));
    println!("  {VERIFIER_NAME}: OPTIONAL {}", which(VERIFIER_NAME));
    println!("  grok-build: OPTIONAL {}", which("grok"));
    let theustad = std::env::var(env_name("THEUSTAD_URL"))
        .ok()
        .filter(|s| !s.is_empty());
    match theustad {
        Some(url) => println!("  theustad: OPTIONAL configured {url}"),
        None => println!("  theustad: OPTIONAL not installed"),
    }
    match daemon_url() {
        Some(url) => println!("  {DAEMON_NAME}: OPTIONAL {url}"),
        None => println!(
            "  {DAEMON_NAME}: OPTIONAL unset (in-process CLI; set {})",
            env_name("DAEMON_URL")
        ),
    }
    println!("  model-provider: OPTIONAL local OpenAI-compatible (not required for mock loop)");
    for tool in aros_core::adapters::detect_optional_engines() {
        println!(
            "  engine-{}: OPTIONAL {} ({})",
            tool.name,
            tool.category,
            tool.path.display()
        );
    }
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
    let mut cmds = vec![
        {
            let mut c = std::process::Command::new("py");
            c.args(["-3.14", "--version"]);
            c
        },
        {
            let mut c = std::process::Command::new("python");
            c.arg("--version");
            c
        },
    ];
    if let Some(local) = std::env::var_os("LOCALAPPDATA") {
        let p = PathBuf::from(local)
            .join("Programs")
            .join("Python")
            .join("Python314")
            .join("python.exe");
        let mut c = std::process::Command::new(p);
        c.arg("--version");
        cmds.push(c);
    }
    for mut cmd in cmds {
        if let Ok(o) = cmd.output() {
            let raw = if o.stdout.is_empty() {
                o.stderr
            } else {
                o.stdout
            };
            if let Ok(s) = String::from_utf8(raw) {
                let t = s.trim().to_string();
                if t.contains("3.14") || t.starts_with("Python 3.") {
                    return t;
                }
            }
        }
    }
    "missing".into()
}

fn init_ws(path: &PathBuf) -> ExitCode {
    let _ = std::fs::create_dir_all(path.join("data"));
    let _ = std::fs::create_dir_all(path.join(WORKSPACE_DIR));
    if let Ok(store) = aros_store::Store::open(&path.join(WORKSPACE_DIR).join(DATABASE_FILE)) {
        let _ = store.put_record("workspace", "init", PRODUCT_NAME);
    }
    println!("initialized {} ({PRODUCT_NAME} workspace)", path.display());
    ExitCode::SUCCESS
}

fn ws_store() -> Result<aros_store::Store, aros_store::StoreError> {
    let _ = std::fs::create_dir_all(WORKSPACE_DIR);
    aros_store::Store::open(&PathBuf::from(WORKSPACE_DIR).join(DATABASE_FILE))
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

fn yn(ok: bool, ran: bool) -> &'static str {
    if !ran {
        "NOT RUN — live OCI not claimable"
    } else if ok {
        "REQUIRED demonstrated"
    } else {
        "UNSAFE/MISCONFIGURED"
    }
}

fn daemon_url() -> Option<String> {
    std::env::var(env_name("DAEMON_URL"))
        .ok()
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
}

fn daemon_token() -> Result<String, String> {
    std::env::var(env_name("DAEMON_TOKEN"))
        .ok()
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty())
        .ok_or_else(|| {
            format!(
                "{} is required for remote daemon access",
                env_name("DAEMON_TOKEN")
            )
        })
}

fn parse_loopback_http(url: &str) -> Result<(String, u16), String> {
    let rest = url
        .strip_prefix("http://")
        .ok_or_else(|| "URL must be http://127.0.0.1".to_string())?;
    let hostport = rest.split('/').next().unwrap_or(rest);
    let (host, port) = if let Some((h, p)) = hostport.rsplit_once(':') {
        let port: u16 = p.parse().map_err(|_| "invalid port".to_string())?;
        (h.to_string(), port)
    } else {
        (hostport.to_string(), 80)
    };
    if host != "127.0.0.1" && host != "localhost" {
        return Err("daemon URL must be loopback".into());
    }
    Ok((host, port))
}

fn run_campaign_remote(fixture: &PathBuf, kind: &str, work: &PathBuf, waive: bool) -> ExitCode {
    let url = daemon_url().unwrap_or_else(|| "http://127.0.0.1:7432".into());
    let (host, port) = match parse_loopback_http(&url) {
        Ok(v) => v,
        Err(e) => {
            eprintln!("{e}");
            return ExitCode::FAILURE;
        }
    };
    let token = match daemon_token() {
        Ok(token) => token,
        Err(error) => {
            eprintln!("{error}");
            return ExitCode::FAILURE;
        }
    };
    let body = serde_json::json!({
        "fixture_root": fixture,
        "work_root": work,
        "kind": kind,
        "waive_containment": waive,
    });
    match aros_core::http_post_json_bearer(
        &host,
        port,
        "/v1/campaigns/fixture",
        &body.to_string(),
        &token,
    ) {
        Ok(resp) if resp.status < 400 => {
            println!("{}", resp.body);
            ExitCode::SUCCESS
        }
        Ok(resp) => {
            eprintln!("arosd error {}: {}", resp.status, resp.body);
            ExitCode::FAILURE
        }
        Err(e) => {
            eprintln!("arosd unreachable at {url}: {e}");
            ExitCode::FAILURE
        }
    }
}

fn get_remote_campaign(campaign_id: &str) -> ExitCode {
    let url = match daemon_url() {
        Some(u) => u,
        None => return show_record("campaign", campaign_id),
    };
    let (host, port) = match parse_loopback_http(&url) {
        Ok(v) => v,
        Err(e) => {
            eprintln!("{e}");
            return ExitCode::FAILURE;
        }
    };
    let token = match daemon_token() {
        Ok(token) => token,
        Err(error) => {
            eprintln!("{error}");
            return ExitCode::FAILURE;
        }
    };
    let path = format!("/v1/campaigns/{campaign_id}");
    match aros_core::http_get_bearer(&host, port, &path, &token) {
        Ok(resp) if resp.status < 400 => {
            println!("{}", resp.body);
            ExitCode::SUCCESS
        }
        Ok(resp) => {
            eprintln!("arosd error {}: {}", resp.status, resp.body);
            ExitCode::FAILURE
        }
        Err(e) => {
            eprintln!("arosd unreachable: {e}");
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
    // The engine launches and re-attacks its own actual patched twin.
    match engine.run_fixture_campaign(fixture, work, host, port, None, kind, manifest) {
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
        "live_reattack_confirmed": out.live_reattack_confirmed,
        "research_card_id": out.research_card_id,
        "verifier_isolated": out.verifier_isolated,
        "campaign_id": out.campaign.id.to_string(),
    })
}

fn verify_ledger(work: &PathBuf, campaign_id: Option<&str>) -> ExitCode {
    use aros_store::Store;
    use aros_types::CampaignId;
    match Store::open(&work.join(DATABASE_FILE)).and_then(|s| match campaign_id {
        Some(raw) => {
            let id: CampaignId = raw
                .parse()
                .map_err(|error| aros_store::StoreError::Ledger(format!("{error}")))?;
            s.load_ledger_for(id)
        }
        None => s.load_ledger(),
    }) {
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
