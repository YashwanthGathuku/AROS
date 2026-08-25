#![forbid(unsafe_code)]
#![allow(clippy::expect_used, clippy::unwrap_used)]

use std::str::FromStr;
use std::sync::Arc;

use axum::{extract::State, routing::get, Json, Router};
use ipnet::IpNet;
use serde::Serialize;
use tokio::sync::Mutex;

use aros_ipc::messages::{envelope, Envelope, IntentResult, PROTOCOL_VERSION};
use aros_ipc::WorkerSupervisor;
use aros_policy::{evaluate, SandboxIdentity};
use aros_types::{
    AllowedEndpoint, AuthorizationManifest, CampaignId, PolicyDecision, ProtocolKind, SandboxId,
    TargetId, ToolCapability, ToolIntent, DAEMON_NAME, PRODUCT_NAME,
};

#[derive(Serialize)]
struct Health {
    service: &'static str,
    product: &'static str,
    version: &'static str,
    python_embedded: bool,
    worker_alive: bool,
    ipc: String,
    intents_handled: u64,
}

struct AppState {
    supervisor: Mutex<WorkerSupervisor>,
    intents_handled: Mutex<u64>,
}

/// Lab / bootstrap manifest used until a full campaign is attached.
/// Default-deny: only capabilities and roots the operator explicitly opens.
fn lab_manifest() -> AuthorizationManifest {
    let root = std::env::var("AROS_LAB_ROOT").unwrap_or_else(|_| {
        std::env::current_dir()
            .map(|p| p.to_string_lossy().into_owned())
            .unwrap_or_else(|_| ".".into())
    });
    let mut m = AuthorizationManifest::default_deny_local(
        CampaignId::new(),
        TargetId::new(),
        root,
    );
    // Daemon lab path: operator may waive containment via env for local unit work.
    // Production campaigns must set require_containment=true and prove it.
    m.require_containment = std::env::var("AROS_REQUIRE_CONTAINMENT")
        .map(|v| v == "1" || v.eq_ignore_ascii_case("true"))
        .unwrap_or(false);
    m.tool_allowlist.insert(ToolCapability::ListTree);
    m.tool_allowlist.insert(ToolCapability::ReadFile);
    m.tool_allowlist.insert(ToolCapability::SearchText);
    m.tool_allowlist.insert(ToolCapability::GitInspect);
    m.tool_allowlist.insert(ToolCapability::HttpRequest);
    if let Ok(cidr) = IpNet::from_str("127.0.0.1/32") {
        m.allowed_endpoints.push(AllowedEndpoint {
            cidr,
            ports: (1..=65535).collect(),
            protocols: [ProtocolKind::Http, ProtocolKind::Tcp]
                .into_iter()
                .collect(),
        });
    }
    m.allowed_service_names.insert("localhost".into());
    m.allowed_service_names.insert("127.0.0.1".into());
    m
}

fn capability_from_str(s: &str) -> Option<ToolCapability> {
    match s {
        "read_file" => Some(ToolCapability::ReadFile),
        "list_tree" => Some(ToolCapability::ListTree),
        "search_text" => Some(ToolCapability::SearchText),
        "git_inspect" => Some(ToolCapability::GitInspect),
        "run_tests" => Some(ToolCapability::RunTests),
        "run_language_tool" => Some(ToolCapability::RunLanguageTool),
        "http_request" => Some(ToolCapability::HttpRequest),
        "browser_request" => Some(ToolCapability::BrowserRequest),
        "execute_allowlisted_binary" => Some(ToolCapability::ExecuteAllowlistedBinary),
        "collect_logs" => Some(ToolCapability::CollectLogs),
        "collect_file" => Some(ToolCapability::CollectFile),
        "collect_process_state" => Some(ToolCapability::CollectProcessState),
        "fuzz_adapter" => Some(ToolCapability::FuzzAdapter),
        "sanitizer_adapter" => Some(ToolCapability::SanitizerAdapter),
        "static_analysis_adapter" => Some(ToolCapability::StaticAnalysisAdapter),
        _ => None,
    }
}

fn intent_from_msg(msg: &aros_ipc::messages::ToolIntentMsg) -> Result<ToolIntent, String> {
    let capability = capability_from_str(&msg.capability)
        .ok_or_else(|| format!("unknown capability {:?}", msg.capability))?;
    let mut intent = ToolIntent::new(capability);
    intent.argv = msg.argv.clone();
    intent.cwd = msg.cwd.clone();
    intent.path = msg.path.clone();
    intent.timeout_ms = if msg.timeout_ms == 0 {
        30_000
    } else {
        msg.timeout_ms
    };
    if let (Some(host), Some(port)) = (&msg.host, msg.port) {
        let protocol = match msg.protocol.as_deref() {
            Some("tcp") => ProtocolKind::Tcp,
            Some("udp") => ProtocolKind::Udp,
            _ => ProtocolKind::Http,
        };
        let port_u16 = u16::try_from(port).map_err(|_| "port out of range".to_string())?;
        intent.network = Some(aros_types::NetworkIntent {
            host: host.clone(),
            port: port_u16,
            protocol,
        });
    }
    Ok(intent)
}

fn decision_str(d: PolicyDecision) -> &'static str {
    match d {
        PolicyDecision::Allow => "ALLOW",
        PolicyDecision::Deny => "DENY",
        PolicyDecision::RequiresHuman => "REQUIRES_HUMAN",
    }
}

async fn handle_worker_intents(state: Arc<AppState>) {
    let manifest = lab_manifest();
    let sandbox = SandboxIdentity {
        id: SandboxId::new(),
        // Lab path: containment_demonstrated tracks whether require_containment was waived.
        containment_demonstrated: !manifest.require_containment,
    };

    loop {
        let env = {
            let mut sup = state.supervisor.lock().await;
            match sup.read_next().await {
                Ok(e) => e,
                Err(e) => {
                    tracing::warn!(error = %e, "worker stream ended or read failed");
                    break;
                }
            }
        };

        match env.kind {
            Some(envelope::Kind::ToolIntent(msg)) => {
                let request_id = env.request_id.clone();
                let result = match intent_from_msg(&msg) {
                    Ok(intent) => {
                        let verdict = evaluate(&manifest, None, &sandbox, &intent);
                        tracing::info!(
                            capability = %msg.capability,
                            decision = %decision_str(verdict.decision),
                            reason = %verdict.reason,
                            "policy decision on worker ToolIntent"
                        );
                        IntentResult {
                            decision: decision_str(verdict.decision).into(),
                            reason: verdict.reason,
                            exit_status: None,
                            stdout_digest: None,
                        }
                    }
                    Err(reason) => IntentResult {
                        decision: "DENY".into(),
                        reason,
                        exit_status: None,
                        stdout_digest: None,
                    },
                };

                let reply = Envelope {
                    protocol_version: PROTOCOL_VERSION,
                    request_id,
                    kind: Some(envelope::Kind::IntentResult(result)),
                };

                {
                    let mut sup = state.supervisor.lock().await;
                    if let Err(e) = sup.write_next(reply).await {
                        tracing::warn!(error = %e, "failed to write IntentResult");
                        break;
                    }
                }
                let mut n = state.intents_handled.lock().await;
                *n += 1;
            }
            Some(envelope::Kind::Heartbeat(_)) => {
                tracing::debug!("worker heartbeat");
            }
            Some(envelope::Kind::Shutdown(s)) => {
                tracing::info!(reason = %s.reason, "worker requested shutdown");
                break;
            }
            other => {
                tracing::warn!(kind = ?other, "unexpected envelope from worker; ignoring");
            }
        }
    }
}

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt()
        .with_env_filter("info")
        .json()
        .init();

    let (sup, listener) = WorkerSupervisor::bind_loopback()
        .await
        .expect("bind worker ipc");
    let ipc = sup.listener_addr.clone();
    let state = Arc::new(AppState {
        supervisor: Mutex::new(sup),
        intents_handled: Mutex::new(0),
    });

    let python = std::env::var("AROS_PYTHON").unwrap_or_else(|_| "python".into());
    let pythonpath = std::env::var("PYTHONPATH").unwrap_or_else(|_| "python".into());
    {
        let mut s = state.supervisor.lock().await;
        if s.spawn_python(&python, &[], &pythonpath).is_ok() {
            match s.accept_hello(&listener).await {
                Ok(ver) => {
                    tracing::info!(python = %ver, "research worker handshake ok");
                    let st = Arc::clone(&state);
                    tokio::spawn(async move {
                        handle_worker_intents(st).await;
                    });
                }
                Err(e) => {
                    tracing::warn!(error = %e, "research worker handshake failed; daemon continues");
                }
            }
        } else {
            tracing::warn!("failed to spawn research worker; daemon continues without worker");
        }
    }

    let app = Router::new()
        .route("/health", get(health))
        .with_state(state);
    let http = tokio::net::TcpListener::bind("127.0.0.1:7432")
        .await
        .expect("bind arosd");
    tracing::info!("{DAEMON_NAME} listening on 127.0.0.1:7432 ipc={ipc}");
    axum::serve(http, app).await.expect("serve");
}

async fn health(State(state): State<Arc<AppState>>) -> Json<Health> {
    let mut sup = state.supervisor.lock().await;
    let intents = *state.intents_handled.lock().await;
    Json(Health {
        service: DAEMON_NAME,
        product: PRODUCT_NAME,
        version: env!("CARGO_PKG_VERSION"),
        python_embedded: false,
        worker_alive: sup.worker_alive(),
        ipc: sup.listener_addr.clone(),
        intents_handled: intents,
    })
}
