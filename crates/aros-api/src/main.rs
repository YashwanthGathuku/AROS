#![forbid(unsafe_code)]
#![allow(clippy::expect_used, clippy::unwrap_used)]

use std::path::PathBuf;
use std::sync::Arc;

use axum::{
    extract::State,
    routing::{get, post},
    Json, Router,
};
use serde::Serialize;
use tokio::sync::Mutex;

use aros_api::lab::{
    capability_from_str, intent_from_request, LabRuntime, ToolIntentRequest, ToolIntentResponse,
};
use aros_ipc::messages::{envelope, Envelope, IntentResult, PROTOCOL_VERSION};
use aros_ipc::WorkerSupervisor;
use aros_types::{ToolIntent, DAEMON_NAME, PRODUCT_NAME};

#[derive(Serialize)]
struct Health {
    service: &'static str,
    product: &'static str,
    version: &'static str,
    python_embedded: bool,
    worker_alive: bool,
    ipc: String,
    intents_handled: u64,
    intents_executed: u64,
    cas_root: String,
    lab_root: String,
}

struct AppState {
    supervisor: Mutex<WorkerSupervisor>,
    intents_handled: Mutex<u64>,
    intents_executed: Mutex<u64>,
    lab: Mutex<LabRuntime>,
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
            Some("tcp") => aros_types::ProtocolKind::Tcp,
            Some("udp") => aros_types::ProtocolKind::Udp,
            _ => aros_types::ProtocolKind::Http,
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

fn execute_intent(lab: &mut LabRuntime, intent: ToolIntent) -> IntentResult {
    let resp = lab.execute(intent);
    IntentResult {
        decision: resp.decision,
        reason: resp.reason,
        exit_status: resp.exit_status,
        stdout_digest: resp.stdout_digest,
    }
}

async fn handle_worker_intents(state: Arc<AppState>) {
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
                        let st = Arc::clone(&state);
                        tokio::task::spawn_blocking(move || {
                            let mut lab = st.lab.blocking_lock();
                            execute_intent(&mut lab, intent)
                        })
                        .await
                        .unwrap_or_else(|e| IntentResult {
                            decision: "DENY".into(),
                            reason: format!("join error: {e}"),
                            exit_status: None,
                            stdout_digest: None,
                        })
                    }
                    Err(reason) => IntentResult {
                        decision: "DENY".into(),
                        reason,
                        exit_status: None,
                        stdout_digest: None,
                    },
                };

                if result.decision == "ALLOW" && result.stdout_digest.is_some() {
                    let mut n = state.intents_executed.lock().await;
                    *n += 1;
                }

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

async fn tool_intent(
    State(state): State<Arc<AppState>>,
    Json(req): Json<ToolIntentRequest>,
) -> Json<ToolIntentResponse> {
    let intent = match intent_from_request(&req) {
        Ok(i) => i,
        Err(reason) => {
            return Json(ToolIntentResponse {
                decision: "DENY".into(),
                reason,
                exit_status: None,
                stdout_digest: None,
            });
        }
    };
    let st = Arc::clone(&state);
    let resp = tokio::task::spawn_blocking(move || {
        let mut lab = st.lab.blocking_lock();
        lab.execute(intent)
    })
    .await
    .unwrap_or_else(|e| ToolIntentResponse {
        decision: "DENY".into(),
        reason: format!("join error: {e}"),
        exit_status: None,
        stdout_digest: None,
    });
    if resp.decision == "ALLOW" && resp.stdout_digest.is_some() {
        let mut n = state.intents_executed.lock().await;
        *n += 1;
    }
    let mut n = state.intents_handled.lock().await;
    *n += 1;
    Json(resp)
}

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt()
        .with_env_filter("info")
        .json()
        .init();

    let data_root = std::env::var("AROS_DATA_ROOT")
        .map(PathBuf::from)
        .unwrap_or_else(|_| PathBuf::from(".aros-data"));
    let lab = LabRuntime::open(&data_root).expect("open lab runtime");

    let (sup, listener) = WorkerSupervisor::bind_loopback()
        .await
        .expect("bind worker ipc");
    let ipc = sup.listener_addr.clone();
    let state = Arc::new(AppState {
        supervisor: Mutex::new(sup),
        intents_handled: Mutex::new(0),
        intents_executed: Mutex::new(0),
        lab: Mutex::new(lab),
    });

    let python = std::env::var("AROS_PYTHON").unwrap_or_else(|_| "python3".into());
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
        .route("/v1/tool-intent", post(tool_intent))
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
    let executed = *state.intents_executed.lock().await;
    let lab = state.lab.lock().await;
    let lab_root = lab
        .manifest
        .allowed_filesystem_roots
        .first()
        .cloned()
        .unwrap_or_default();
    Json(Health {
        service: DAEMON_NAME,
        product: PRODUCT_NAME,
        version: env!("CARGO_PKG_VERSION"),
        python_embedded: false,
        worker_alive: sup.worker_alive(),
        ipc: sup.listener_addr.clone(),
        intents_handled: intents,
        intents_executed: executed,
        cas_root: lab.cas.root().display().to_string(),
        lab_root,
    })
}
