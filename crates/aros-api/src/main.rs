#![forbid(unsafe_code)]
#![allow(clippy::expect_used, clippy::unwrap_used)]

use std::path::PathBuf;
use std::sync::Arc;

use axum::{
    extract::{Path, State},
    http::{header::AUTHORIZATION, HeaderMap, StatusCode},
    routing::{get, post},
    Json, Router,
};
use serde::Serialize;
use tokio::sync::Mutex;

use aros_api::campaign::{run_fixture_campaign, FixtureCampaignRequest, FixtureCampaignResponse};
use aros_api::lab::{
    capability_from_str, intent_from_request, LabRuntime, ToolIntentRequest, ToolIntentResponse,
};
use aros_api::registry::{CampaignRecord, CampaignRegistry};
use aros_ipc::messages::{envelope, Envelope, IntentResult, PROTOCOL_VERSION};
use aros_ipc::WorkerSupervisor;
use aros_types::{env_name, ToolIntent, DAEMON_NAME, PRODUCT_NAME};

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
    campaigns_stored: u64,
}

#[derive(Serialize)]
struct ApiError {
    error: String,
}

struct AppState {
    supervisor: Mutex<WorkerSupervisor>,
    intents_handled: Mutex<u64>,
    intents_executed: Mutex<u64>,
    lab: Mutex<LabRuntime>,
    registry: Mutex<CampaignRegistry>,
    daemon_token: String,
}

fn authorized(headers: &HeaderMap, state: &AppState) -> bool {
    let Some(value) = headers.get(AUTHORIZATION).and_then(|value| value.to_str().ok()) else {
        return false;
    };
    value
        .strip_prefix("Bearer ")
        .is_some_and(|token| token == state.daemon_token)
}

fn unauthorized() -> (StatusCode, Json<ApiError>) {
    (
        StatusCode::UNAUTHORIZED,
        Json(ApiError {
            error: "missing or invalid bearer token".into(),
        }),
    )
}

fn intent_from_msg(msg: &aros_ipc::messages::ToolIntentMsg) -> Result<ToolIntent, String> {
    let capability = capability_from_str(&msg.capability)
        .ok_or_else(|| format!("unknown capability {:?}", msg.capability))?;
    let mut intent = ToolIntent::new(capability);
    intent.argv = msg.argv.clone();
    intent.cwd = msg.cwd.clone();
    intent.path = msg.path.clone();
    intent.timeout_ms = if msg.timeout_ms == 0 { 30_000 } else { msg.timeout_ms };
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
    let response = lab.execute(intent);
    IntentResult {
        decision: response.decision,
        reason: response.reason,
        exit_status: response.exit_status,
        stdout_digest: response.stdout_digest,
    }
}

async fn handle_worker_intents(state: Arc<AppState>) {
    loop {
        let envelope = {
            let mut supervisor = state.supervisor.lock().await;
            match supervisor.read_next().await {
                Ok(envelope) => envelope,
                Err(error) => {
                    tracing::warn!(error = %error, "worker stream ended or read failed");
                    break;
                }
            }
        };

        match envelope.kind {
            Some(envelope::Kind::ToolIntent(message)) => {
                let request_id = envelope.request_id.clone();
                let result = match intent_from_msg(&message) {
                    Ok(intent) => {
                        let state_for_task = Arc::clone(&state);
                        tokio::task::spawn_blocking(move || {
                            let mut lab = state_for_task.lab.blocking_lock();
                            execute_intent(&mut lab, intent)
                        })
                        .await
                        .unwrap_or_else(|error| IntentResult {
                            decision: "DENY".into(),
                            reason: format!("join error: {error}"),
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
                    *state.intents_executed.lock().await += 1;
                }
                let reply = Envelope {
                    protocol_version: PROTOCOL_VERSION,
                    request_id,
                    kind: Some(envelope::Kind::IntentResult(result)),
                };
                let mut supervisor = state.supervisor.lock().await;
                if let Err(error) = supervisor.write_next(reply).await {
                    tracing::warn!(error = %error, "failed to write IntentResult");
                    break;
                }
                drop(supervisor);
                *state.intents_handled.lock().await += 1;
            }
            Some(envelope::Kind::Heartbeat(_)) => tracing::debug!("worker heartbeat"),
            Some(envelope::Kind::Shutdown(shutdown)) => {
                tracing::info!(reason = %shutdown.reason, "worker requested shutdown");
                break;
            }
            other => tracing::warn!(kind = ?other, "unexpected envelope from worker; ignoring"),
        }
    }
}

async fn tool_intent(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Json(request): Json<ToolIntentRequest>,
) -> Result<Json<ToolIntentResponse>, (StatusCode, Json<ApiError>)> {
    if !authorized(&headers, &state) {
        return Err(unauthorized());
    }
    let intent = match intent_from_request(&request) {
        Ok(intent) => intent,
        Err(reason) => {
            return Ok(Json(ToolIntentResponse {
                decision: "DENY".into(),
                reason,
                exit_status: None,
                stdout_digest: None,
            }))
        }
    };
    let state_for_task = Arc::clone(&state);
    let response = tokio::task::spawn_blocking(move || {
        let mut lab = state_for_task.lab.blocking_lock();
        lab.execute(intent)
    })
    .await
    .unwrap_or_else(|error| ToolIntentResponse {
        decision: "DENY".into(),
        reason: format!("join error: {error}"),
        exit_status: None,
        stdout_digest: None,
    });
    if response.decision == "ALLOW" && response.stdout_digest.is_some() {
        *state.intents_executed.lock().await += 1;
    }
    *state.intents_handled.lock().await += 1;
    Ok(Json(response))
}

async fn fixture_campaign(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Json(request): Json<FixtureCampaignRequest>,
) -> Result<Json<FixtureCampaignResponse>, (StatusCode, Json<ApiError>)> {
    if !authorized(&headers, &state) {
        return Err(unauthorized());
    }
    let result = tokio::task::spawn_blocking(move || run_fixture_campaign(&request))
        .await
        .map_err(|error| {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(ApiError {
                    error: format!("join error: {error}"),
                }),
            )
        })?;
    match result {
        Ok(response) => {
            let registry = state.registry.lock().await;
            if let Err(error) = registry.put(&response) {
                tracing::warn!(error = %error, "failed to persist campaign outcome");
            }
            Ok(Json(response))
        }
        Err(error) => Err((StatusCode::UNPROCESSABLE_ENTITY, Json(ApiError { error }))),
    }
}

async fn get_campaign(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Path(id): Path<String>,
) -> Result<Json<CampaignRecord>, (StatusCode, Json<ApiError>)> {
    if !authorized(&headers, &state) {
        return Err(unauthorized());
    }
    let registry = state.registry.lock().await;
    registry
        .get(&id)
        .map(Json)
        .map_err(|error| (StatusCode::NOT_FOUND, Json(ApiError { error })))
}

async fn list_campaigns(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
) -> Result<Json<Vec<CampaignRecord>>, (StatusCode, Json<ApiError>)> {
    if !authorized(&headers, &state) {
        return Err(unauthorized());
    }
    let registry = state.registry.lock().await;
    registry
        .list()
        .map(Json)
        .map_err(|error| (StatusCode::INTERNAL_SERVER_ERROR, Json(ApiError { error })))
}

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt()
        .with_env_filter("info")
        .json()
        .init();

    let daemon_token = std::env::var(env_name("DAEMON_TOKEN"))
        .expect("AROS_DAEMON_TOKEN is required");
    assert!(
        daemon_token.len() >= 32,
        "AROS_DAEMON_TOKEN must contain at least 32 characters"
    );
    let data_root = std::env::var(env_name("DATA_ROOT"))
        .map(PathBuf::from)
        .unwrap_or_else(|_| PathBuf::from(".aros-data"));
    let lab = LabRuntime::open(&data_root).expect("open fail-closed lab runtime");
    let registry = CampaignRegistry::open(&data_root).expect("open campaign registry");

    let (supervisor, listener) = WorkerSupervisor::bind_loopback()
        .await
        .expect("bind worker ipc");
    let ipc = supervisor.listener_addr.clone();
    let state = Arc::new(AppState {
        supervisor: Mutex::new(supervisor),
        intents_handled: Mutex::new(0),
        intents_executed: Mutex::new(0),
        lab: Mutex::new(lab),
        registry: Mutex::new(registry),
        daemon_token,
    });

    let python = std::env::var(env_name("PYTHON")).unwrap_or_else(|_| "python3".into());
    let pythonpath = std::env::var("PYTHONPATH").unwrap_or_else(|_| "python".into());
    {
        let mut supervisor = state.supervisor.lock().await;
        if supervisor.spawn_python(&python, &[], &pythonpath).is_ok() {
            match supervisor.accept_hello(&listener).await {
                Ok(version) => {
                    tracing::info!(python = %version, "research worker handshake ok");
                    let worker_state = Arc::clone(&state);
                    tokio::spawn(async move { handle_worker_intents(worker_state).await });
                }
                Err(error) => {
                    tracing::warn!(error = %error, "research worker handshake failed; daemon continues without worker");
                }
            }
        } else {
            tracing::warn!("failed to spawn research worker; daemon continues without worker");
        }
    }

    let app = Router::new()
        .route("/health", get(health))
        .route("/v1/tool-intent", post(tool_intent))
        .route("/v1/campaigns/fixture", post(fixture_campaign))
        .route("/v1/campaigns", get(list_campaigns))
        .route("/v1/campaigns/{id}", get(get_campaign))
        .with_state(state);
    let http = tokio::net::TcpListener::bind("127.0.0.1:7432")
        .await
        .expect("bind arosd");
    tracing::info!("{DAEMON_NAME} listening on 127.0.0.1:7432 ipc={ipc}");
    axum::serve(http, app).await.expect("serve");
}

async fn health(State(state): State<Arc<AppState>>) -> Json<Health> {
    let mut supervisor = state.supervisor.lock().await;
    let intents = *state.intents_handled.lock().await;
    let executed = *state.intents_executed.lock().await;
    let lab = state.lab.lock().await;
    let lab_root = lab
        .manifest
        .allowed_filesystem_roots
        .first()
        .cloned()
        .unwrap_or_default();
    let campaigns_stored = state
        .registry
        .lock()
        .await
        .list()
        .map(|campaigns| campaigns.len() as u64)
        .unwrap_or(0);
    Json(Health {
        service: DAEMON_NAME,
        product: PRODUCT_NAME,
        version: env!("CARGO_PKG_VERSION"),
        python_embedded: false,
        worker_alive: supervisor.worker_alive(),
        ipc: supervisor.listener_addr.clone(),
        intents_handled: intents,
        intents_executed: executed,
        cas_root: lab.cas.root().display().to_string(),
        lab_root,
        campaigns_stored,
    })
}
