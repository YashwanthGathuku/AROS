#![forbid(unsafe_code)]
#![allow(clippy::expect_used, clippy::unwrap_used)]

use std::sync::Arc;

use axum::{extract::State, routing::get, Json, Router};
use serde::Serialize;
use tokio::sync::Mutex;

use aros_ipc::WorkerSupervisor;
use aros_types::{DAEMON_NAME, PRODUCT_NAME};

#[derive(Serialize)]
struct Health {
    service: &'static str,
    product: &'static str,
    version: &'static str,
    python_embedded: bool,
    worker_alive: bool,
    ipc: String,
}

struct AppState {
    supervisor: Mutex<WorkerSupervisor>,
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
    });

    let python = std::env::var("AROS_PYTHON").unwrap_or_else(|_| "python".into());
    let pythonpath = std::env::var("PYTHONPATH").unwrap_or_else(|_| "python".into());
    {
        let mut s = state.supervisor.lock().await;
        if s.spawn_python(&python, &[], &pythonpath).is_ok() {
            if let Ok(ver) = s.accept_hello(&listener).await {
                tracing::info!(python = %ver, "research worker handshake ok");
            } else {
                tracing::warn!("research worker handshake failed; daemon continues");
            }
        }
    }

    let app = Router::new()
        .route("/health", get(health))
        .with_state(state);
    let listener = tokio::net::TcpListener::bind("127.0.0.1:7432")
        .await
        .expect("bind arosd");
    tracing::info!("{DAEMON_NAME} listening on 127.0.0.1:7432 ipc={ipc}");
    axum::serve(listener, app).await.expect("serve");
}

async fn health(State(state): State<Arc<AppState>>) -> Json<Health> {
    let mut sup = state.supervisor.lock().await;
    Json(Health {
        service: DAEMON_NAME,
        product: PRODUCT_NAME,
        version: env!("CARGO_PKG_VERSION"),
        python_embedded: false,
        worker_alive: sup.worker_alive(),
        ipc: sup.listener_addr.clone(),
    })
}
