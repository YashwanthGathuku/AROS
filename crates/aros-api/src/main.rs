#![forbid(unsafe_code)]
#![allow(clippy::expect_used, clippy::unwrap_used)]

use axum::{routing::get, Json, Router};
use serde::Serialize;

#[derive(Serialize)]
struct Health {
    service: &'static str,
    version: &'static str,
    python_embedded: bool,
}

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt()
        .with_env_filter("info")
        .json()
        .init();

    let app = Router::new().route("/health", get(health));
    let listener = tokio::net::TcpListener::bind("127.0.0.1:7432")
        .await
        .expect("bind arosd");
    tracing::info!("arosd listening on 127.0.0.1:7432");
    axum::serve(listener, app).await.expect("serve");
}

async fn health() -> Json<Health> {
    Json(Health {
        service: "arosd",
        version: env!("CARGO_PKG_VERSION"),
        python_embedded: false,
    })
}
