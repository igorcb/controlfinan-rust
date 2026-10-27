use std::net::SocketAddr;
use std::sync::Arc;

use controlfinan::web::{AppState, LogMailer};
use sqlx::postgres::PgPoolOptions;

fn env(name: &str, fallback: &str) -> String {
    std::env::var(name)
        .ok()
        .filter(|v| !v.is_empty())
        .unwrap_or_else(|| fallback.to_string())
}

#[tokio::main]
async fn main() {
    let db = PgPoolOptions::new()
        .max_connections(env("DB_POOL", "10").parse().expect("DB_POOL"))
        .connect(&env(
            "DATABASE_URL",
            "postgres://app:app@localhost:5432/controlfinan_rust",
        ))
        .await
        .expect("database");
    controlfinan::migrate(&db).await.expect("schema");

    let secret = std::env::var("SECRET_KEY_BASE").expect("SECRET_KEY_BASE is required");
    let zone = env("APP_TIMEZONE", "America/Sao_Paulo")
        .parse()
        .expect("APP_TIMEZONE");
    let cost = env("BCRYPT_COST", "12").parse().expect("BCRYPT_COST");
    let state = Arc::new(AppState::new(db, &secret, cost, zone, Arc::new(LogMailer)));

    let address = format!("0.0.0.0:{}", env("PORT", "8000"));
    let listener = tokio::net::TcpListener::bind(&address).await.expect("bind");
    println!("ControlFinan listening on {address}");
    let app = controlfinan::app(state, &env("STATIC_DIR", "static"));
    axum::serve(
        listener,
        app.into_make_service_with_connect_info::<SocketAddr>(),
    )
    .await
    .expect("server");
}
