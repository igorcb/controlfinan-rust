//! ControlFinan in Rust: same screens, rules and database as the Rails 8 + Hotwire app.

pub mod format;
pub mod handlers;
pub mod models;
pub mod web;

use axum::Router;
use axum::middleware::from_fn_with_state;

/// Creates the tables (same schema as the Rails app) when they do not exist.
pub async fn migrate(db: &sqlx::PgPool) -> sqlx::Result<()> {
    sqlx::raw_sql(include_str!("schema.sql"))
        .execute(db)
        .await?;
    Ok(())
}

/// The app. The request pipeline runs in an outer router whose only job is to hand every request to the
/// inner one, so "_method" can change the method before the inner router picks a route.
pub fn app(state: web::SharedState, static_dir: &str) -> Router {
    Router::new()
        .fallback_service(handlers::router(state.clone(), static_dir))
        .layer(from_fn_with_state(state, web::pipeline))
}
