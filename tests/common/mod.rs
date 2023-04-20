#![allow(dead_code)]
use std::sync::Arc;
use axum::{body::Body, http::Request, Router};
use axum_jwt_auth::{config::Config, AppState};
use serde_json::Value;
use tower::ServiceExt;
pub fn config(database_url: &str) -> Config {
    Config::from_lookup(|key| match key {
        "DATABASE_URL" => Some(database_url.into()),
        "JWT_SECRET" => Some("test-secret-at-least-thirty-two-bytes-long".into()),
        _ => None,
    }).unwrap()
}
pub fn lazy_state() -> Arc<AppState> {
    let config = config("postgres://127.0.0.1:1/unused");
    Arc::new(AppState { db:sqlx::postgres::PgPoolOptions::new().acquire_timeout(std::time::Duration::from_millis(50)).connect_lazy(&config.database_url).unwrap(), env:config })
}
pub async fn request(app: Router, method: &str, path: &str, body: Value, token: Option<&str>) -> (u16, Value) {
    let mut builder = Request::builder().method(method).uri(path).header("content-type", "application/json");
    if let Some(token) = token { builder = builder.header("authorization", format!("Bearer {token}")); }
    let response = app.oneshot(builder.body(Body::from(body.to_string())).unwrap()).await.unwrap();
    let status = response.status().as_u16();
    let bytes = axum::body::to_bytes(response.into_body(), 1024*1024).await.unwrap();
    let value = serde_json::from_slice(&bytes).unwrap_or(Value::Null);
    (status, value)
}
