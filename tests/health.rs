use axum::response::IntoResponse;
use axum_jwt_auth::handler::health_checker_handler;

#[tokio::test]
async fn health_returns_json_success() {
    let response = health_checker_handler().await.into_response();
    assert_eq!(response.status(), 200);
    assert_eq!(response.headers()["content-type"], "application/json");
    let body = axum::body::to_bytes(response.into_body(), 4096)
        .await
        .unwrap();
    let value: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(value["status"], "success");
}
