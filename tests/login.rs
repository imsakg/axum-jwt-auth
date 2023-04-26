mod common;
use axum_jwt_auth::route::create_router;
use serde_json::json;
#[tokio::test]
async fn malformed_credentials_fail_before_database_access() {
    for (email,password) in [("broken", "some-password".into()), ("a@example.com", "".into()), ("a@example.com", "a".repeat(129))] {
        let (status,body) = common::request(create_router(common::lazy_state()), "POST", "/api/auth/login", json!({"email":email,"password":password}), None).await;
        assert_eq!(status, 401); assert_eq!(body["code"], "unauthorized");
    }
}
#[tokio::test]
async fn unavailable_database_never_leaks_sql_or_connection_details() {
    let (status,body) = common::request(create_router(common::lazy_state()), "POST", "/api/auth/login", json!({"email":"a@example.com","password":"long-enough-password"}), None).await;
    assert_eq!(status, 500); assert_eq!(body["code"], "internal_error");
    assert!(!body.to_string().contains("127.0.0.1"));
}
