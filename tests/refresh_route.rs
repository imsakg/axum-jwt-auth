mod common;
use axum_jwt_auth::route::create_router;
use serde_json::json;
#[tokio::test]
async fn malformed_refresh_secret_returns_401_without_a_database() {
    for token in ["", "invalid", "not.a.jwt"] {
        let (status,body)=common::request(create_router(common::lazy_state()),"POST","/api/auth/refresh",json!({"refresh_token":token}),None).await;
        assert_eq!(status,401); assert_eq!(body["code"],"unauthorized");
    }
}
