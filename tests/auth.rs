mod common;
use axum_jwt_auth::route::create_router;
use serde_json::json;
#[tokio::test]
async fn protected_routes_reject_missing_or_malformed_bearer_credentials() {
    for token in [None,Some("invalid"),Some(""),Some("x.y.z")] {
        let (status,body)=common::request(create_router(common::lazy_state()),"GET","/api/users/me",json!(null),token).await;
        assert_eq!(status,401); assert_eq!(body["code"],"unauthorized");
    }
}
