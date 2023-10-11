mod common;
use axum_jwt_auth::route::create_router;
use serde_json::json;
#[tokio::test]
async fn logout_all_is_protected() {
    let (status,_)=common::request(create_router(common::lazy_state()),"POST","/api/auth/logout-all",json!(null),None).await;
    assert_eq!(status,401);
}
