mod common;
use axum_jwt_auth::route::create_router;
use serde_json::json;
#[tokio::test]
async fn administrator_route_authenticates_before_authorizing() {
    let (status,body)=common::request(create_router(common::lazy_state()),"GET","/api/admin/users",json!(null),None).await;
    assert_eq!(status,401); assert_eq!(body["code"],"unauthorized");
}
