mod common;
use axum_jwt_auth::route::create_router;
use serde_json::json;
#[tokio::test]
async fn registration_validates_before_touching_the_database() {
    let app = create_router(common::lazy_state());
    let (status,body) = common::request(app, "POST", "/api/auth/register", json!({"name":" ","email":"broken","password":"short"}), None).await;
    assert_eq!(status, 400);
    assert_eq!(body["code"], "bad_request");
}
