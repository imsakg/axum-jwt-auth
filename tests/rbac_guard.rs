use axum::{body::Body,http::Request,middleware,routing::get,Router};
use tower::ServiceExt;
#[tokio::test]
async fn admin_guard_requires_an_authenticated_identity() {
    let router=Router::new().route("/",get(|| async {"secret"})).layer(middleware::from_fn(axum_jwt_auth::rbac::require_admin));
    let response=router.oneshot(Request::builder().uri("/").body(Body::empty()).unwrap()).await.unwrap();
    assert_eq!(response.status(),401);
}
