use axum::{body::Body,http::Request,middleware,routing::get,Router};
use tower::ServiceExt;
#[tokio::test]
async fn administrator_guard_distinguishes_forbidden_roles_from_missing_identity() {
    for (role,status) in [("user",403),("admin",200),("unknown",403)] {
        let user:axum_jwt_auth::model::User=serde_json::from_value(serde_json::json!({"id":uuid::Uuid::new_v4(),"name":"Alice","email":"a@example.test","password":"hash","role":role,"photo":"default.png","verified":false,"createdAt":null,"updatedAt":null})).unwrap();
        let router=Router::new().route("/",get(|| async {"secret"})).layer(middleware::from_fn(axum_jwt_auth::rbac::require_admin));
        let mut request=Request::builder().uri("/").body(Body::empty()).unwrap();
        request.extensions_mut().insert(user);
        let response=router.oneshot(request).await.unwrap();
        assert_eq!(response.status(),status,"{role}");
    }
}
#[tokio::test]
async fn admin_guard_requires_an_authenticated_identity() {
    let router=Router::new().route("/",get(|| async {"secret"})).layer(middleware::from_fn(axum_jwt_auth::rbac::require_admin));
    let response=router.oneshot(Request::builder().uri("/").body(Body::empty()).unwrap()).await.unwrap();
    assert_eq!(response.status(),401);
}
