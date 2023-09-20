use super::*;
use axum_jwt_auth::{route::create_router,session::rotate_session};
use serde_json::json;
#[tokio::test]
#[ignore = "requires TEST_DATABASE_URL and CREATEDB on a disposable Postgres"]
async fn full_http_lifecycle_preserves_identity_and_revokes_access() {
    let fixture=Fixture::new().await;
    let app=create_router(fixture.state.clone());
    let registration=json!({"name":"Alice","email":"a@example.test","password":"long-enough-password"});
    assert_eq!(common::request(app.clone(),"POST","/api/auth/register",registration.clone(),None).await.0,201);
    assert_eq!(common::request(app.clone(),"POST","/api/auth/register",registration,None).await.0,409);
    for email in ["a@example.test","missing@example.test"] {
        let (status,body)=common::request(app.clone(),"POST","/api/auth/login",json!({"email":email,"password":"wrong"}),None).await;
        assert_eq!(status,401); assert_eq!(body["code"],"unauthorized");
    }
    let (status,first)=common::request(app.clone(),"POST","/api/auth/login",json!({"email":"a@example.test","password":"long-enough-password"}),None).await;
    assert_eq!(status,200);
    let token=first["access_token"].as_str().unwrap();
    let (status,me)=common::request(app.clone(),"GET","/api/users/me",json!(null),Some(token)).await;
    assert_eq!(status,200); assert_eq!(me["data"]["user"]["email"],"a@example.test");
    let (status,second)=common::request(app.clone(),"POST","/api/auth/refresh",json!({"refresh_token":first["refresh_token"]}),None).await;
    assert_eq!(status,200);
    assert_eq!(common::request(app.clone(),"POST","/api/auth/logout",json!(null),second["access_token"].as_str()).await.0,204);
    assert_eq!(common::request(app,"GET","/api/users/me",json!(null),Some(token)).await.0,401);
    fixture.close().await;
}
#[tokio::test]
#[ignore = "requires TEST_DATABASE_URL and CREATEDB on a disposable Postgres"]
async fn expired_families_and_deleted_accounts_cannot_refresh() {
    let fixture=Fixture::new().await;
    let user=fixture.user().await;
    let pair=issue_session(&fixture.state,user).await.unwrap();
    sqlx::query("UPDATE session_families SET created_at=NOW()-INTERVAL '2 days',expires_at=NOW()-INTERVAL '1 second'").execute(&fixture.state.db).await.unwrap();
    assert!(rotate_session(&fixture.state,&pair.refresh_token).await.is_err());
    let pair=issue_session(&fixture.state,user).await.unwrap();
    sqlx::query("DELETE FROM users WHERE id=$1").bind(user).execute(&fixture.state.db).await.unwrap();
    assert!(rotate_session(&fixture.state,&pair.refresh_token).await.is_err());
    let count:i64=sqlx::query_scalar("SELECT COUNT(*) FROM refresh_tokens").fetch_one(&fixture.state.db).await.unwrap();
    assert_eq!(count,0);
    fixture.close().await;
}
