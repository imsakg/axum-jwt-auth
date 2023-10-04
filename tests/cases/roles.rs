use super::*;
use axum_jwt_auth::route::create_router;
use serde_json::json;
#[tokio::test]
#[ignore = "requires TEST_DATABASE_URL and CREATEDB on a disposable Postgres"]
async fn current_database_roles_override_old_access_tokens() {
    let fixture=Fixture::new().await;
    let user=fixture.user().await;
    let pair=issue_session(&fixture.state,user).await.unwrap();
    let app=create_router(fixture.state.clone());
    assert_eq!(common::request(app.clone(),"GET","/api/admin/users",json!(null),Some(&pair.access_token)).await.0,403);
    sqlx::query("UPDATE users SET role='admin' WHERE id=$1").bind(user).execute(&fixture.state.db).await.unwrap();
    let (status,body)=common::request(app.clone(),"GET","/api/admin/users",json!(null),Some(&pair.access_token)).await;
    assert_eq!(status,200); assert_eq!(body["data"]["users"].as_array().unwrap().len(),1);
    assert!(body["data"]["users"][0].get("password").is_none());
    sqlx::query("UPDATE users SET role='user' WHERE id=$1").bind(user).execute(&fixture.state.db).await.unwrap();
    assert_eq!(common::request(app,"GET","/api/admin/users",json!(null),Some(&pair.access_token)).await.0,403);
    let error=sqlx::query("UPDATE users SET role='superadmin' WHERE id=$1").bind(user).execute(&fixture.state.db).await.unwrap_err();
    assert_eq!(error.as_database_error().unwrap().code().as_deref(),Some("23514"));
    fixture.close().await;
}
