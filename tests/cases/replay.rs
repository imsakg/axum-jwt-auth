use super::*;
use axum_jwt_auth::route::create_router;
use serde_json::json;
#[tokio::test]
#[ignore = "requires TEST_DATABASE_URL and CREATEDB on a disposable Postgres"]
async fn replay_returns_401_and_the_revocation_survives_the_response() {
    let fixture=Fixture::new().await;
    let first=issue_session(&fixture.state,fixture.user().await).await.unwrap();
    let app=create_router(fixture.state.clone());
    let (status,second)=common::request(app.clone(),"POST","/api/auth/refresh",json!({"refresh_token":first.refresh_token}),None).await;
    assert_eq!(status,200); assert_ne!(second["refresh_token"],first.refresh_token);
    let (status,_)=common::request(app.clone(),"POST","/api/auth/refresh",json!({"refresh_token":first.refresh_token}),None).await;
    assert_eq!(status,401);
    let (status,_)=common::request(app,"POST","/api/auth/refresh",json!({"refresh_token":second["refresh_token"]}),None).await;
    assert_eq!(status,401);
    let revoked:bool=sqlx::query_scalar("SELECT revoked_at IS NOT NULL FROM session_families").fetch_one(&fixture.state.db).await.unwrap();
    assert!(revoked);
    fixture.close().await;
}
