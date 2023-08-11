use super::*;
use axum_jwt_auth::route::create_router;
use serde_json::json;
#[tokio::test]
#[ignore = "requires TEST_DATABASE_URL and CREATEDB on a disposable Postgres"]
async fn access_requires_a_live_family_owned_by_the_subject() {
    let fixture=Fixture::new().await;
    let user=fixture.user().await;
    let pair=issue_session(&fixture.state,user).await.unwrap();
    let app=create_router(fixture.state.clone());
    let (status,_)=common::request(app.clone(),"GET","/api/users/me",json!(null),Some(&pair.access_token)).await;
    assert_eq!(status,200);
    let orphan=fixture.state.env.token_service().unwrap().issue(user,Uuid::new_v4(),chrono::Utc::now().timestamp()).unwrap();
    let (status,_)=common::request(app.clone(),"GET","/api/users/me",json!(null),Some(&orphan)).await;
    assert_eq!(status,401);
    sqlx::query("UPDATE session_families SET revoked_at=NOW()").execute(&fixture.state.db).await.unwrap();
    let (status,_)=common::request(app.clone(),"GET","/api/users/me",json!(null),Some(&pair.access_token)).await;
    assert_eq!(status,401);
    sqlx::query("UPDATE session_families SET revoked_at=NULL,created_at=NOW()-INTERVAL '2 days',expires_at=NOW()-INTERVAL '1 second'").execute(&fixture.state.db).await.unwrap();
    let (status,_)=common::request(app,"GET","/api/users/me",json!(null),Some(&pair.access_token)).await;
    assert_eq!(status,401);
    fixture.close().await;
}
