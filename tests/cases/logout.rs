use super::*;
use axum_jwt_auth::route::create_router;
use serde_json::json;
#[tokio::test]
#[ignore = "requires TEST_DATABASE_URL and CREATEDB on a disposable Postgres"]
async fn logout_is_post_only_and_revokes_the_refresh_family() {
    let fixture=Fixture::new().await;
    let pair=issue_session(&fixture.state,fixture.user().await).await.unwrap();
    let app=create_router(fixture.state.clone());
    let (status,_)=common::request(app.clone(),"GET","/api/auth/logout",json!(null),Some(&pair.access_token)).await;
    assert_eq!(status,405);
    let (status,_)=common::request(app.clone(),"POST","/api/auth/logout",json!(null),Some(&pair.access_token)).await;
    assert_eq!(status,204);
    let (status,_)=common::request(app,"POST","/api/auth/refresh",json!({"refresh_token":pair.refresh_token}),None).await;
    assert_eq!(status,401);
    fixture.close().await;
}
