use super::*;
use axum_jwt_auth::{route::create_router,session::rotate_session};
use serde_json::json;
#[tokio::test]
#[ignore = "requires TEST_DATABASE_URL and CREATEDB on a disposable Postgres"]
async fn all_device_logout_revokes_only_the_authenticated_users_sessions() {
    let fixture=Fixture::new().await;
    let user=fixture.user().await;
    let first=issue_session(&fixture.state,user).await.unwrap();
    let second=issue_session(&fixture.state,user).await.unwrap();
    let unrelated=issue_session(&fixture.state,fixture.user().await).await.unwrap();
    let app=create_router(fixture.state.clone());
    assert_eq!(common::request(app.clone(),"POST","/api/auth/logout-all",json!(null),Some(&first.access_token)).await.0,204);
    for pair in [first,second] {
        assert_eq!(common::request(app.clone(),"GET","/api/users/me",json!(null),Some(&pair.access_token)).await.0,401);
        assert!(rotate_session(&fixture.state,&pair.refresh_token).await.is_err());
    }
    assert_eq!(common::request(app,"GET","/api/users/me",json!(null),Some(&unrelated.access_token)).await.0,200);
    assert!(rotate_session(&fixture.state,&unrelated.refresh_token).await.is_ok());
    fixture.close().await;
}
