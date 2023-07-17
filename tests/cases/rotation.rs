use super::*;
#[tokio::test]
#[ignore = "requires TEST_DATABASE_URL and CREATEDB on a disposable Postgres"]
async fn refresh_rotates_once_without_extending_the_family_deadline() {
    let fixture=Fixture::new().await;
    let user=fixture.user().await;
    let first=issue_session(&fixture.state,user).await.unwrap();
    let deadline:chrono::DateTime<chrono::Utc>=sqlx::query_scalar("SELECT expires_at FROM session_families").fetch_one(&fixture.state.db).await.unwrap();
    let second=axum_jwt_auth::session::rotate_session(&fixture.state,&first.refresh_token).await.unwrap();
    assert_ne!(first.refresh_token,second.refresh_token);
    let after:chrono::DateTime<chrono::Utc>=sqlx::query_scalar("SELECT expires_at FROM session_families").fetch_one(&fixture.state.db).await.unwrap();
    assert_eq!(deadline,after);
    assert!(axum_jwt_auth::session::rotate_session(&fixture.state,&first.refresh_token).await.is_err());
    let revoked:bool=sqlx::query_scalar("SELECT revoked_at IS NOT NULL FROM session_families").fetch_one(&fixture.state.db).await.unwrap();
    assert!(revoked);
    assert!(axum_jwt_auth::session::rotate_session(&fixture.state,&second.refresh_token).await.is_err());
    fixture.close().await;
}
