use super::*;
use axum_jwt_auth::session::rotate_session;
#[tokio::test]
#[ignore = "requires TEST_DATABASE_URL and CREATEDB on a disposable Postgres"]
async fn concurrent_refresh_has_one_winner_and_revokes_that_family_on_reuse() {
    let fixture=Fixture::new().await;
    let user=fixture.user().await;
    for _ in 0..5 {
        let first=issue_session(&fixture.state,user).await.unwrap();
        let (one,two)=tokio::join!(rotate_session(&fixture.state,&first.refresh_token),rotate_session(&fixture.state,&first.refresh_token));
        assert_ne!(one.is_ok(),two.is_ok());
        let winner=one.or(two).unwrap();
        assert!(rotate_session(&fixture.state,&winner.refresh_token).await.is_err());
        let claims=fixture.state.env.token_service().unwrap().verify(&winner.access_token).unwrap();
        let revoked:bool=sqlx::query_scalar("SELECT revoked_at IS NOT NULL FROM session_families WHERE id=$1").bind(claims.sid).fetch_one(&fixture.state.db).await.unwrap();
        assert!(revoked);
    }
    fixture.close().await;
}
