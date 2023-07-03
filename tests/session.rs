use axum_jwt_auth::{config::Config, session::issue_session, AppState};
use sqlx::postgres::PgPoolOptions;
#[tokio::test]
async fn issuing_a_session_propagates_database_failure_without_panicking() {
    let config=Config::from_lookup(|key| match key {"DATABASE_URL"=>Some("postgres://127.0.0.1:1/unused".into()),"JWT_SECRET"=>Some("a-long-test-key-at-least-thirty-two-bytes".into()),_=>None}).unwrap();
    let state=AppState{db:PgPoolOptions::new().acquire_timeout(std::time::Duration::from_millis(30)).connect_lazy(&config.database_url).unwrap(),env:config};
    assert!(issue_session(&state,uuid::Uuid::new_v4()).await.is_err());
}
