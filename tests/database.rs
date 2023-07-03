mod common;
use std::{str::FromStr,sync::Arc};
use axum_jwt_auth::{session::issue_session,AppState};
use sqlx::{postgres::{PgConnectOptions,PgPoolOptions},PgPool};
use uuid::Uuid;
struct Fixture { state:Arc<AppState>, admin:PgPool, name:String }
impl Fixture {
    async fn new() -> Self {
        let url=std::env::var("TEST_DATABASE_URL").expect("set TEST_DATABASE_URL to a disposable Postgres with CREATEDB");
        let options=PgConnectOptions::from_str(&url).unwrap();
        let admin=PgPoolOptions::new().max_connections(2).connect_with(options.clone()).await.unwrap();
        let name=format!("axum_jwt_test_{}",Uuid::new_v4().simple());
        sqlx::query(&format!("CREATE DATABASE {name}")).execute(&admin).await.unwrap();
        let db=PgPoolOptions::new().max_connections(5).connect_with(options.database(&name)).await.unwrap();
        sqlx::migrate!("./migrations").run(&db).await.unwrap();
        let state=Arc::new(AppState{db,env:common::config(&url)});
        Self{state,admin,name}
    }
    async fn user(&self) -> Uuid {
        sqlx::query_scalar("INSERT INTO users (name,email,password) VALUES ('Alice',$1,'test-placeholder') RETURNING id")
            .bind(format!("{}@example.test",Uuid::new_v4())).fetch_one(&self.state.db).await.unwrap()
    }
    async fn close(self) {
        self.state.db.close().await;
        sqlx::query(&format!("DROP DATABASE {}",self.name)).execute(&self.admin).await.unwrap();
        self.admin.close().await;
    }
}
#[tokio::test]
#[ignore = "requires TEST_DATABASE_URL and CREATEDB on a disposable Postgres"]
async fn session_issuance_persists_only_the_refresh_digest() {
    let fixture=Fixture::new().await;
    let user=fixture.user().await;
    let pair=issue_session(&fixture.state,user).await.unwrap();
    let digest:String=sqlx::query_scalar("SELECT token_hash FROM refresh_tokens").fetch_one(&fixture.state.db).await.unwrap();
    assert_ne!(digest,pair.refresh_token);
    assert_eq!(digest,axum_jwt_auth::refresh::refresh_digest(&pair.refresh_token).unwrap());
    let claims=fixture.state.env.token_service().unwrap().verify(&pair.access_token).unwrap();
    assert_eq!(claims.sub,user);
    let stored:Uuid=sqlx::query_scalar("SELECT id FROM session_families WHERE user_id=$1").bind(user).fetch_one(&fixture.state.db).await.unwrap();
    assert_eq!(stored,claims.sid);
    fixture.close().await;
}
