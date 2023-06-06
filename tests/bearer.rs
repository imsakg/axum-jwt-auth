use axum::http::{header,HeaderMap,HeaderValue};
use axum_jwt_auth::jwt_auth::bearer_token;
#[test]
fn bearer_scheme_is_case_insensitive_but_ambiguous_credentials_fail() {
    let mut headers=HeaderMap::new();
    headers.insert(header::AUTHORIZATION, HeaderValue::from_static("bEaReR signed-token"));
    assert_eq!(bearer_token(&headers).unwrap(),"signed-token");
    for value in ["Basic abc", "Bearer", "Bearer ", "Bearer  abc", "Bearer a b", "Bearer abc\t"] {
        headers.insert(header::AUTHORIZATION,HeaderValue::from_str(value).unwrap());
        assert!(bearer_token(&headers).is_err(),"{value}");
    }
    headers.insert(header::AUTHORIZATION, HeaderValue::from_static("Bearer one"));
    headers.append(header::AUTHORIZATION, HeaderValue::from_static("Bearer two"));
    assert!(bearer_token(&headers).is_err());
}
#[tokio::test]
async fn token_cookie_is_not_an_authentication_credential() {
    use tower::ServiceExt;
    use axum::{body::Body,http::Request};
    let config=axum_jwt_auth::config::Config::from_lookup(|key| match key {"DATABASE_URL"=>Some("postgres://127.0.0.1:1/unused".into()),"JWT_SECRET"=>Some("a-long-test-key-at-least-thirty-two-bytes".into()),_=>None}).unwrap();
    let state=std::sync::Arc::new(axum_jwt_auth::AppState{db:sqlx::postgres::PgPoolOptions::new().connect_lazy(&config.database_url).unwrap(),env:config});
    let response=axum_jwt_auth::route::create_router(state).oneshot(Request::builder().uri("/api/users/me").header("cookie","token=anything").body(Body::empty()).unwrap()).await.unwrap();
    assert_eq!(response.status(),401);
    assert_eq!(response.headers()[header::WWW_AUTHENTICATE],"Bearer");
}
