use axum_jwt_auth::{config::Config, token::TokenService};
use std::collections::HashMap;
#[test]
fn environment_keyrings_select_active_key_and_redact_secrets() {
    let values=HashMap::from([
        ("DATABASE_URL","postgres://localhost/auth"),
        ("JWT_ACTIVE_KID","october"),
        ("JWT_KEYS",r#"{"october":"a-long-new-key-at-least-thirty-two-bytes"}"#),
    ]);
    let config=Config::from_lookup(|key| values.get(key).map(|v| v.to_string())).unwrap();
    let service=TokenService::from_keys(&config.active_kid,config.jwt_keys.clone(),&config.issuer,&config.audience,config.access_ttl_seconds).unwrap();
    let jwt=service.issue(uuid::Uuid::new_v4(),uuid::Uuid::new_v4(),chrono::Utc::now().timestamp()).unwrap();
    assert_eq!(jsonwebtoken::decode_header(&jwt).unwrap().kid.as_deref(),Some("october"));
    assert!(!format!("{config:?}").contains("a-long-new-key"));
}
#[test]
fn invalid_keyrings_fail_closed_instead_of_falling_back() {
    for keys in ["broken",r#"{}"#,r#"{"default":"short"}"#] {
        assert!(Config::from_lookup(|key| match key {"DATABASE_URL"=>Some("postgres://localhost/auth".into()),"JWT_KEYS"=>Some(keys.into()),"JWT_SECRET"=>Some("strong-fallback-secret-at-least-32-bytes".into()),_=>None}).is_err());
    }
}
