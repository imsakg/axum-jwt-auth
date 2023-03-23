use axum_jwt_auth::config::Config;
use std::collections::HashMap;
fn vars() -> HashMap<String, String> {
    HashMap::from([
        ("DATABASE_URL".into(), "postgres://localhost/auth".into()),
        (
            "JWT_SECRET".into(),
            "a-development-secret-at-least-32-bytes".into(),
        ),
    ])
}
#[test]
fn parses_safe_defaults() {
    let config = Config::from_lookup(|key| vars().get(key).cloned()).unwrap();
    assert_eq!(config.access_ttl_seconds, 900);
    assert_eq!(config.refresh_ttl_seconds, 604800);
    assert_eq!(config.bind_address, "127.0.0.1:8000");
}
#[test]
fn rejects_missing_or_weak_secrets() {
    assert!(Config::from_lookup(|_| None).is_err());
    let mut values = vars();
    values.insert("JWT_SECRET".into(), "short".into());
    assert!(Config::from_lookup(|key| values.get(key).cloned()).is_err());
}
#[test]
fn rejects_invalid_lifetimes_without_exposing_values() {
    for ttl in ["0", "-5", "tomorrow", "86401"] {
        let mut values = vars();
        values.insert("ACCESS_TTL_SECONDS".into(), ttl.into());
        let error = Config::from_lookup(|key| values.get(key).cloned()).unwrap_err();
        assert_eq!(error, "invalid ACCESS_TTL_SECONDS");
    }
}
